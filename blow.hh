#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <random>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <immintrin.h>

class BlowingUtil {
public:
    static bool compare(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
        volatile uint8_t r = 0;
        for (size_t i = 0; i < len; ++i) r |= a[i] ^ b[i];
        _mm_lfence();
        return r == 0;
    }

    static void wipe(uint8_t* buf, size_t len) noexcept {
        volatile uint8_t* p = buf;
        for (size_t i = 0; i < len; ++i) p[i] = 0;
        _mm_sfence();
    }

    static void xor_simd(uint8_t* dst, const uint8_t* src, size_t len) noexcept {
        size_t i = 0;
        for (; i + 32 <= len; i += 32) {
            __m256i a = _mm256_loadu_si256((const __m256i*)(dst + i));
            __m256i b = _mm256_loadu_si256((const __m256i*)(src + i));
            _mm256_storeu_si256((__m256i*)(dst + i), _mm256_xor_si256(a, b));
        }
        for (; i < len; ++i) dst[i] ^= src[i];
    }

    static void prefetch(const uint8_t* buf, size_t len) noexcept {
        for (size_t i = 0; i < len; i += 64)
            _mm_prefetch(reinterpret_cast<const char*>(buf + i), _MM_HINT_T0);
    }

    static void clflush_range(const uint8_t* buf, size_t len) noexcept {
        for (size_t i = 0; i < len; i += 64)
            _mm_clflush(buf + i);
        _mm_mfence();
    }

    static void encode_u64le_vec(uint64_t v, std::vector<uint8_t>& out) {
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
};

class Blowing16 {
    std::array<uint8_t, 32> master_key;

    static void arx_quarter_round(uint32_t* s, int a, int b, int c, int d) noexcept {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = (s[d] << 16) | (s[d] >> 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = (s[b] << 12) | (s[b] >> 20);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = (s[d] <<  8) | (s[d] >> 24);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = (s[b] <<  7) | (s[b] >> 25);
    }

    static void arx_block(uint8_t block[64]) noexcept {
        uint32_t init[16], state[16];
        memcpy(init,  block, 64);
        memcpy(state, block, 64);
        for (int r = 0; r < 16; r += 2) {
            arx_quarter_round(state,  0,  4,  8, 12);
            arx_quarter_round(state,  1,  5,  9, 13);
            arx_quarter_round(state,  2,  6, 10, 14);
            arx_quarter_round(state,  3,  7, 11, 15);
            arx_quarter_round(state,  0,  5, 10, 15);
            arx_quarter_round(state,  1,  6, 11, 12);
            arx_quarter_round(state,  2,  7,  8, 13);
            arx_quarter_round(state,  3,  4,  9, 14);
        }
        for (int i = 0; i < 16; ++i) state[i] += init[i];
        memcpy(block, state, 64);
        BlowingUtil::wipe(reinterpret_cast<uint8_t*>(state), 64);
        BlowingUtil::wipe(reinterpret_cast<uint8_t*>(init),  64);
    }

    void kdf(const uint8_t* nonce, uint8_t enc_key[32], uint8_t mac_key[32]) const {
        uint8_t hash[64];
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, master_key.data(), 32);
        SHA512_Update(&ctx, nonce, 96);
        SHA512_Final(hash, &ctx);
        arx_block(hash);
        memcpy(enc_key, hash,      32);
        memcpy(mac_key, hash + 32, 32);
        BlowingUtil::wipe(hash, 64);
    }

    void keystream_xor(const uint8_t key[32], const uint8_t* nonce, uint8_t* buf, size_t len) const {
        uint8_t state[64];
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, key, 32);
        SHA512_Update(&ctx, nonce, 96);
        SHA512_Final(state, &ctx);
        arx_block(state);

        size_t offset = 0;
        while (offset < len) {
            size_t blk = (len - offset < 64) ? (len - offset) : 64;
            BlowingUtil::xor_simd(buf + offset, state, blk);
            offset += blk;
            if (offset < len) {
                SHA512(state, 64, state);
                arx_block(state);
            }
        }
        BlowingUtil::wipe(state, 64);
    }

    static std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& in, size_t block_size) {
        size_t pad_len = block_size - (in.size() % block_size);
        std::vector<uint8_t> out = in;
        out.insert(out.end(), pad_len, static_cast<uint8_t>(pad_len));
        return out;
    }

    static std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& in, size_t block_size) {
        if (in.empty() || in.size() % block_size != 0)
            throw std::runtime_error("invalid padding");
        uint8_t pad_val = in.back();
        volatile uint8_t bad = 0;
        bad |= static_cast<uint8_t>(pad_val == 0);
        bad |= static_cast<uint8_t>(pad_val > static_cast<uint8_t>(block_size));
        size_t pad_start = in.size() - pad_val;
        for (size_t i = pad_start; i < in.size(); ++i)
            bad |= in[i] ^ pad_val;
        _mm_lfence();
        if (bad) throw std::runtime_error("invalid padding");
        return std::vector<uint8_t>(in.begin(), in.begin() + pad_start);
    }

    void hmac_sha512(const uint8_t key[32], const uint8_t* data, size_t len, uint8_t tag[64]) const {
        unsigned int out_len = 64;
        HMAC(EVP_sha512(), key, 32, data, len, tag, &out_len);
    }

    std::vector<uint8_t> build_mac_input(
        const uint8_t* nonce,
        const std::vector<uint8_t>& ad,
        const uint8_t* ct, size_t ct_len) const
    {
        std::vector<uint8_t> m;
        m.reserve(96 + 8 + ad.size() + 8 + ct_len);
        m.insert(m.end(), nonce, nonce + 96);
        BlowingUtil::encode_u64le_vec(static_cast<uint64_t>(ad.size()), m);
        m.insert(m.end(), ad.begin(), ad.end());
        BlowingUtil::encode_u64le_vec(static_cast<uint64_t>(ct_len), m);
        m.insert(m.end(), ct, ct + ct_len);
        return m;
    }

public:
    explicit Blowing16(const std::array<uint8_t, 32>& key) : master_key(key) {}

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ad = {}) const {
        std::vector<uint8_t> nonce(96);
        std::random_device rd;
        for (size_t i = 0; i < 96; ++i) nonce[i] = static_cast<uint8_t>(rd() & 0xff);

        uint8_t enc_key[32], mac_key[32];
        kdf(nonce.data(), enc_key, mac_key);

        std::vector<uint8_t> padded = pkcs7_pad(plaintext, 64);
        BlowingUtil::prefetch(padded.data(), padded.size());
        keystream_xor(enc_key, nonce.data(), padded.data(), padded.size());

        std::vector<uint8_t> mac_in = build_mac_input(nonce.data(), ad, padded.data(), padded.size());
        uint8_t tag[64];
        hmac_sha512(mac_key, mac_in.data(), mac_in.size(), tag);
        BlowingUtil::wipe(mac_in.data(), mac_in.size());

        std::vector<uint8_t> out;
        out.reserve(96 + padded.size() + 64);
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), padded.begin(), padded.end());
        out.insert(out.end(), tag, tag + 64);

        BlowingUtil::clflush_range(enc_key, 32);
        BlowingUtil::clflush_range(mac_key, 32);
        BlowingUtil::wipe(enc_key, 32);
        BlowingUtil::wipe(mac_key, 32);
        BlowingUtil::wipe(tag, 64);

        return out;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& ad = {}) const {
        if (data.size() < 96 + 64 + 64)
            throw std::runtime_error("invalid data");

        const uint8_t* nonce   = data.data();
        const uint8_t* ct_ptr  = data.data() + 96;
        size_t         ct_len  = data.size() - 96 - 64;
        const uint8_t* tag_ptr = data.data() + 96 + ct_len;

        if (ct_len == 0 || ct_len % 64 != 0)
            throw std::runtime_error("invalid data");

        uint8_t enc_key[32], mac_key[32];
        kdf(nonce, enc_key, mac_key);

        std::vector<uint8_t> mac_in = build_mac_input(nonce, ad, ct_ptr, ct_len);
        uint8_t expected_tag[64];
        hmac_sha512(mac_key, mac_in.data(), mac_in.size(), expected_tag);
        BlowingUtil::wipe(mac_in.data(), mac_in.size());

        bool valid = BlowingUtil::compare(tag_ptr, expected_tag, 64);

        std::vector<uint8_t> buf(ct_ptr, ct_ptr + ct_len);
        keystream_xor(enc_key, nonce, buf.data(), buf.size());

        BlowingUtil::clflush_range(enc_key, 32);
        BlowingUtil::clflush_range(mac_key, 32);
        BlowingUtil::wipe(enc_key, 32);
        BlowingUtil::wipe(mac_key, 32);
        BlowingUtil::wipe(expected_tag, 64);

        if (!valid) {
            BlowingUtil::wipe(buf.data(), buf.size());
            throw std::runtime_error("authentication failed");
        }

        std::vector<uint8_t> plaintext = pkcs7_unpad(buf, 64);
        BlowingUtil::wipe(buf.data(), buf.size());
        return plaintext;
    }
};

class PolyInfiniteGE {
    std::array<uint8_t, 32> mac_key;

    void hmac_sha512(const uint8_t* key, const uint8_t* data, size_t len, uint8_t* tag) const {
        unsigned int out_len = 64;
        HMAC(EVP_sha512(), key, 32, data, len, tag, &out_len);
    }

    std::vector<uint8_t> build_mac_input(
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ad,
        const std::vector<uint8_t>& ciphertext) const
    {
        std::vector<uint8_t> m;
        m.reserve(nonce.size() + 8 + ad.size() + 8 + ciphertext.size());
        m.insert(m.end(), nonce.begin(), nonce.end());
        BlowingUtil::encode_u64le_vec(static_cast<uint64_t>(ad.size()), m);
        m.insert(m.end(), ad.begin(), ad.end());
        BlowingUtil::encode_u64le_vec(static_cast<uint64_t>(ciphertext.size()), m);
        m.insert(m.end(), ciphertext.begin(), ciphertext.end());
        return m;
    }

public:
    explicit PolyInfiniteGE(const std::array<uint8_t, 32>& key) : mac_key(key) {}

    void compute_tag(
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ad,
        const std::vector<uint8_t>& ciphertext,
        uint8_t tag_out[64]) const
    {
        std::vector<uint8_t> m = build_mac_input(nonce, ad, ciphertext);
        hmac_sha512(mac_key.data(), m.data(), m.size(), tag_out);
        BlowingUtil::wipe(m.data(), m.size());
    }

    bool verify_tag(const uint8_t* tag, const uint8_t* expected) const noexcept {
        return BlowingUtil::compare(tag, expected, 64);
    }
};
