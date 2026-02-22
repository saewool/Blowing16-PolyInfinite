# Blowing16

A symmetric authenticated encryption library written in C++17, using OpenSSL primitives and AVX2 SIMD intrinsics.

---

## Overview

Blowing16 implements an **Encrypt-then-MAC** AEAD (Authenticated Encryption with Associated Data) scheme. Each encryption operation produces a self-contained ciphertext blob that includes the nonce, padded ciphertext, and authentication tag. Decryption verifies the tag before returning any plaintext.

The construction uses:

- A custom **ARX stream cipher** (ChaCha-style quarter rounds, 16 rounds) to process keystream blocks
- **SHA-512** for per-message key derivation and keystream generation
- **HMAC-SHA-512** for authentication
- **PKCS#7** padding aligned to 64-byte blocks
- A **768-bit (96-byte)** nonce generated fresh per message via `std::random_device`
- **AVX2** for XOR across 256-bit registers
- Constant-time comparison, `volatile`-based memory wiping, and `_mm_clflush` cache eviction for key material

`PolyInfiniteGE` is a standalone MAC component that computes and verifies HMAC-SHA-512 tags independently of the cipher.

---

## Requirements

| Dependency | Detail |
|---|---|
| C++17 compiler | GCC ≥ 9 or Clang ≥ 10 |
| OpenSSL ≥ 1.1 | `libssl-dev` on Debian/Ubuntu |
| AVX2-capable CPU | Intel Haswell (2013) or newer; AMD Ryzen or newer |
| x86-64 Linux | Uses `_mm_lfence`, `_mm_sfence`, `_mm_mfence`, `_mm_clflush` |

---

## Build

```bash
g++ -O2 -std=c++17 -mavx2 -o blowing16 main.cpp -lssl -lcrypto
```

To verify AVX2 support on the target machine:

```bash
grep -m1 avx2 /proc/cpuinfo
```

---

## File Extension

Header files in this project use the `.hh` extension.

```
blowing16.hh
```

---

## API

### `Blowing16`

Include and instantiate with a 256-bit master key:

```cpp
#include "blowing16.hh"

std::array<uint8_t, 32> key = { /* 32 bytes of key material */ };
Blowing16 cipher(key);
```

#### Encrypt

```cpp
// Without associated data
std::vector<uint8_t> ct = cipher.encrypt(plaintext);

// With associated data
std::vector<uint8_t> ct = cipher.encrypt(plaintext, ad);
```

The returned buffer has the following layout:

```
┌─────────────────┬───────────────────────────┬───────────────┐
│  nonce (96 B)   │  ciphertext + PKCS#7 pad  │  tag (64 B)   │
└─────────────────┴───────────────────────────┴───────────────┘
```

- Nonce is randomly generated per call.
- Plaintext is padded to a multiple of 64 bytes before encryption.
- The tag authenticates: `nonce || len(ad) || ad || len(ct) || ct`.

Minimum output size: `96 + 64 + 64 = 224 bytes`.

#### Decrypt

```cpp
// Without associated data
std::vector<uint8_t> pt = cipher.decrypt(ct);

// With associated data
std::vector<uint8_t> pt = cipher.decrypt(ct, ad);
```

Throws `std::runtime_error` in the following cases:

| Exception message | Cause |
|---|---|
| `"invalid data"` | Buffer too short, ciphertext length zero, or not a multiple of 64 |
| `"invalid padding"` | PKCS#7 padding bytes are malformed |
| `"authentication failed"` | HMAC tag does not match |

Decryption always verifies the tag **before** returning plaintext. Plaintext is wiped from the intermediate buffer immediately after unpadding.

---

### `PolyInfiniteGE`

Standalone HMAC-SHA-512 MAC component with the same length-prefixed input encoding used by `Blowing16`.

```cpp
#include "blowing16.hh"

std::array<uint8_t, 32> mac_key = { /* 32 bytes */ };
PolyInfiniteGE poly(mac_key);

// Compute tag
uint8_t tag[64];
poly.compute_tag(nonce, ad, ciphertext, tag);

// Verify tag (constant-time)
bool ok = poly.verify_tag(received_tag, expected_tag);
```

MAC input encoding:

```
nonce || u64le(len(ad)) || ad || u64le(len(ct)) || ct
```

---

## Key Derivation

A fresh pair of per-message keys is derived for every encryption and decryption call:

```
hash    = SHA-512( master_key || nonce )
hash    = ARX_block( hash )
enc_key = hash[0..31]
mac_key = hash[32..63]
```

This separates encryption and MAC keys per message. Both keys are wiped and cache-flushed after use.

---

## Keystream Generation

The encryption keystream is produced by chaining SHA-512 blocks through the ARX transform:

```
state₀  = ARX_block( SHA-512( enc_key || nonce ) )
stateₙ  = ARX_block( SHA-512( stateₙ₋₁ ) )
```

Each 64-byte state block is XOR'd into the corresponding 64-byte plaintext block. XOR is performed 256 bits at a time using `_mm256_xor_si256` where buffer alignment permits, with a scalar fallback for remaining bytes.

---

## ARX Block Function

The ARX block function operates on a 512-bit (64-byte) state interpreted as 16 × `uint32_t` words. It runs 8 double-rounds (16 quarter-round pairs total), mirroring the ChaCha20 round structure:

```
// Column rounds
QR(state,  0,  4,  8, 12)
QR(state,  1,  5,  9, 13)
QR(state,  2,  6, 10, 14)
QR(state,  3,  7, 11, 15)
// Diagonal rounds
QR(state,  0,  5, 10, 15)
QR(state,  1,  6, 11, 12)
QR(state,  2,  7,  8, 13)
QR(state,  3,  4,  9, 14)
```

Each quarter round applies: add, XOR, rotate — with rotation constants 16, 12, 8, 7 bits. After all rounds the initial state is added back (feed-forward). The intermediate state arrays are wiped after use.

---

## Security Properties

| Property | Detail |
|---|---|
| Nonce size | 96 bytes per message, randomly generated |
| Master key size | 256 bits |
| Per-message key size | 256-bit enc key + 256-bit mac key |
| Tag size | 512-bit HMAC-SHA-512 |
| MAC order | Encrypt-then-MAC |
| Timing safety | Tag comparison uses `volatile` XOR accumulator + `_mm_lfence` barrier |
| Memory safety | All key material wiped with `volatile uint8_t*` writes + `_mm_sfence` |
| Cache safety | `_mm_clflush` evicts enc key and mac key cache lines after use, followed by `_mm_mfence` |
| Padding oracle resistance | MAC is verified before any padding is inspected |

---

## Audit Status

Blowing16 has not yet undergone a formal third-party security audit. Absence of an audit is a statement about process, not about correctness. The implementation follows established patterns — Encrypt-then-MAC, constant-time comparison, per-message key derivation — and the full construction is documented above for independent review.

---

## Known Constraints

- **Nonce reuse:** Reusing a nonce with the same master key exposes the XOR of two plaintexts and breaks key separation. The 96-byte nonce space makes accidental collision negligible at practical message volumes, but callers are responsible for ensuring nonce uniqueness if overriding the default random generation.
- **Padding size leak:** PKCS#7 with a 64-byte block reveals plaintext length rounded up to the nearest 64 bytes. Callers with strict length-hiding requirements should pre-pad plaintext before passing it in.
- **`std::random_device` quality:** On Linux this reads from `/dev/urandom`. On other platforms, entropy quality may vary; verify platform behavior before deployment.
- **Non-standard construction:** The ARX + SHA-512 keystream is not an IETF-standardized cipher. Reviewers should evaluate the construction directly from the documented specification above.

---

## License

BSD 3-Clause License

Copyright (c) 2025, Blowing16 Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the project nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
