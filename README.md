# Secure Data Protection using AES-GCM and ChaCha20-Poly1305

CS6530 (Applied Cryptography) Assignment 1: a secure data protection subsystem that
exchanges application records between a `Sender` and a `Receiver` using authenticated
encryption (AEAD), configurable to either **AES-128-GCM** or **ChaCha20-Poly1305**.

## Design Summary

- **Record** (`src/record.h`): the application record — a sequence id, timestamp, and
  payload string.
- **Serializer** (`src/serializer.{h,cpp}`): packs/unpacks a `Record` to/from a
  fixed-width byte layout (`8-byte timestamp | 4-byte length | payload`), independent of
  platform endianness/struct padding.
- **Crypt** (`src/crypt.{h,cpp}`): the AEAD engine, wrapping OpenSSL's EVP API for
  AES-128-GCM and ChaCha20-Poly1305. Produces/consumes the wire format
  `AAD(4B) | nonce(12B) | ciphertext | tag(16B)`.
- **Sender / Receiver** (`src/sender.*`, `src/receiver.*`): orchestrate
  record → serialize → encrypt → write, and read → decrypt → verify → deserialize,
  over a shared file (`tm.bin`) that stands in for a network channel.

**Nonce management**: a fresh 96-bit nonce is generated via `RAND_bytes` for every
encryption call (never reused across messages under the same key). See TR-7 for
empirical verification across 10,000 records.

**Associated Data (AAD)**: the record's sequence id is authenticated as AAD — it stays
visible in plaintext on the wire but cannot be detached from its ciphertext without
breaking the authentication tag.

**Replay handling**: the `Receiver` keeps a set of accepted record ids (recovered from
the authenticated AAD) for its session and rejects any record whose id has already been
seen.

## Software Requirements

- A C++17 compiler (developed/tested with `g++`)
- `make`
- OpenSSL development headers/library (`libssl-dev` on Debian/Ubuntu/Kali,
  `openssl-devel` on Fedora/RHEL, `brew install openssl` on macOS)

## External Libraries

- [OpenSSL](https://www.openssl.org/) `libcrypto` (EVP API) — the only third-party
  dependency, used for AES-128-GCM and ChaCha20-Poly1305 AEAD operations. The AES,
  ChaCha20, GCM, and Poly1305 primitives themselves are not implemented by this project.

## Build Instructions

```sh
make            # builds bin/demo and bin/test_suite
```

Individual targets: `make demo`, `make tests`, `make clean`.

## Execution Instructions

### Interactive demo (`bin/demo`)

Run from the `src/` directory so the relative key paths and the `tm.bin` transport
medium resolve correctly:

```sh
cd src
../bin/demo "<data>" <aes|chacha> <keyfile.bin>

# examples
../bin/demo "hello world" aes ../keys/aeskey.bin
../bin/demo "hello world" chacha ../keys/ccpkey.bin
```

`keys/aeskey.bin` is a 16-byte key (AES-128-GCM); `keys/ccpkey.bin` is a 32-byte key
(ChaCha20-Poly1305).

### Test suite (`bin/test_suite`)

Runs TR-1 through TR-8 (positive baseline, ciphertext/tag/AAD tamper detection, replay,
wrong-key, nonce uniqueness over 10,000 records, and a performance comparison at
64 B / 1 KiB / 64 KiB) for both AEAD configurations and prints PASS/FAIL evidence:

```sh
make run-tests
# or
cd src && ../bin/test_suite
```
