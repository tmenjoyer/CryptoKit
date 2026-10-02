# CryptoKit

A small, dependency-free **cryptography & ethical security** command-line toolkit written in Go.
It uses the Go standard library only, compiles to a single static binary, and runs on Windows, Linux and macOS.

> **Disclaimer:** CryptoKit is intended for lawful, educational and authorized security purposes only
> (protecting your own data, auditing your own passwords, verifying file integrity, learning cryptography).
> You are responsible for how you use it.

## Features

| Command    | Description |
|------------|-------------|
| `encrypt`  | Encrypt a file with **AES-256-GCM**; key derived with **PBKDF2-HMAC-SHA256** (600,000 iterations by default) |
| `decrypt`  | Decrypt and authenticate a file produced by `encrypt` |
| `hash`     | Compute MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 of a file, stdin or string, and verify against an expected value |
| `genpass`  | Generate passwords with a cryptographically secure RNG (`crypto/rand`) |
| `strength` | Estimate password entropy and flag common weaknesses |
| `identify` | Guess a hash type from its format (length / prefix) |

## Security design

- **Authenticated encryption (AEAD):** AES-256-GCM detects wrong passwords, corruption and tampering.
- **Chunked streaming:** files are processed in 64 KiB chunks, so large files do not need to fit in memory.
- **Per-chunk unique nonces:** a random 8-byte prefix plus a 32-bit chunk counter.
- **Anti-truncation / reordering:** the header and a "final chunk" flag are bound as additional authenticated data.
- **Random salt per file** (16 bytes) so identical passwords never yield identical keys.
- **Atomic writes:** output goes to a temporary file first, then is renamed, so a failed run never leaves a half-written file.
- **No secrets on the command line:** the password is prompted without echo (or read from `CRYPTOKIT_PASSWORD`).

### File format (`.ckit`)

```
"CKIT1" | iterations (u32, big-endian) | salt (16) | nonce prefix (8) | chunk_0 | chunk_1 | ...
chunk_i = AES-256-GCM(plaintext <= 64 KiB) || 16-byte tag
nonce_i = nonce prefix || i (u32)      AAD_i = header || final-chunk flag
```

> Note: PBKDF2 is used because it is available without third-party packages. For highest resistance
> against GPU cracking, choose a long random password (see `genpass`) or a passphrase of several words.

## Build

Requires [Go](https://go.dev/dl/) 1.21 or newer.

**Windows** (produces `cryptokit.exe`):

```bat
build.bat
```

**Linux / macOS:**

```sh
./build.sh
```

Or manually:

```sh
go build -trimpath -ldflags "-s -w" -o cryptokit .
# cross-compile for Windows from any OS:
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o cryptokit.exe .
```

Run the tests:

```sh
go test ./...
```

## Usage

```sh
# Encrypt / decrypt a file (you will be prompted for a password)
cryptokit encrypt secret.pdf          # -> secret.pdf.ckit
cryptokit decrypt secret.pdf.ckit     # -> secret.pdf

# Custom output, overwrite existing, custom iteration count
cryptokit encrypt -o backup.ckit -f -iter 1000000 notes.txt

# Non-interactive (scripts) - beware of shell history / process environment
CRYPTOKIT_PASSWORD="..." cryptokit decrypt secret.pdf.ckit

# Hashing and integrity verification
cryptokit hash installer.exe
cryptokit hash -a sha512 file.iso
cryptokit hash -c <expected_sha256> installer.exe
cryptokit hash -s "hello world"

# Secure password generation
cryptokit genpass                     # one 20-char password
cryptokit genpass -l 32 -n 5          # five 32-char passwords
cryptokit genpass -l 16 -no-symbols

# Password audit
cryptokit strength                    # prompted, hidden input
cryptokit strength "Tr0ub4dor&3"

# Identify a hash
cryptokit identify 5d41402abc4b2a76b9719d911017c592
```

## Project layout

```
main.go           CLI and command handling
crypt.go          AES-256-GCM streaming encryption / decryption
pbkdf2.go         PBKDF2-HMAC-SHA256 (stdlib-only implementation)
tools.go          hashing, hash identification, password generation & strength
term_*.go         platform-specific hidden password input
crypt_test.go     unit tests (round-trips, tampering, PBKDF2 test vectors)
```

## Limitations

- Entropy estimation in `strength` is a heuristic, not a guarantee.
- Losing the password means losing the data: there is no recovery mechanism.
- This tool has not been independently audited. For critical production use, prefer audited tools
  such as [age](https://age-encryption.org/) or GnuPG.

## License

MIT - see [LICENSE](LICENSE).
