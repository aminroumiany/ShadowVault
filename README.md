# ShadowVault C

**XChaCha20-Poly1305 + Argon2id File/Directory/Disk Encryption**

A single-file, static CLI encryption utility written in C. Encrypts files, directories (recursively), and raw disk images with modern authenticated encryption, key derivation via Argon2id, optional zlib compression, and secure shredding of originals.

## Features

- **XChaCha20-Poly1305 AEAD** — authenticated encryption with a random 24-byte nonce per chunk
- **Argon2id key derivation** — tunable time cost, memory cost, and parallelism (defaults: t=3, m=64 MiB, p=4)
- **File, directory, and disk modes** — encrypt individual files, recursively encrypt entire directories (`<name>.vault`), or treat any input as a raw disk image (`-d`)
- **Keyfile support** — combine a binary keyfile with a password before key derivation
- **Optional zlib compression** — per-chunk deflate before encryption (`-c`)
- **Integrity verification** — decrypt in memory to verify AEAD tags without writing any output (`verify` subcommand)
- **Secure deletion** — 3-pass overwrite (random/random/zeros), rename, and unlink of originals after encryption
- **Progress bar** — real-time percentage, throughput (B/s–GiB/s), and ETA
- **Signal-safe cleanup** — SIGINT/SIGTERM cleanly remove partial output files
- **Same-file guard** — refuses to process if input and output are the same inode
- **Memory security** — locks sensitive memory with `mlock`, zeroes with `sodium_memzero` / `explicit_bzero`

## Dependencies

- [libsodium](https://doc.libsodium.org/) — XChaCha20-Poly1305, Argon2id, secure memory
- [zlib](https://zlib.net/) — compression

## Build

```sh
gcc -O3 -o shadowvault shadowvault.c -lsodium -lz -D_GNU_SOURCE
```

A static 64-bit binary is also included in the repository.

## Usage

```
./shadowvault enc <file|dir|disk>  [options]
./shadowvault dec <vault|dir>      [options]
./shadowvault verify <vault>       [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --password <pw>` | Password (use `-` for stdin prompt) | — |
| `-k, --keyfile <file>` | Binary keyfile (combined with password) | — |
| `-o, --output <path>` | Output file/directory | — |
| `-t, --t-cost <N>` | Argon2 time cost | 3 |
| `-m, --m-cost <KiB>` | Argon2 memory cost in KiB | 65536 (64 MiB) |
| `-P, --parallel <N>` | Argon2 parallelism | 4 |
| `-c, --compress` | Enable zlib compression before encryption | off |
| `-d, --disk` | Treat input as whole disk/partition image | off |
| `-v, --verbose` | Verbose output | off |
| `-h, --help` | Show help | — |

### Examples

```sh
# Encrypt a file
./shadowvault enc secret.docx -p mypassword -c -o secret.docx.vault

# Decrypt a vault
./shadowvault dec secret.docx.vault -p mypassword -o secret.docx

# Encrypt a directory (recursively, output in-place as .vault files)
./shadowvault enc mydocs/ -p mypassword -c

# Encrypt a disk image
./shadowvault enc sdcard.img -p mypassword -d -o sdcard.img.vault

# Verify integrity without writing output
./shadowvault verify secret.docx.vault -p mypassword

# Use a keyfile
./shadowvault enc secret.docx -p mypassword -k key.bin -o secret.docx.vault
```

## Vault File Format

- **Magic:** `SV04` (4 bytes)
- **Version:** 1 byte
- **Salt:** 16 bytes
- **AAD length:** 4 bytes (network byte order)
- **AAD JSON:** variable length (e.g. `{"v":4,"f":"doc.txt","s":12345,"m":644,"c":1048576,"d":0}`)
- **Chunks** (repeated until end marker):
  - Ciphertext length: 4 bytes (big-endian, excludes 16-byte auth tag)
  - Nonce: 24 bytes
  - Ciphertext + Poly1305 tag
- **End marker:** 4 zero bytes

## Security Notes

- Default Argon2id parameters (t=3, m=64 MiB, p=4) balance security and speed on modern hardware. Increase `-m` for higher resistance against GPU/ASIC attacks.
- A unique random salt is generated for each encryption operation.
- A unique random nonce is generated for every 1 MiB chunk.
- Original files can be securely shredded after encryption (enabled by default).
- Authentication tags are verified on every chunk during decryption and verification.


