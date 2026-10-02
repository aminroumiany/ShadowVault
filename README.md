# ShadowVault C

**XChaCha20-Poly1305 + Argon2id file/directory encryption**

A single-file CLI encryption utility written in C. Encrypts files and whole
directory trees with modern authenticated encryption (libsodium
`secretstream`), key derivation via Argon2id, optional per-chunk zlib
compression, encrypted multi-slot key envelopes, secure shredding of
originals, and an encrypted content manifest.

The wire format is documented in [FORMAT.md](FORMAT.md) (current: `SV07`;
legacy `SV06` vaults are read-only and can be migrated with `rekey`).

## Features

- **XChaCha20-Poly1305 secretstream** — 1 MiB authenticated frames; the nonce
  chain and per-frame tags are derived by libsodium, so reordering,
  truncation, and chunk swapping are all detected.
- **Argon2id key derivation** — tunable cost parameters, persisted in the
  vault header (defaults: `MODERATE` opslimit/memlimit; override with
  `-t`/`-m` at encryption).
- **Multi-slot key envelope (v7)** — up to 8 independent password/keyfile
  credentials per vault. `addkey`, `passwd`, and `delkey` manage slots in
  place without re-encrypting the payload; `slots` lists them.
- **File and directory modes** — encrypt individual files, or bundle an
  entire tree (permissions, mtimes, empty dirs, unicode names, deep
  nesting) into one `.vault` stream.
- **Encrypted manifest** — an AEAD trailer bound to the header stores the
  original names, sizes, modes, and mtimes; `list` shows contents without
  decrypting payload data, and single-file `dec` restores mode/mtime.
- **Keyfile support** — combine a binary keyfile with a password before key
  derivation (`keygen` creates random keyfiles).
- **Optional zlib compression** — independent gzip member per frame (`-c`).
  Before encrypting, a multi-point sample of the input is deflated; if it
  would save less than ~5%, compression is skipped automatically (useful for
  disk images and other incompressible bulk). The decision is stored in the
  vault header, so decryption needs no flags.
- **Integrity verification** — `verify` authenticates every frame in memory
  without writing output.
- **Crash-safe output** — vaults and extractions are written to temp files
  and renamed into place only on success; a failed or interrupted run never
  destroys an existing output. Slot operations back up the previous header
  to `<vault>.svbak`.
- **Secure deletion** — opt-in 3-pass overwrite (random/random/zeros),
  rename, and unlink of originals after encryption (`-s`).
- **Signal-safe cleanup** — SIGINT/SIGTERM stop cleanly and remove partial
  output.
- **Memory security** — keys, passwords, and keyfiles live in
  `sodium_malloc`'d, `mlock`ed buffers that are zeroed on release.
- **Hidden password input** — interactive prompts disable terminal echo
  (Ctrl-C can't leave your terminal with echo off); `--pass-fd` exists for
  scripts.

## Dependencies

- [libsodium](https://doc.libsodium.org/) — AEAD, Argon2id, secure memory
- [zlib](https://zlib.net/) — compression

## Build

```sh
make            # or: cc -O2 -Wall -Wextra -o shadowvault shadowvault.c -lsodium -lz
make test       # run the regression suite
```

## Usage

```
./shadowvault enc <file|dir>       [options]
./shadowvault dec <vault>          [options]
./shadowvault verify <vault>       [options]
./shadowvault list <vault>         show contents from the encrypted manifest
./shadowvault slots <vault>        list key slots (optionally test a credential)
./shadowvault keygen [-o file]     generate a random keyfile
./shadowvault addkey <vault>       add another password/keyfile slot
./shadowvault passwd <vault>       rotate the slot you unlock with
./shadowvault delkey --slot N      remove a key slot
./shadowvault rekey <old.vault>    migrate a legacy v6 vault to v7
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --password <pw>` | Password (`-` to prompt) | prompt |
| `--pass-fd <n>` | Read password from file descriptor n | — |
| `-k, --keyfile <file>` | Binary keyfile (combined with password) | — |
| `-o, --output <path>` | Output path (`-` for stdout) | `.vault` appended/stripped |
| `-c, --compress` | zlib compression (single-file mode; persisted) | off |
| `-s, --shred` | Overwrite + delete original after encrypting | off |
| `-f, --force` | Overwrite existing output | off |
| `-P, --progress` | Progress meter on stderr | off |
| `-t, --opslimit <n>` | Argon2id opslimit | `MODERATE` |
| `-m, --memlimit <n>` | Argon2id memlimit in bytes | `MODERATE` |
| `--exclude <glob>` | Skip matching entries in dir mode (repeatable) | — |
| `--keyfile-max-size <n>` | Max keyfile size | 4 MiB |
| `--allow-empty-pass` | Permit empty password with no keyfile | off |
| `--size <n>` | keygen: keyfile size in bytes | 32 |
| `--new-password` / `--new-pass-fd` / `--new-keyfile` | addkey/passwd credential | — |
| `--slot <n>` | delkey: slot index to remove | — |
| `-v, --verbose` | Verbose output | off |
| `-V, --version` | Print version | — |
| `-h, --help` | Help | — |

On `addkey`/`passwd`, `-t`/`-m` create **type-2 slots** whose Argon2id
parameters are stored per slot — strengthen one credential without touching
the rest. For `enc`, they set the vault-global KDF cost.

### Examples

```sh
# Encrypt a file
./shadowvault enc secret.docx -p mypassword -c -o secret.docx.vault

# Decrypt it (mode + mtime are restored from the encrypted manifest)
./shadowvault dec secret.docx.vault -p mypassword -o secret.docx

# Encrypt a directory tree (permissions, mtimes, empty dirs preserved)
./shadowvault enc mydocs -p mypassword

# List contents without decrypting payload data
./shadowvault list mydocs.vault -p mypassword

# Verify integrity without writing output
./shadowvault verify secret.docx.vault -p mypassword

# Share with a second credential, then rotate yours
printf 'alice\n' | ./shadowvault addkey doc.vault -p mypassword
printf 'newpw\n'  | ./shadowvault passwd doc.vault -p mypassword
./shadowvault slots doc.vault                 # no credential needed
./shadowvault slots doc.vault -p newpw        # reports the matching slot

# Stronger per-slot KDF cost for the new credential only
printf 'hrdpw\n' | ./shadowvault addkey doc.vault -p mypassword -t 4 -m 1073741824

# Use a keyfile together with a password
./shadowvault keygen -o key.bin --size 64
./shadowvault enc secret.docx -k key.bin -o secret.docx.vault

# Pipes (an explicit password is required when reading stdin)
cat secret | ./shadowvault enc - -p mypassword -o secret.vault
./shadowvault dec secret.vault -p mypassword -o - | less

# Migrate a legacy v6 vault (original metadata is carried across)
./shadowvault rekey old.vault -p mypassword
```

## Security notes

- A unique random DEK wraps the payload; each credential wraps only the DEK,
  so adding/removing keys never re-encrypts data.
- The first stream frame and the manifest are AEAD-bound to the fixed header
  prefix; the slot area sits outside that AAD precisely so slots can be
  edited in place.
- Wrong-password attempts cost one Argon2id run per occupied slot (up to 8).
- `--shred` overwrite semantics are unreliable on SSDs, log-structured, or
  copy-on-write filesystems; it is best-effort only.
- No unencrypted metadata: even file names require a credential (the
  manifest is encrypted; only its ciphertext length leaks).
- Passwords passed with `-p` are visible in the process list — prefer the
  prompt or `--pass-fd` in shared environments.
