# ShadowVault Wire Format

This document specifies the on-disk format produced by ShadowVault. All
multi-byte integers are big-endian unless stated otherwise. "BE" = big-endian.

**Current format: v7 ("SV07") - multi-slot key envelope.**
**v6 ("SV06") is read-only legacy: dec/verify/list/rekey still accept it.**

## Primitives (libsodium)

| Purpose            | Primitive                                   |
|--------------------|---------------------------------------------|
| KDF                | Argon2id (`crypto_pwhash`, ALG_ARGON2ID13)  |
| DEK wrap           | `crypto_secretbox_easy` (XSalsa20-Poly1305) |
| Payload AEAD       | `crypto_secretstream_xchacha20poly1305`     |
| Manifest AEAD      | `crypto_aead_xchacha20poly1305_ietf`        |
| Subkey derivation  | `crypto_kdf_derive_from_key` (BLAKE2b)      |

Sizes: salt 16, DEK/KEY 32, secretbox MAC 16, secretbox nonce 24,
secretstream header 24, secretstream ABYTES 17, frame chunk plaintext ≤ 1 MiB.

## Key hierarchy

    DEK = random(32)                      # one per vault, encrypts all data
    KEK_i = Argon2id(cred_i || keyfile_i?, salt_i, ops, mem)
    wrapped_dek_i = secretbox(DEK, nonce_i, KEK_i)

Each key *slot* independently wraps the same DEK under its own credential.
`addkey`/`passwd`/`delkey` rewrite only the slot area - never the DEK, the
stream, or anything covered by AAD.

## Header (v7) - 830 bytes, packed, no padding

```
offset  size  field
0       4     magic           "SV07"
4       1     version         7
5       1     flags           bit0 0x01 FLAG_COMPRESSED (single-file mode only)
                              bit1 0x02 FLAG_DIRECTORY (bundle)
6       18    reserved        zero on write, ignored on read
24      8     opslimit_be     u64 - global Argon2id cost for ALL slots
32      8     memlimit_be     u64
40      24    stream_header   secretstream header (init_push output)
64      8x96  slots           see below
```

### Slot record (96 bytes each)

```
off size field
0   1    type             0 = empty, 1 = passphrase (+ optional keyfile)
1   7    reserved
8   16   kdf_salt         per-slot Argon2id salt
24  24   wrap_nonce       per-slot secretbox nonce
48  48   wrapped_dek      secretbox output: 32B ciphertext + 16B MAC
```

Slots are **self-describing**: readers scan all 8 and skip `type == 0`.
There is deliberately no slot-count field - any count stored near offset 6
would sit inside the AAD prefix, making every add/remove a stream-breaking
event (an earlier draft made exactly that mistake).

### AAD rule (critical)

The first secretstream block is authenticated with the fixed **64-byte
header prefix only** (magic through stream_header). The slot area lives
outside the AAD so keys are swappable in place; flags, KDF params and the
wrapped stream state remain tamper-evident. Consequence: the fixed prefix can
never change without re-encrypting the first block - which is why `rekey`
(v6 to v7 migration) performs a full decrypt/re-encrypt.

Wrong-credential unlock cost: one Argon2id run per occupied slot (up to 8).

## Header (v6, legacy) - 134 bytes

Same frame/stream machinery, single hardcoded slot inside the header:
salt@6, wrapped_dek@38, wrap_nonce@86, stream_header@110, params@22/@30.
The **entire 134-byte header is the first-block AAD** - which is precisely
why v6 cannot support in-place slot management and needs `rekey`.

## Frame stream (after header)

Repeated frames:

    [u32 BE clen][ciphertext: clen bytes]

Constraints: `17 <= clen <= CHUNK_SIZE + ABYTES` (1048576 + 17).
Plaintext of each frame ≤ 1 MiB. Tags:

- `TAG_MESSAGE` (0): intermediate blocks; bundle entry headers and file data.
- `TAG_FINAL` (3): last block of the vault.

AAD is supplied **only** while decrypting/encrypting the first frame (see
above); subsequent frames use no AAD. The stream ends at `TAG_FINAL`; readers
must reject a clean EOF that arrives before `TAG_FINAL`. Bytes after the
`TAG_FINAL` frame are ignored by v6 readers (reserved for future trailers).

## Encrypted manifest trailer (optional, after TAG_FINAL)

Vaults may end with an authenticated, encrypted metadata index:

    "SVM1" | version(1)=1 | nonce(24) | ct_len(u64 BE) | AEAD ciphertext

- Cipher: `crypto_aead_xchacha20poly1305_ietf` one-shot.
- Key:    `mkey = crypto_kdf_derive_from_key(32, subkey_id=1, ctx="SVmanif1", DEK)`
          (`crypto_kdf_KEYBYTES` = 32 = DEK size; distinct context from all
          other key material).
- AAD:    v7 -> the 64-byte fixed header prefix; v6 -> the full 134-byte
          header. The trailer is cryptographically bound to its own vault's
          header and cannot be transplanted.
- Plaintext: zero or more entry records in the exact bundle entry encoding
  (tag/path_len/path/metadata, see below), concatenated.
- `ct_len` must be within [16, 256 MiB]; readers reject anything else.
- Detection while walking frames: a 4-byte frame-length field reading exactly
  "SVM1" (0x53564D31) can never be a valid length (max valid ≈ 0x100011), so
  the marker is unambiguous.
- v6-only readers stop at TAG_FINAL and ignore trailing bytes; absence of a
  trailer is legal and reported by `list`.

The manifest is *metadata only*: `list` authenticates the trailer but does not
authenticate payload frames. `verify` remains the full-integrity operation.

Writers store the true original plaintext size per file (so compressed vaults
list their real sizes) and, for single-file mode, the original basename
("-" for stdin).

## Single-file layout

    header || frames...

With `FLAG_COMPRESSED`, each frame's plaintext is an independent zlib/gzip
member (`deflateInit2(windowBits=15+16)`, finished and reset per frame);
decompressors must `inflateReset()` between frames. Without the flag,
plaintext is raw file bytes in order.

## Directory bundle layout (`FLAG_DIRECTORY`)

The stream body is a sequence of entries interleaved with file content:

```
entry := tag(1) path_len(u16 BE) path[path_len] meta...
         where tag ∈ { ENTRY_FILE=1, ENTRY_DIR=2 }

ENTRY_DIR  meta: mode u32 BE                       (permission bits only)
ENTRY_FILE meta: size u64 BE, mode u32 BE,
                 mtime_sec i64 BE, mtime_nsec i32 BE
```

- After an `ENTRY_FILE`, exactly `size` plaintext bytes follow across one or
  more frames (frames may straddle entry boundaries arbitrarily).
- The root directory is emitted as `ENTRY_DIR` with path `"."`.
- The final frame carries `TAG_FINAL` with 1 plaintext byte `ENTRY_END` (0).

Traversal rules (writer):
- Entries are sorted lexicographically per directory; directories are emitted
  depth-first via an explicit stack (no recursion).
- Every directory entry precedes its contained files.
- Symbolic links, devices, sockets, and FIFOs are skipped silently.

Extraction rules (reader):
- Paths are extracted into a staging dir `<outdir>.svtmp.XXXXXX` and atomically
  renamed into place on success; staging is removed on any failure/interrupt.
- Reject absolute paths and paths containing `..`.
- Parent directories are created as needed (0755), then final modes/times are
  applied via chmod + utimensat.

## CLI contract

- Exit code 0 on success, 1 on usage/validation errors, 255-style (-1) on
  operational failure.
- `-` as input/output selects stdin/stdout (bundles cannot be auto-detected
  from stdin; they fail with an explicit message).
- Default outputs: `enc` appends `.vault`; `dec` strips `.vault`, else appends
  `.dec`; bundle `dec` uses `<target>_extracted`.

## Known limitations

- `--shred` overwrite semantics are unreliable on SSDs, log-structured, or
  copy-on-write filesystems; it is best-effort only.
- No unencrypted metadata: even file names require the password (the manifest
  is encrypted; only its ciphertext length leaks).
