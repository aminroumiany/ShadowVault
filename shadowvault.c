/*
 * ShadowVault v6.1 – Envelope Encryption + XChaCha20-Poly1305 Secretstream
 *
 * Build: gcc -O2 -Wall -Wextra -o shadowvault shadowvault.c -lsodium -lz
 * Usage: ./shadowvault <enc|dec|verify> <file|dir> [options]
 *
 * ==========================================================================
 * WHAT CHANGED FROM v6.0 (improvements & hardening) @aminroumiany
 * ==========================================================================
 *
 * 1. FILE PERMISSION & TIMESTAMP RESTORATION
 *    Bundle entries now store the original mode, modification time (seconds +
 *    nanoseconds), and, for directories, an explicit ENTRY_DIR tag. Empty
 *    directories are preserved and restored with correct metadata.
 *
 * 2. OVERWRITE SAFETY
 *    The program now refuses to overwrite an existing output file/directory
 *    unless `-f` (force) is given.
 *
 * 3. DETERMINISTIC DIRECTORY PROCESSING
 *    Directory entries are sorted before serialisation, making the bundle
 *    order predictable across identical filesystem trees.
 *
 * 4. ITERATIVE DIRECTORY TRAVERSAL
 *    Recursion in `bundle_add_tree` has been replaced with an explicit stack
 *    to avoid stack overflow on deeply nested directories.
 *
 * 5. ENHANCED SECURE DELETION
 *    The overwrite buffer is zeroed with sodium_memzero and the parent
 *    directory is fsync()'d after the file is unlinked.
 *
 * 6. CONFIGURABLE ARGON2ID COSTS
 *    New CLI options `-t`/`--opslimit` and `-m`/`--memlimit` allow the user
 *    to choose stronger or weaker parameters at encrypt time. They are
 *    persisted in the header, so decryption needs no extra flags.
 *
 * 7. MEMORY LOCKING
 *    All sensitive heap buffers (DEK, KEK, password) are guarded with
 *    sodium_mlock() to prevent them from being paged to swap.
 *
 * 8. PORTABLE MEMORY ZEROING
 *    `explicit_bzero` has been replaced with `sodium_memzero`.
 *
 * 9. CONFIGURABLE KEYFILE SIZE LIMIT
 *    The maximum allowed keyfile size can be set with `--keyfile-max-size`
 *    (default 4 MiB).
 *
 * 10. STDIN / STDOUT SUPPORT
 *     Using `-` as the input or output path reads from stdin or writes to
 *     stdout, enabling piping.
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>
#include <signal.h>
#include <getopt.h>
#include <sodium.h>
#include <zlib.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <ftw.h>
#include <fnmatch.h>

/* ----- Constants ----- */
#define SV_MAGIC        "SV06"
#define SV_VERSION      6
#define CHUNK_SIZE      (1024 * 1024)   /* 1 MiB plaintext per stream message */
#define SALT_SIZE       crypto_pwhash_SALTBYTES        /* 16 */
#define DEK_SIZE        crypto_secretstream_xchacha20poly1305_KEYBYTES /* 32 */
#define WRAP_NONCE_SIZE crypto_secretbox_NONCEBYTES     /* 24 */
#define WRAP_MAC_SIZE   crypto_secretbox_MACBYTES       /* 16 */
#define STREAM_HEADER_SIZE crypto_secretstream_xchacha20poly1305_HEADERBYTES /* 24 */

/* Flags byte */
#define FLAG_COMPRESSED 0x01
#define FLAG_DIRECTORY  0x02

/* Input slack when compressing: guarantees worst-case zlib expansion of a
 * compressed frame stays under the CHUNK_SIZE + ABYTES ciphertext bound. */
#define COMP_SLACK 4096

/* Argon2id defaults – overridable via CLI */
#define DEFAULT_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define DEFAULT_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

/* Bundle entry tags */
#define ENTRY_FILE  1
#define ENTRY_DIR   2
#define ENTRY_END   0

/* Maximum path length inside a bundle */
#define MAX_BUNDLE_PATH 4095

/* Default maximum keyfile size */
#define DEFAULT_KEYFILE_MAX_SIZE (4 * 1024 * 1024)

/* Maximum password bytes accepted via --pass-fd (incl. NUL) */
#define PASS_FD_MAX 4096

/* ----- On-disk header – the exact byte range of this struct is used as
 * authenticated additional data for the first stream block. ----- */
#pragma pack(push, 1)
typedef struct {
    char     magic[4];
    uint8_t  version;
    uint8_t  flags;
    uint8_t  salt[SALT_SIZE];
    uint8_t  opslimit_be[8];    /* big-endian on disk */
    uint8_t  memlimit_be[8];    /* big-endian on disk */
    uint8_t  wrapped_dek[DEK_SIZE + WRAP_MAC_SIZE];
    uint8_t  wrap_nonce[WRAP_NONCE_SIZE];
    uint8_t  stream_header[STREAM_HEADER_SIZE];
} sv_header_t;

/* ----- v7 header: multi-slot key envelope -----
 *
 *   off  size  field
 *    0    4    magic "SV07"
 *    4    1    version (7)
 *    5    1    flags
 *    6   18    reserved (zero) -- deliberately OUTSIDE no field: slots are
 *                 self-describing so slot ops never touch the AAD prefix
 *   24    8    opslimit_be      global KDF params for all slots
 *   32    8    memlimit_be
 *   40   24    stream_header
 *   64  8x96   slots
 *
 * AAD for the first secretstream block and for the manifest trailer is ONLY
 * the fixed 64-byte prefix. The slot area is deliberately outside the AAD so
 * keys can be added/removed/rotated in place without touching the encrypted
 * stream. */
#define SV7_MAGIC     "SV07"
#define SV7_VERSION   7
#define SV7_MAX_SLOTS 8
#define SV7_SLOT_SIZE 96
#define SV7_FIXED_LEN 64
#define SV7_HDR_LEN   (SV7_FIXED_LEN + SV7_MAX_SLOTS * SV7_SLOT_SIZE)

/* slot types */
#define SV_SLOT_EMPTY 0
#define SV_SLOT_PASS  1

#pragma pack(push, 1)
typedef struct {
    uint8_t type;                                   /* SV_SLOT_* */
    uint8_t reserved[7];
    uint8_t kdf_salt[SALT_SIZE];
    uint8_t wrap_nonce[WRAP_NONCE_SIZE];
    uint8_t wrapped_dek[DEK_SIZE + WRAP_MAC_SIZE];
} sv7_slot_t;

typedef struct {
    char     magic[4];
    uint8_t  version;
    uint8_t  flags;
    uint8_t  reserved[18];
    uint8_t  opslimit_be[8];
    uint8_t  memlimit_be[8];
    uint8_t  stream_header[STREAM_HEADER_SIZE];
    sv7_slot_t slots[SV7_MAX_SLOTS];
} sv7_header_t;
#pragma pack(pop)

_Static_assert(sizeof(sv7_slot_t)  == SV7_SLOT_SIZE, "slot layout");
_Static_assert(sizeof(sv7_header_t) == SV7_HDR_LEN,  "v7 header layout");
_Static_assert(sizeof(sv_header_t) == 134,           "v6 header layout");

/* ----- Generic read-side view of a vault header (v6 or v7) ----- */
typedef struct {
    int     version;                 /* 6 or 7 */
    uint8_t flags;
    uint64_t opslimit, memlimit;
    const uint8_t *shdr;             /* stream header (points into raw[]) */
    const uint8_t *aad;              /* first-block / manifest-trailer AAD */
    size_t  aad_len;
    uint8_t raw[SV7_HDR_LEN];        /* full on-disk header bytes */
    size_t  raw_len;
    uint8_t dek[DEK_SIZE];           /* filled by vault_unlock() */
} vault_meta_t;

static int vault_read_header(int fd, vault_meta_t *m);
static int vault_unlock(vault_meta_t *m, const char *pw, size_t pw_len,
                        const uint8_t *kf, size_t kf_len);
static int vault_unlock_ex(vault_meta_t *m, const char *pw, size_t pw_len,
                           const uint8_t *kf, size_t kf_len, int *matched_slot);
static void vault_wipe_dek(vault_meta_t *m);

#pragma pack(pop)

static volatile sig_atomic_t g_interrupted = 0;

static void signal_handler(int sig) { (void)sig; g_interrupted = 1; }

/* ----- Progress meter (-P) ----- */
static int g_progress = 0;

/* total < 0 means "unknown" (pipes, compressed streams, bundles) */
static void progress_update(off_t done, off_t total) {
    static off_t last_bytes = 0;
    static time_t last_sec = 0;
    static int started = 0;
    if (!g_progress) return;
    time_t now = time(NULL);
    int final = (total >= 0 && done >= total);
    if (started && !final &&
        done - last_bytes < (256 << 10) && now == last_sec)
        return;
    started = 1;
    last_bytes = done;
    last_sec = now;
    if (total > 0) {
        fprintf(stderr, "\r%lld / %lld bytes (%d%%)   ",
                (long long)done, (long long)total,
                (int)(((double)done * 100.0) / (double)total));
    } else {
        fprintf(stderr, "\r%lld bytes   ", (long long)done);
    }
    fflush(stderr);
}

static void progress_finish(void) {
    static int called = 0;
    if (g_progress && !called) { fputc('\n', stderr); called = 1; }
}

/* ----- Network-byte-order helpers ----- */
static void put_u64be(uint8_t *out, uint64_t v) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint64_t get_u64be(const uint8_t *in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
}
static int32_t get_i32be(const uint8_t *in) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | in[i];
    return (int32_t)v;
}

/* Strictly parse a decimal uint64 CLI argument with range validation. */
static int parse_u64_arg(const char *s, const char *name,
                          uint64_t lo, uint64_t hi, uint64_t *out) {
    if (!s || !*s) { fprintf(stderr, "Error: %s requires a value\n", name); return -1; }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        fprintf(stderr, "Error: invalid %s '%s'\n", name, s);
        return -1;
    }
    if (v < lo || v > hi) {
        fprintf(stderr, "Error: %s out of range [%llu..%llu]: '%s'\n", name,
                (unsigned long long)lo, (unsigned long long)hi, s);
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

/* ----- Robust I/O helpers to handle partial reads/writes ----- */
static ssize_t read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)got; /* EOF – return what we already read */
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static ssize_t write_full(int fd, const void *buf, size_t n) {
    size_t put = 0;
    while (put < n) {
        ssize_t r = write(fd, (const char *)buf + put, n - put);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        put += (size_t)r;
    }
    return (ssize_t)put;
}

/* ----- Argon2id: derive a KEK from password (+ optional keyfile) ----- */
static int derive_kek(const char *password, size_t pw_len,
                       const uint8_t *keyfile_data, size_t keyfile_len,
                       const uint8_t *salt, uint8_t *kek,
                       unsigned long long opslimit, size_t memlimit) {
    size_t total_len = pw_len + keyfile_len;
    uint8_t *combined = sodium_malloc(total_len > 0 ? total_len : 1);
    if (!combined) return -1;
    /* Locking is best-effort: large keyfiles can exceed RLIMIT_MEMLOCK, and
     * failing derivation over a missed hardening would break legitimate use.
     * sodium_malloc still provides guard pages + canary protection. */
    (void)sodium_mlock(combined, total_len > 0 ? total_len : 1);

    if (password && pw_len) memcpy(combined, password, pw_len);
    if (keyfile_data && keyfile_len) memcpy(combined + pw_len, keyfile_data, keyfile_len);

    int ret = crypto_pwhash(kek, DEK_SIZE,
                             (const char *)combined, total_len,
                             salt, opslimit, memlimit,
                             crypto_pwhash_ALG_ARGON2ID13);
    sodium_munlock(combined, total_len > 0 ? total_len : 1);
    sodium_memzero(combined, total_len > 0 ? total_len : 1);
    sodium_free(combined);
    return ret;
}

/* ==========================================================================
 * Generic vault opening (v6 + v7)
 * ========================================================================== */

static int vault_read_header(int fd, vault_meta_t *m) {
    memset(m, 0, sizeof(*m));
    char magic[4];
    if (read_full(fd, magic, 4) != 4 || memcmp(magic, "SV0", 3) != 0)
        return -1;
    if (magic[3] == '6') {
        m->version = 6;
        m->raw_len = sizeof(sv_header_t);
    } else if (magic[3] == '7') {
        m->version = 7;
        m->raw_len = SV7_HDR_LEN;
    } else {
        return -1;
    }
    memcpy(m->raw, magic, 4);
    if (read_full(fd, m->raw + 4, m->raw_len - 4) != (ssize_t)(m->raw_len - 4))
        return -1;

    m->flags = m->raw[5];
    if (m->version == 6) {
        m->opslimit = get_u64be(m->raw + 22);
        m->memlimit = get_u64be(m->raw + 30);
        m->shdr     = m->raw + 110;
        m->aad      = m->raw;
        m->aad_len  = sizeof(sv_header_t);
    } else {
        m->opslimit = get_u64be(m->raw + 24);
        m->memlimit = get_u64be(m->raw + 32);
        m->shdr     = m->raw + 40;
        m->aad      = m->raw;
        m->aad_len  = SV7_FIXED_LEN;
    }
    return 0;
}

static int vault_unlock(vault_meta_t *m, const char *pw, size_t pw_len,
                        const uint8_t *kf, size_t kf_len) {
    return vault_unlock_ex(m, pw, pw_len, kf, kf_len, NULL);
}

/* Same, but reports which slot authenticated (v7 only, else -1). */
static int vault_unlock_ex(vault_meta_t *m, const char *pw, size_t pw_len,
                           const uint8_t *kf, size_t kf_len, int *matched_slot) {
    if (matched_slot) *matched_slot = -1;
    uint8_t kek[DEK_SIZE];
    if (sodium_mlock(kek, DEK_SIZE) != 0) return -1;
    int rc = -1;

    if (m->version == 6) {
        if (derive_kek(pw, pw_len, kf, kf_len, m->raw + 6, kek,
                       m->opslimit, (size_t)m->memlimit) == 0 &&
            crypto_secretbox_open_easy(m->dek, m->raw + 38,
                                       DEK_SIZE + WRAP_MAC_SIZE,
                                       m->raw + 86, kek) == 0)
            rc = 0;
    } else {
        for (unsigned i = 0; i < SV7_MAX_SLOTS && rc != 0; i++) {
            const uint8_t *slot = m->raw + SV7_FIXED_LEN + i * SV7_SLOT_SIZE;
            if (slot[0] != SV_SLOT_PASS) continue;
            if (derive_kek(pw, pw_len, kf, kf_len, slot + 8, kek,
                           m->opslimit, (size_t)m->memlimit) == 0 &&
                crypto_secretbox_open_easy(m->dek, slot + 48,
                                           DEK_SIZE + WRAP_MAC_SIZE,
                                           slot + 24, kek) == 0) {
                rc = 0;
                if (matched_slot) *matched_slot = (int)i;
            }
        }
    }

    sodium_munlock(kek, DEK_SIZE);
    sodium_memzero(kek, DEK_SIZE);
    return rc;
}

static void vault_wipe_dek(vault_meta_t *m) {
    sodium_munlock(m->dek, DEK_SIZE);
    sodium_memzero(m->dek, DEK_SIZE);
}

/* Populate a passphrase slot wrapping `dek`. Returns 0 on success. */
static int fill_slot(sv7_slot_t *slot, const uint8_t dek[DEK_SIZE],
                     const char *pw, size_t pw_len,
                     const uint8_t *kf, size_t kf_len,
                     uint64_t ops, size_t mem) {
    memset(slot, 0, sizeof(*slot));
    slot->type = SV_SLOT_PASS;
    randombytes_buf(slot->kdf_salt, SALT_SIZE);
    randombytes_buf(slot->wrap_nonce, WRAP_NONCE_SIZE);
    uint8_t kek[DEK_SIZE];
    int rc = -1;
    if (sodium_mlock(kek, DEK_SIZE) == 0) {
        if (derive_kek(pw, pw_len, kf, kf_len, slot->kdf_salt, kek, ops, mem) == 0 &&
            crypto_secretbox_easy(slot->wrapped_dek, dek, DEK_SIZE,
                                  slot->wrap_nonce, kek) == 0)
            rc = 0;
        sodium_munlock(kek, DEK_SIZE);
        sodium_memzero(kek, DEK_SIZE);
    }
    return rc;
}

/* ----- nftw helpers to recursively remove a directory ----- */
static int nftw_remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}
static void recursive_remove(const char *path) {
    nftw(path, nftw_remove_cb, 16, FTW_DEPTH | FTW_PHYS);
}

/* ----- file identity check ----- */
static int is_same_file(const char *a, const char *b) {
    struct stat sa, sb;
    if (stat(a, &sa) < 0 || stat(b, &sb) < 0) return 0;
    return (sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino);
}

static int is_path_inside(const char *parent, const char *child) {
    size_t plen = strlen(parent);
    if (plen == 0) return 0;
    if (strncmp(child, parent, plen) != 0) return 0;
    if (child[plen] == '/' || child[plen] == '\0') return 1;
    return 0;
}

/* ----- secure (overwrite-based) deletion ----- */
static int secure_delete(const char *path, off_t size) {
    int fd = open(path, O_RDWR);
    if (fd < 0 && errno == EACCES) {
        if (chmod(path, S_IRUSR | S_IWUSR) == 0)
            fd = open(path, O_RDWR);
    }
    if (fd < 0) {
        perror("open for shred");
        return -1;
    }

    uint8_t *buf = sodium_malloc(CHUNK_SIZE);
    if (!buf) { close(fd); return -1; }
    sodium_mlock(buf, CHUNK_SIZE);

    for (int pass = 0; pass < 3; pass++) {
        if (lseek(fd, 0, SEEK_SET) < 0) break;
        off_t remaining = size;
        while (remaining > 0) {
            size_t want = remaining > CHUNK_SIZE ? CHUNK_SIZE : (size_t)remaining;
            if (pass < 2) randombytes_buf(buf, want);
            else          memset(buf, 0, want);
            ssize_t w = write_full(fd, buf, want);
            if (w < 0) break;
            remaining -= w;
        }
        fsync(fd);
    }
    sodium_munlock(buf, CHUNK_SIZE);
    sodium_memzero(buf, CHUNK_SIZE);
    sodium_free(buf);
    close(fd);

    /* Rename before unlink to obscure name, then sync parent directory. */
    char *dup = strdup(path);
    if (dup) {
        char *dirp = dirname(dup);
        char tmpl[PATH_MAX];
        if (snprintf(tmpl, sizeof(tmpl), "%s/.sv_shred_XXXXXX", dirp) < (int)sizeof(tmpl)) {
            int tfd = mkstemp(tmpl);
            if (tfd >= 0) {
                close(tfd);
                unlink(tmpl);
                if (rename(path, tmpl) == 0) {
                    /* Sync parent directory after rename */
                    int dir_fd = open(dirp, O_RDONLY);
                    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }
                    unlink(tmpl);
                } else {
                    unlink(path);
                }
            } else {
                unlink(path);
            }
        } else {
            unlink(path);
        }
        free(dup);
    } else {
        unlink(path);
    }
    /* Final parent directory sync after unlink */
    {
        char *dup2 = strdup(path);
        if (dup2) {
            char *dname = dirname(dup2);
            int dir_fd = open(dname, O_RDONLY);
            if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }
            free(dup2);
        }
    }
    return 0;
}

/* ==========================================================================
 * Core stream writer / reader
 * ========================================================================== */

typedef struct {
    int out_fd;
    crypto_secretstream_xchacha20poly1305_state st;
    uint8_t *cipher_buf;
    int first_block;
    const uint8_t *header_ad;
    size_t header_ad_len;
} sv_writer_t;

static int writer_init(sv_writer_t *w, int out_fd, const uint8_t dek[DEK_SIZE],
                        uint8_t stream_header_out[STREAM_HEADER_SIZE],
                        const uint8_t *header_ad, size_t header_ad_len) {
    w->out_fd = out_fd;
    w->first_block = 1;
    w->header_ad = header_ad;
    w->header_ad_len = header_ad_len;
    w->cipher_buf = sodium_malloc(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!w->cipher_buf) return -1;
    if (crypto_secretstream_xchacha20poly1305_init_push(&w->st, stream_header_out, dek) != 0) {
        sodium_free(w->cipher_buf);
        w->cipher_buf = NULL;
        return -1;
    }
    return 0;
}

static int writer_push(sv_writer_t *w, const uint8_t *plain, size_t plain_len, uint8_t tag) {
    if (plain_len > CHUNK_SIZE) return -1;  /* would exceed frame bound */
    unsigned long long clen;
    const uint8_t *ad = w->first_block ? w->header_ad : NULL;
    size_t ad_len = w->first_block ? w->header_ad_len : 0;
    w->first_block = 0;

    if (crypto_secretstream_xchacha20poly1305_push(
            &w->st, w->cipher_buf, &clen, plain, plain_len, ad, ad_len, tag) != 0)
        return -1;

    uint8_t len_field[4];
    len_field[0] = (uint8_t)((clen >> 24) & 0xff);
    len_field[1] = (uint8_t)((clen >> 16) & 0xff);
    len_field[2] = (uint8_t)((clen >> 8) & 0xff);
    len_field[3] = (uint8_t)(clen & 0xff);
    if (write_full(w->out_fd, len_field, 4) != 4) return -1;
    if (write_full(w->out_fd, w->cipher_buf, clen) != (ssize_t)clen) return -1;
    return 0;
}

static void writer_free(sv_writer_t *w) {
    if (w->cipher_buf) sodium_free(w->cipher_buf);
}

typedef struct {
    int in_fd;
    crypto_secretstream_xchacha20poly1305_state st;
    uint8_t *cipher_buf;
    int first_block;
    int saw_final;
    const uint8_t *header_ad;
    size_t header_ad_len;
} sv_reader_t;

static int reader_init(sv_reader_t *r, int in_fd, const uint8_t dek[DEK_SIZE],
                        const uint8_t stream_header_in[STREAM_HEADER_SIZE],
                        const uint8_t *header_ad, size_t header_ad_len) {
    r->in_fd = in_fd;
    r->first_block = 1;
    r->saw_final = 0;
    r->header_ad = header_ad;
    r->header_ad_len = header_ad_len;
    r->cipher_buf = sodium_malloc(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!r->cipher_buf) return -1;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&r->st, stream_header_in, dek) != 0) {
        sodium_free(r->cipher_buf);
        r->cipher_buf = NULL;
        return -1;
    }
    return 0;
}

static int reader_pull(sv_reader_t *r, uint8_t *plain, size_t *plain_len, uint8_t *tag) {
    uint8_t len_field[4];
    ssize_t got = read_full(r->in_fd, len_field, 4);
    if (got == 0) {
        return r->saw_final ? 0 : -1;
    }
    if (got != 4) return -1;
    if (r->saw_final) return -1;

    uint32_t clen = ((uint32_t)len_field[0] << 24) | ((uint32_t)len_field[1] << 16) |
                    ((uint32_t)len_field[2] << 8)  | (uint32_t)len_field[3];
    if (clen > CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES ||
        clen < crypto_secretstream_xchacha20poly1305_ABYTES)
        return -1;
    if (read_full(r->in_fd, r->cipher_buf, clen) != (ssize_t)clen) return -1;

    const uint8_t *ad = r->first_block ? r->header_ad : NULL;
    size_t ad_len = r->first_block ? r->header_ad_len : 0;
    r->first_block = 0;

    unsigned long long plen;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &r->st, plain, &plen, tag, r->cipher_buf, clen, ad, ad_len) != 0)
        return -1;

    *plain_len = (size_t)plen;
    if (*tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) r->saw_final = 1;
    return 1;
}

static void reader_free(sv_reader_t *r) {
    if (r->cipher_buf) sodium_free(r->cipher_buf);
}



/* Encode one entry record (shared by stream writer and manifest builder).
 * Returns encoded length, or -1 on oversize paths. */
static int encode_entry_header(uint8_t *buf, size_t bufsz, const char *relpath,
                                int is_dir, off_t size, mode_t mode,
                                int64_t mtime_sec, int32_t mtime_nsec) {
    size_t rlen = strlen(relpath);
    if (rlen > MAX_BUNDLE_PATH) return -1;
    uint16_t plen = (uint16_t)rlen;
    if (bufsz < (size_t)(1 + 2 + plen + (is_dir ? 4 : 24))) return -1;
    size_t o = 0;
    buf[o++] = is_dir ? ENTRY_DIR : ENTRY_FILE;
    buf[o++] = (uint8_t)(plen >> 8);
    buf[o++] = (uint8_t)(plen & 0xff);
    memcpy(buf + o, relpath, plen); o += plen;
    if (is_dir) {
        buf[o++] = (uint8_t)((mode >> 24) & 0xff);
        buf[o++] = (uint8_t)((mode >> 16) & 0xff);
        buf[o++] = (uint8_t)((mode >> 8) & 0xff);
        buf[o++] = (uint8_t)(mode & 0xff);
    } else {
        put_u64be(buf + o, (uint64_t)size); o += 8;
        buf[o++] = (uint8_t)((mode >> 24) & 0xff);
        buf[o++] = (uint8_t)((mode >> 16) & 0xff);
        buf[o++] = (uint8_t)((mode >> 8) & 0xff);
        buf[o++] = (uint8_t)(mode & 0xff);
        /* mtime_sec (int64 BE) */
        for (int i = 7; i >= 0; i--) {
            buf[o++] = (uint8_t)((mtime_sec >> (i*8)) & 0xff);
        }
        /* mtime_nsec (int32 BE) */
        buf[o++] = (uint8_t)((mtime_nsec >> 24) & 0xff);
        buf[o++] = (uint8_t)((mtime_nsec >> 16) & 0xff);
        buf[o++] = (uint8_t)((mtime_nsec >> 8) & 0xff);
        buf[o++] = (uint8_t)(mtime_nsec & 0xff);
    }
    return (int)o;
}

/* ==========================================================================
 * Encrypted manifest trailer (appended AFTER the TAG_FINAL frame)
 *
 *   "SVM1" | ver(1)=1 | nonce(24) | ct_len(u64 BE) | AEAD ciphertext
 *
 * Key:  mkey = crypto_kdf_derive_from_key(dek, subkey_id=1, ctx="SVmanif1")
 * AAD:  the full v6 header – binds the trailer to this exact vault header.
 * Readers that only understand v6 stop at TAG_FINAL and ignore these bytes.
 * ========================================================================== */

#define SV_MANIFEST_MAGIC "SVM1"
#define SV_MANIFEST_VERSION 1
#define SV_MANIFEST_FIXED (4 + 1 + 24 + 8)
#define SV_MANIFEST_MAX_CT (256u * 1024 * 1024)

typedef struct { uint8_t *data; size_t len, cap; } mbuf_t;

static int mbuf_append(mbuf_t *m, const void *p, size_t n) {
    if (m->len + n > m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 4096;
        while (nc < m->len + n) nc *= 2;
        uint8_t *nd = realloc(m->data, nc);
        if (!nd) return -1;
        m->data = nd;
        m->cap = nc;
    }
    memcpy(m->data + m->len, p, n);
    m->len += n;
    return 0;
}

static void mbuf_free(mbuf_t *m) { free(m->data); m->data = NULL; m->len = m->cap = 0; }

static int write_manifest_trailer(int out_fd, const uint8_t dek[DEK_SIZE],
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *plain, size_t plain_len) {
    unsigned char mkey[crypto_kdf_KEYBYTES];
    if (crypto_kdf_derive_from_key(mkey, sizeof(mkey), 1, "SVmanif1", dek) != 0)
        return -1;

    size_t ct_cap = plain_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char *ct = malloc(ct_cap);
    if (!ct) { sodium_memzero(mkey, sizeof(mkey)); return -1; }
    unsigned long long clen = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct, &clen, plain, plain_len,
        aad, aad_len, NULL, nonce, mkey);
    sodium_memzero(mkey, sizeof(mkey));
    if (rc != 0) { free(ct); return -1; }

    uint8_t fixed[SV_MANIFEST_FIXED];
    memcpy(fixed, SV_MANIFEST_MAGIC, 4);
    fixed[4] = SV_MANIFEST_VERSION;
    memcpy(fixed + 5, nonce, sizeof(nonce));
    put_u64be(fixed + 29, (uint64_t)clen);

    int ret = -1;
    if (write_full(out_fd, fixed, sizeof(fixed)) == sizeof(fixed) &&
        write_full(out_fd, ct, clen) == (ssize_t)clen)
        ret = 0;
    sodium_memzero(ct, (size_t)clen);
    free(ct);
    return ret;
}

/* ==========================================================================
 * Single file encrypt / decrypt
 * ========================================================================== */

static int encrypt_stream_body(int in_fd, sv_writer_t *w, int use_zlib,
                                off_t total, off_t *processed_out) {
    z_stream zstrm;
    memset(&zstrm, 0, sizeof(zstrm));
    if (use_zlib) {
        if (deflateInit2(&zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                         Z_DEFAULT_STRATEGY) != Z_OK) {
            return -1;
        }
    }

    ssize_t n;
    off_t processed = 0;
    int ret = -1;

    uint8_t *cur_buf = malloc(CHUNK_SIZE);
    uint8_t *next_buf = malloc(CHUNK_SIZE);
    if (!cur_buf || !next_buf) {
        free(cur_buf); free(next_buf);
        if (use_zlib) deflateEnd(&zstrm);
        return -1;
    }

    /* When compressing, read slightly less than a full chunk: worst-case
     * zlib expansion on incompressible data (~+0.04%) must still fit the
     * frame bound of CHUNK_SIZE + ABYTES enforced by writer/reader. */
    const size_t chunk_in = use_zlib ? CHUNK_SIZE - COMP_SLACK : CHUNK_SIZE;

    n = read_full(in_fd, cur_buf, chunk_in);
    if (n < 0) goto done;

    if (n == 0) {
        if (writer_push(w, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0)
            goto done;
        ret = 0;
        goto done;
    }

    while (!g_interrupted && n > 0) {
        uint8_t *data = cur_buf;
        size_t data_len = (size_t)n;
        uint8_t *comp_buf = NULL;

        if (use_zlib) {
            size_t cap = deflateBound(&zstrm, (uLong)n);
            comp_buf = malloc(cap);
            if (!comp_buf) goto done;
            zstrm.avail_in = (uInt)n;
            zstrm.next_in = cur_buf;
            zstrm.avail_out = (uInt)cap;
            zstrm.next_out = comp_buf;
            if (deflate(&zstrm, Z_FINISH) != Z_STREAM_END) { free(comp_buf); goto done; }
            data_len = cap - zstrm.avail_out;
            data = comp_buf;
            deflateReset(&zstrm);
        }

        ssize_t next_n = read_full(in_fd, next_buf, chunk_in);
        if (next_n < 0) { if (comp_buf) free(comp_buf); goto done; }

        uint8_t tag = (next_n == 0) ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                     : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        if (writer_push(w, data, data_len, tag) != 0) {
            if (comp_buf) free(comp_buf);
            goto done;
        }
        if (comp_buf) free(comp_buf);

        processed += n;
        progress_update(processed, total);
        n = next_n;
        uint8_t *tmp = cur_buf; cur_buf = next_buf; next_buf = tmp;
    }

    if (g_interrupted) goto done;
    ret = 0;

done:
    if (use_zlib) deflateEnd(&zstrm);
    free(cur_buf);
    free(next_buf);
    if (processed_out) *processed_out = processed;
    return ret;
}

static int encrypt_file(const char *inpath, const char *outpath,
                         const char *password, size_t pw_len,
                         const uint8_t *keyfile_data, size_t keyfile_len,
                         int compress, uint64_t opslimit, uint64_t memlimit,
                         int shred_original, int verbose, int force_overwrite) {
    int in_fd = -1, out_fd = -1, ret = -1;
    uint8_t dek[DEK_SIZE];
    sv_writer_t w; memset(&w, 0, sizeof(w));
    int writer_ok = 0;

    /* Guard against overwriting existing output */
    if (!force_overwrite) {
        struct stat st_out;
        if (stat(outpath, &st_out) == 0) {
            fprintf(stderr, "Output '%s' already exists. Use -f to force overwrite.\n", outpath);
            return -1;
        }
    }

    if (is_same_file(inpath, outpath)) {
        fprintf(stderr, "Error: input and output are the same file\n");
        return -1;
    }
    int use_stdin = (strcmp(inpath, "-") == 0);
    if (use_stdin) {
        in_fd = STDIN_FILENO;
    } else {
        in_fd = open(inpath, O_RDONLY);
        if (in_fd < 0) { perror("open input"); goto cleanup; }
    }
    struct stat st;
    if (!use_stdin) {
        if (fstat(in_fd, &st) < 0) { perror("fstat"); goto cleanup; }
    }

    int use_stdout = (strcmp(outpath, "-") == 0);
    if (use_stdout) {
        out_fd = STDOUT_FILENO;
    } else {
        out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (out_fd < 0) { perror("open output"); goto cleanup; }
    }

    sv7_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, SV7_MAGIC, 4);
    hdr.version = SV7_VERSION;
    hdr.flags = compress ? FLAG_COMPRESSED : 0;
    put_u64be(hdr.opslimit_be, opslimit);
    put_u64be(hdr.memlimit_be, memlimit);

    if (verbose) {
        fprintf(stderr, "opslimit=%llu memlimit=%llu flags=0x%02x\n",
                (unsigned long long)opslimit, (unsigned long long)memlimit,
                hdr.flags);
    }

    randombytes_buf(dek, DEK_SIZE);
    if (sodium_mlock(dek, DEK_SIZE) != 0) goto cleanup;
    if (fill_slot(&hdr.slots[0], dek, password, pw_len,
                  keyfile_data, keyfile_len, opslimit, (size_t)memlimit) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        goto cleanup;
    }

    if (writer_init(&w, out_fd, dek, hdr.stream_header,
                    (const uint8_t *)&hdr, SV7_FIXED_LEN) != 0) {
        fprintf(stderr, "Stream init failed\n");
        goto cleanup;
    }
    writer_ok = 1;

    if (write_full(out_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("write header");
        goto cleanup;
    }

    off_t processed = 0;
    if (encrypt_stream_body(in_fd, &w, compress,
                            use_stdin ? -1 : st.st_size, &processed) != 0) {
        fprintf(stderr, "Encryption failed or interrupted\n");
        goto cleanup;
    }
    if (verbose) fprintf(stderr, "Encrypted %lld bytes -> %s\n",
                         (long long)processed, outpath);

    /* Encrypted manifest trailer: original filename + TRUE plaintext size
     * (even when compressed). Optional metadata – failure never invalidates
     * the vault itself. */
    {
        mbuf_t mf = {0};
        char *name_copy = NULL;
        const char *disp = "-";
        if (!use_stdin) {
            name_copy = strdup(inpath);
            disp = name_copy ? basename(name_copy) : "?";
        }
        uint8_t rec[1 + 2 + MAX_BUNDLE_PATH + 8 + 4 + 8 + 4];
        int rn = encode_entry_header(rec, sizeof(rec), disp, 0, processed,
                                     use_stdin ? 0 : (int)(st.st_mode & 0777),
                                     use_stdin ? 0 : (int64_t)st.st_mtim.tv_sec,
                                     use_stdin ? 0 : st.st_mtim.tv_nsec);
        free(name_copy);
        if (rn < 0 || mbuf_append(&mf, rec, (size_t)rn) != 0 ||
            write_manifest_trailer(out_fd, dek,
                                   (const uint8_t *)&hdr, SV7_FIXED_LEN,
                                   mf.data, mf.len) != 0)
            fprintf(stderr, "Warning: manifest trailer not written\n");
        mbuf_free(&mf);
    }

    /* Make the vault durable BEFORE reporting success / shredding the
     * original – otherwise a crash can lose both copies at once. */
    if (out_fd >= 0 && out_fd != STDOUT_FILENO && fsync(out_fd) != 0)
        perror("fsync vault");

    ret = 0;

    if (shred_original && ret == 0 && !use_stdin) {
        close(in_fd); in_fd = -1;
        fprintf(stderr, "Shredding original (overwrite-based; see header comment on SSD/COW caveats)...\n");
        if (secure_delete(inpath, st.st_size) != 0)
            fprintf(stderr, "Warning: secure deletion failed\n");
    }

cleanup:
    sodium_munlock(dek, DEK_SIZE);
    sodium_memzero(dek, DEK_SIZE);
    if (writer_ok) writer_free(&w);
    if (in_fd >= 0 && in_fd != STDIN_FILENO) close(in_fd);
    if (out_fd >= 0 && out_fd != STDOUT_FILENO) {
        close(out_fd);
        if (ret != 0) unlink(outpath);
    }
    return ret;
}

static int decrypt_file(const char *inpath, const char *outpath,
                         const char *password, size_t pw_len,
                         const uint8_t *keyfile_data, size_t keyfile_len,
                         int verify_only, int verbose, int force_overwrite) {
    int in_fd = -1, out_fd = -1, ret = -1;
    vault_meta_t vm;
    sv_reader_t r; memset(&r, 0, sizeof(r));
    int reader_ok = 0;
    z_stream zstrm; memset(&zstrm, 0, sizeof(zstrm));
    int zlib_ok = 0;

    int use_stdin = (strcmp(inpath, "-") == 0);
    if (use_stdin) {
        in_fd = STDIN_FILENO;
    } else {
        in_fd = open(inpath, O_RDONLY);
        if (in_fd < 0) { perror("open input"); goto cleanup; }
    }

    if (!verify_only) {
        if (!force_overwrite) {
            struct stat st_out;
            if (strcmp(outpath, "-") != 0 && stat(outpath, &st_out) == 0) {
                fprintf(stderr, "Output '%s' already exists. Use -f to force overwrite.\n", outpath);
                goto cleanup;
            }
        }
        if (is_same_file(inpath, outpath)) {
            fprintf(stderr, "Error: output would overwrite input\n");
            goto cleanup;
        }
        int use_stdout = (strcmp(outpath, "-") == 0);
        if (use_stdout) {
            out_fd = STDOUT_FILENO;
        } else {
            out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (out_fd < 0) { perror("open output"); goto cleanup; }
        }
    }

    if (vault_read_header(in_fd, &vm) != 0) {
        fprintf(stderr, "Invalid or truncated vault file (header)\n");
        goto cleanup;
    }
    if (vm.flags & FLAG_DIRECTORY) {
        fprintf(stderr, "This is a directory bundle, not a single file\n");
        goto cleanup;
    }
    if (vault_unlock(&vm, password, pw_len, keyfile_data, keyfile_len) != 0) {
        fprintf(stderr, "[FAIL] Wrong password/keyfile, or header tampered\n");
        goto cleanup;
    }

    if (reader_init(&r, in_fd, vm.dek, vm.shdr, vm.aad, vm.aad_len) != 0) {
        fprintf(stderr, "Stream init failed\n");
        goto cleanup;
    }
    reader_ok = 1;

    if (vm.flags & FLAG_COMPRESSED) {
        if (inflateInit2(&zstrm, 15 + 16) != Z_OK) {
            fprintf(stderr, "Decompression init failed\n");
            goto cleanup;
        }
        zlib_ok = 1;
    }

    uint8_t *plain = sodium_malloc(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!plain) goto cleanup;

    off_t decrypted_size = 0;
    for (;;) {
        if (g_interrupted) { sodium_free(plain); goto cleanup; }
        size_t plen; uint8_t tag;
        int rc = reader_pull(&r, plain, &plen, &tag);
        if (rc < 0) {
            fprintf(stderr, "\n[FAIL] Authentication failed: wrong password, tampered, "
                    "reordered, or truncated ciphertext\n");
            sodium_free(plain);
            goto cleanup;
        }
        if (rc == 0) break;

        if (!verify_only) {
            if (zlib_ok) {
                /* Each ciphertext message holds one complete gzip member
                 * (the encryptor finishes + resets per chunk), so the inflate
                 * state must be reset before every message or all chunks
                 * after the first silently decompress to nothing. */
                if (inflateReset(&zstrm) != Z_OK) {
                    fprintf(stderr, "Decompression reset failed\n");
                    sodium_free(plain); goto cleanup;
                }
                zstrm.avail_in = (uInt)plen;
                zstrm.next_in = plain;
                do {
                    uint8_t outbuf[CHUNK_SIZE];
                    zstrm.avail_out = CHUNK_SIZE;
                    zstrm.next_out = outbuf;
                    int zrc = inflate(&zstrm, Z_NO_FLUSH);
                    size_t have = CHUNK_SIZE - zstrm.avail_out;
                    if (have) {
                        if (write_full(out_fd, outbuf, have) != (ssize_t)have) {
                            perror("write"); sodium_free(plain); goto cleanup;
                        }
                        decrypted_size += have;
                    }
                    if (zrc == Z_STREAM_END) break;
                    if (zrc != Z_OK) { fprintf(stderr, "Decompression error\n");
                        sodium_free(plain); goto cleanup; }
                } while (zstrm.avail_in > 0);
            } else {
                if (write_full(out_fd, plain, plen) != (ssize_t)plen) {
                    perror("write"); sodium_free(plain); goto cleanup;
                }
                decrypted_size += plen;
            }
        } else {
            decrypted_size += plen;
        }
        progress_update(decrypted_size, -1);

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
    }
    sodium_free(plain);

    if (verbose) fprintf(stderr, "%s %lld bytes OK\n",
                         verify_only ? "Verified" : "Decrypted",
                         (long long)decrypted_size);
    ret = 0;

cleanup:
    vault_wipe_dek(&vm);
    if (zlib_ok) inflateEnd(&zstrm);
    if (reader_ok) reader_free(&r);
    if (in_fd >= 0 && in_fd != STDIN_FILENO) close(in_fd);
    if (out_fd >= 0 && out_fd != STDOUT_FILENO) {
        close(out_fd);
        if (ret != 0) unlink(outpath);
    }
    return ret;
}


/* ==========================================================================
 * Directory bundle mode - with improved metadata and iterative traversal
 * ========================================================================== */

/*
 * Bundle entry header format (per entry):
 *   tag          : 1 byte  (ENTRY_FILE or ENTRY_DIR)
 *   path_len     : 2 bytes (big-endian)
 *   relpath      : path_len bytes
 *   [for files:]
 *     size       : 8 bytes (uint64 BE)
 *     mode       : 4 bytes (uint32 BE)
 *     mtime_sec  : 8 bytes (int64 BE)
 *     mtime_nsec : 4 bytes (int32 BE)
 *   [for dirs:]
 *     mode       : 4 bytes (uint32 BE)   - no size or times
 */

static int bundle_write_entry_header(sv_writer_t *w, const char *relpath,
                                     int is_dir, off_t size, mode_t mode,
                                     int64_t mtime_sec, int32_t mtime_nsec) {
    uint8_t hdrbuf[1 + 2 + MAX_BUNDLE_PATH + 8 + 4 + 8 + 4];
    int n = encode_entry_header(hdrbuf, sizeof(hdrbuf), relpath, is_dir,
                                size, mode, mtime_sec, mtime_nsec);
    if (n < 0) {
        fprintf(stderr, "Path too long for bundle entry (max %d): %s\n",
                MAX_BUNDLE_PATH, relpath);
        return -1;
    }
    return writer_push(w, hdrbuf, (size_t)n,
                       crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
}

/* Comparison function for sorting directory entries */
static int dirent_comp(const void *a, const void *b) {
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sa, sb);
}

/* A path is excluded when a pattern matches the full relative path OR the
 * basename, so "*.tmp" works anywhere and "sub/x*.log" matches by location. */
static int name_excluded(const char *relpath, char **pats, size_t n_pats) {
    if (n_pats == 0) return 0;
    const char *base = strrchr(relpath, '/');
    base = base ? base + 1 : relpath;
    for (size_t i = 0; i < n_pats; i++) {
        if (fnmatch(pats[i], relpath, 0) == 0) return 1;
        if (fnmatch(pats[i], base, 0) == 0) return 1;
    }
    return 0;
}

/* Iterative directory traversal using an explicit stack */
static int bundle_add_tree(sv_writer_t *w, const char *base_in,
                           char **excludes, size_t n_excludes,
                           mbuf_t *mf) {
    struct stack_node {
        char *rel;        /* relative path from base_in, or "" for root */
        int visited;      /* 0 = not yet enumerated, 1 = files processed */
    };
    struct stack_node *stack = NULL;
    size_t stack_sz = 0;
    int file_count = 0;
    off_t bytes_done = 0;
    int ret = -1;

    /* Push root */
    stack = realloc(stack, (stack_sz + 1) * sizeof(*stack));
    if (!stack) goto cleanup;
    stack[0].rel = strdup("");
    stack[0].visited = 0;
    stack_sz = 1;

    while (stack_sz > 0 && !g_interrupted) {
        struct stack_node *top = &stack[stack_sz - 1];

        char full[PATH_MAX * 2];
        int wrote = snprintf(full, sizeof(full), "%s/%s", base_in,
                             top->rel[0] ? top->rel : "");
        if (wrote < 0 || (size_t)wrote >= sizeof(full)) {
            fprintf(stderr, "Path too long, aborting: %s/%s\n", base_in, top->rel);
            goto cleanup;
        }

        if (top->visited == 0) {
            size_t cur_idx = stack_sz - 1;
            /* First visit – open directory and push all subdirectories */
            DIR *d = opendir(full);
            if (!d) { perror("opendir"); goto cleanup; }

            /* Collect names and sort */
            char **names = NULL;
            size_t names_count = 0, names_cap = 0;
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) continue;
                if (names_count >= names_cap) {
                    names_cap = names_cap ? names_cap * 2 : 32;
                    names = realloc(names, names_cap * sizeof(char *));
                    if (!names) { closedir(d); goto cleanup; }
                }
                names[names_count] = strdup(entry->d_name);
                if (!names[names_count]) { closedir(d); while (names_count > 0) free(names[--names_count]); free(names); goto cleanup; }
                names_count++;
            }
            closedir(d);

            if (names_count > 0) {
                qsort(names, names_count, sizeof(char *), dirent_comp);
                /* Cache the current directory's relative path before pushing:
                 * stack growth below realloc()s the node array and invalidates
                 * `top`, but the path string itself is allocated separately
                 * and remains valid. */
                const char *cur_rel = top->rel;
                /* Push subdirectories onto stack (reverse order so they are processed in sorted order) */
                for (size_t i = names_count; i > 0; i--) {
                    const char *name = names[i-1];
                    struct stat st;
                    char child_full[PATH_MAX * 2];
                    int w2 = snprintf(child_full, sizeof(child_full), "%s/%s", full, name);
                    if (w2 < 0 || (size_t)w2 >= sizeof(child_full)) continue;

                    char child_rel[PATH_MAX];
                    int w1 = cur_rel[0]
                             ? snprintf(child_rel, sizeof(child_rel), "%s/%s", cur_rel, name)
                             : snprintf(child_rel, sizeof(child_rel), "%s", name);
                    if (w1 < 0 || (size_t)w1 >= sizeof(child_rel)) continue;
                    /* Excluded directories are pruned with their whole subtree */
                    if (name_excluded(child_rel, excludes, n_excludes)) continue;

                    if (lstat(child_full, &st) < 0) continue;
                    if (S_ISLNK(st.st_mode)) continue;

                    if (S_ISDIR(st.st_mode)) {
                        /* Push directory to stack (visited=0) */
                        stack = realloc(stack, (stack_sz + 1) * sizeof(*stack));
                        if (!stack) { while (names_count > 0) free(names[--names_count]); free(names); goto cleanup; }
                        stack[stack_sz].rel = strdup(child_rel);
                        stack[stack_sz].visited = 0;
                        stack_sz++;
                    }
                }
                for (size_t i = 0; i < names_count; i++) free(names[i]);
                free(names);
            }

            /* top may be stale after realloc above – refresh it */
            top = &stack[cur_idx];

            /* Now mark current directory as visited and write its directory entry */
            {
                struct stat st;
                if (lstat(full, &st) < 0) goto cleanup;
                const char *dir_rel = top->rel[0] ? top->rel : ".";
                if (bundle_write_entry_header(w, dir_rel, 1, 0,
                                              st.st_mode & 0777, 0, 0) != 0)
                    goto cleanup;
                if (mf) {
                    uint8_t rec[1 + 2 + MAX_BUNDLE_PATH + 8 + 4 + 8 + 4];
                    int rn = encode_entry_header(rec, sizeof(rec), dir_rel, 1, 0,
                                                 st.st_mode & 0777, 0, 0);
                    if (rn < 0 || mbuf_append(mf, rec, (size_t)rn) != 0)
                        goto cleanup;
                }
            }
            top->visited = 1;
        } else {
            /* Second visit – process all regular files in this directory (they have not been pushed) */
            DIR *d = opendir(full);
            if (!d) { perror("opendir"); goto cleanup; }

            char **names = NULL;
            size_t names_count = 0, names_cap = 0;
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) continue;
                if (names_count >= names_cap) {
                    names_cap = names_cap ? names_cap * 2 : 32;
                    names = realloc(names, names_cap * sizeof(char *));
                    if (!names) { closedir(d); goto cleanup; }
                }
                names[names_count] = strdup(entry->d_name);
                if (!names[names_count]) { closedir(d); while (names_count > 0) free(names[--names_count]); free(names); goto cleanup; }
                names_count++;
            }
            closedir(d);

            if (names_count > 0) {
                qsort(names, names_count, sizeof(char *), dirent_comp);
                for (size_t i = 0; i < names_count; i++) {
                    const char *name = names[i];
                    struct stat st;
                    char child_full[PATH_MAX * 2];
                    int w2 = snprintf(child_full, sizeof(child_full), "%s/%s", full, name);
                    if (w2 < 0 || (size_t)w2 >= sizeof(child_full)) continue;
                    if (lstat(child_full, &st) < 0) continue;
                    if (S_ISDIR(st.st_mode)) continue;  /* already processed */
                    if (!S_ISREG(st.st_mode)) continue;

                    char child_rel[PATH_MAX];
                    int w1 = top->rel[0]
                             ? snprintf(child_rel, sizeof(child_rel), "%s/%s", top->rel, name)
                             : snprintf(child_rel, sizeof(child_rel), "%s", name);
                    if (w1 < 0 || (size_t)w1 >= sizeof(child_rel)) continue;
                    if (name_excluded(child_rel, excludes, n_excludes)) continue;

                    int fd = open(child_full, O_RDONLY);
                    if (fd < 0) { perror("open"); continue; }
                    if (bundle_write_entry_header(w, child_rel, 0, st.st_size,
                                                  st.st_mode & 0777,
                                                  st.st_mtim.tv_sec,
                                                  st.st_mtim.tv_nsec) != 0) {
                        close(fd);
                        continue;
                    }
                    if (mf) {
                        uint8_t rec[1 + 2 + MAX_BUNDLE_PATH + 8 + 4 + 8 + 4];
                        int rn = encode_entry_header(rec, sizeof(rec), child_rel, 0,
                                                     st.st_size,
                                                     st.st_mode & 0777,
                                                     st.st_mtim.tv_sec,
                                                     st.st_mtim.tv_nsec);
                        if (rn < 0 || mbuf_append(mf, rec, (size_t)rn) != 0) {
                            close(fd);
                            goto cleanup;
                        }
                    }
                    uint8_t *buf = malloc(CHUNK_SIZE);
                    ssize_t n;
                    while ((n = read_full(fd, buf, CHUNK_SIZE)) > 0) {
                        if (g_interrupted) { free(buf); close(fd); break; }
                        if (writer_push(w, buf, (size_t)n,
                                        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
                            free(buf); close(fd); goto cleanup;
                        }
                        bytes_done += n;
                        progress_update(bytes_done, -1);
                    }
                    free(buf);
                    close(fd);
                    file_count++;
                    if (g_interrupted) break;
                }
                for (size_t i = 0; i < names_count; i++) free(names[i]);
                free(names);
            }
            /* Pop this directory from stack */
            free(top->rel);
            stack_sz--;
        }
    }

    if (g_interrupted) goto cleanup;
    ret = file_count;   /* return number of files bundled */

cleanup:
    while (stack_sz > 0) {
        free(stack[stack_sz - 1].rel);
        stack_sz--;
    }
    free(stack);
    return ret;
}

static int encrypt_dir(const char *dirpath, const char *outpath,
                        const char *password, size_t pw_len,
                        const uint8_t *keyfile_data, size_t keyfile_len,
                        uint64_t opslimit, uint64_t memlimit,
                        int verbose, int force_overwrite,
                        char **excludes, size_t n_excludes) {
    /* Overwrite guard */
    if (!force_overwrite) {
        struct stat st_out;
        if (stat(outpath, &st_out) == 0) {
            fprintf(stderr, "Output '%s' already exists. Use -f to force overwrite.\n", outpath);
            return -1;
        }
    }

    int out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) { perror("open output"); return -1; }

    uint8_t dek[DEK_SIZE];
    sv7_header_t hdr; memset(&hdr, 0, sizeof(hdr));
    mbuf_t mf = {0};
    memcpy(hdr.magic, SV7_MAGIC, 4);
    hdr.version = SV7_VERSION;
    hdr.flags = FLAG_DIRECTORY;
    put_u64be(hdr.opslimit_be, opslimit);
    put_u64be(hdr.memlimit_be, memlimit);

    if (verbose) {
        fprintf(stderr, "opslimit=%llu memlimit=%llu flags=0x%02x\n",
                (unsigned long long)opslimit, (unsigned long long)memlimit,
                hdr.flags);
    }

    randombytes_buf(dek, DEK_SIZE);
    if (sodium_mlock(dek, DEK_SIZE) != 0) { close(out_fd); return -1; }
    if (fill_slot(&hdr.slots[0], dek, password, pw_len,
                  keyfile_data, keyfile_len, opslimit, (size_t)memlimit) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        sodium_munlock(dek, DEK_SIZE);
        close(out_fd); return -1;
    }

    sv_writer_t w; memset(&w, 0, sizeof(w));
    if (writer_init(&w, out_fd, dek, hdr.stream_header,
                    (const uint8_t *)&hdr, SV7_FIXED_LEN) != 0) {
        fprintf(stderr, "Stream init failed\n");
        sodium_munlock(dek, DEK_SIZE);
        close(out_fd); return -1;
    }

    if (write_full(out_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("write header");
        writer_free(&w);
        sodium_munlock(dek, DEK_SIZE);
        close(out_fd); return -1;
    }

    int file_count = bundle_add_tree(&w, dirpath, excludes, n_excludes, &mf);
    if (file_count < 0) {
        mbuf_free(&mf);
        writer_free(&w);
        sodium_munlock(dek, DEK_SIZE);
        close(out_fd);
        unlink(outpath);
        return -1;
    }

    /* Final empty TAG_FINAL block marks end of bundle. */
    uint8_t end_marker[1] = { ENTRY_END };
    int ret = writer_push(&w, end_marker, 1,
                          crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    if (ret != 0) {
        mbuf_free(&mf);
        writer_free(&w);
        sodium_munlock(dek, DEK_SIZE);
        close(out_fd);
        unlink(outpath);
        return -1;
    }

    /* Encrypted manifest trailer – bound to this header via AEAD AAD */
    if (write_manifest_trailer(out_fd, dek,
                               (const uint8_t *)&hdr, SV7_FIXED_LEN,
                               mf.data, mf.len) != 0) {
        fprintf(stderr, "Failed to write manifest trailer\n");
        mbuf_free(&mf);
        writer_free(&w);
        sodium_munlock(dek, DEK_SIZE);
        close(out_fd);
        unlink(outpath);
        return -1;
    }
    mbuf_free(&mf);

    if (fsync(out_fd) != 0) perror("fsync vault");

    if (verbose) fprintf(stderr, "Bundled %d files from %s -> %s\n",
                         file_count, dirpath, outpath);

    sodium_munlock(dek, DEK_SIZE);
    sodium_memzero(dek, DEK_SIZE);
    writer_free(&w);
    close(out_fd);
    return 0;
}

static int decrypt_dir_bundle(const char *inpath, const char *outdir,
                               const char *password, size_t pw_len,
                               const uint8_t *keyfile_data, size_t keyfile_len,
                               int verify_only, int verbose, int force_overwrite) {
    int in_fd = -1, ret = -1, files_done = 0;
    off_t bytes_seen = 0;
    vault_meta_t vm;
    if (strcmp(inpath, "-") == 0) {
        in_fd = STDIN_FILENO;
    } else {
        in_fd = open(inpath, O_RDONLY);
        if (in_fd < 0) { perror("open input"); return -1; }
    }

    if (vault_read_header(in_fd, &vm) != 0) {
        fprintf(stderr, "Invalid or unsupported vault bundle\n");
        goto cleanup_fd;
    }
    if (vault_unlock(&vm, password, pw_len, keyfile_data, keyfile_len) != 0) {
        fprintf(stderr, "[FAIL] Wrong password/keyfile, or header tampered\n");
        goto cleanup_fd;
    }

    sv_reader_t r;
    if (reader_init(&r, in_fd, vm.dek, vm.shdr, vm.aad, vm.aad_len) != 0) {
        fprintf(stderr, "Stream init failed\n");
        goto cleanup_fd;
    }

    char staging[PATH_MAX * 2] = {0};
    if (!verify_only) {
        /* Guard against existing output directory */
        struct stat st_out;
        if (stat(outdir, &st_out) == 0) {
            if (!force_overwrite) {
                fprintf(stderr, "Output directory '%s' already exists. Use -f to force overwrite.\n", outdir);
                reader_free(&r);
                goto cleanup_fd;
            }
            recursive_remove(outdir);
        }
        snprintf(staging, sizeof(staging), "%s.svtmp.XXXXXX", outdir);
        if (mkdtemp(staging) == NULL) {
            perror("mkdtemp staging");
            reader_free(&r);
            goto cleanup_fd;
        }
    }

    uint8_t *plain = sodium_malloc(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    int out_fd = -1;
    off_t remaining_in_file = 0;
    int in_file = 0;
    uint32_t saved_mode = 0;
    int64_t saved_msec = 0;
    int32_t saved_mnsec = 0;
    char cur_path[PATH_MAX * 2] = {0};

    for (;;) {
        if (g_interrupted) { fprintf(stderr, "\nInterrupted\n"); goto cleanup; }
        size_t plen; uint8_t tag;
        int rc = reader_pull(&r, plain, &plen, &tag);
        if (rc < 0) {
            fprintf(stderr, "[FAIL] Bundle authentication failed: tampered, "
                    "reordered, or truncated\n");
            goto cleanup;
        }
        if (rc == 0) { ret = 0; break; }
        bytes_seen += (off_t)plen;
        progress_update(bytes_seen, -1);

        if (remaining_in_file == 0) {
            if (plen < 1) goto cleanup;
            if (plain[0] == ENTRY_END) {
                ret = 0;
                if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
                continue;
            }
            if (plain[0] != ENTRY_FILE && plain[0] != ENTRY_DIR) goto cleanup;
            if (plen < 1 + 2) goto cleanup;
            uint16_t path_len = ((uint16_t)plain[1] << 8) | plain[2];
            /* Minimum length for files: tag(1)+pathlen(2)+path+size(8)+mode(4)+mtime(12) = 27+path */
            /* Minimum length for dirs:  tag(1)+pathlen(2)+path+mode(4) = 7+path */
            if (plain[0] == ENTRY_FILE && plen < (size_t)(1 + 2 + path_len + 8 + 4 + 8 + 4)) goto cleanup;
            if (plain[0] == ENTRY_DIR  && plen < (size_t)(1 + 2 + path_len + 4)) goto cleanup;

            char relpath[PATH_MAX];
            if (path_len >= sizeof(relpath)) goto cleanup;
            memcpy(relpath, plain + 3, path_len);
            relpath[path_len] = '\0';
            if (relpath[0] == '/' || strstr(relpath, "..") != NULL) {
                fprintf(stderr, "Refusing unsafe path in bundle: %s\n", relpath);
                goto cleanup;
            }

            if (plain[0] == ENTRY_DIR) {
                if (verify_only) {
                    files_done++;
                    continue;
                }
                int wrote = snprintf(cur_path, sizeof(cur_path), "%s/%s", staging, relpath);
                if (wrote < 0 || (size_t)wrote >= sizeof(cur_path)) {
                    fprintf(stderr, "Output path too long for directory: %s\n", relpath);
                    goto cleanup;
                }
                /* mkdir -p equivalent */
                char tmp[PATH_MAX * 2];
                strncpy(tmp, cur_path, sizeof(tmp)-1);
                tmp[sizeof(tmp)-1] = '\0';
                for (char *p = tmp + strlen(staging) + 1; *p; p++) {
                    if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
                }
                if (mkdir(cur_path, 0755) != 0 && errno != EEXIST) {
                    perror("mkdir"); goto cleanup;
                }
                /* Restore mode */
                uint32_t mode = ((uint32_t)plain[3 + path_len] << 24) |
                                ((uint32_t)plain[3 + path_len + 1] << 16) |
                                ((uint32_t)plain[3 + path_len + 2] << 8) |
                                (uint32_t)plain[3 + path_len + 3];
                if (chmod(cur_path, mode) != 0) {
                    perror("chmod dir"); /* non-fatal */
                }
                files_done++;
                continue;
            }

            /* ENTRY_FILE */
            uint64_t fsize = get_u64be(plain + 3 + path_len);
            remaining_in_file = (off_t)fsize;
            in_file = 1;
            saved_mode = ((uint32_t)plain[3 + path_len + 8] << 24) |
                         ((uint32_t)plain[3 + path_len + 8 + 1] << 16) |
                         ((uint32_t)plain[3 + path_len + 8 + 2] << 8) |
                         (uint32_t)plain[3 + path_len + 8 + 3];
            saved_msec = (int64_t)get_u64be(plain + 3 + path_len + 12);
            saved_mnsec = get_i32be(plain + 3 + path_len + 20);

            if (verify_only) {
                files_done++;
                if (remaining_in_file == 0) in_file = 0;
            } else {
                int wrote = snprintf(cur_path, sizeof(cur_path), "%s/%s",
                                     staging, relpath);
                if (wrote < 0 || (size_t)wrote >= sizeof(cur_path)) {
                    fprintf(stderr, "Output path too long, skipping: %s\n", relpath);
                    goto cleanup;
                }
                /* mkdir -p for parent */
                char tmp[PATH_MAX * 2];
                strncpy(tmp, cur_path, sizeof(tmp)-1);
                tmp[sizeof(tmp)-1] = '\0';
                for (char *p = tmp + strlen(staging) + 1; *p; p++) {
                    if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
                }
                out_fd = open(cur_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (out_fd < 0) { perror("open output entry"); goto cleanup; }
                if (remaining_in_file == 0) {
                    close(out_fd); out_fd = -1;
                    fchmodat(AT_FDCWD, cur_path, saved_mode, 0);
                    struct timespec times[2] = { {0, UTIME_OMIT}, {saved_msec, saved_mnsec} };
                    utimensat(AT_FDCWD, cur_path, times, 0);
                    in_file = 0; files_done++;
                }
            }
        } else {
            size_t to_write = plen;
            if ((off_t)to_write > remaining_in_file) to_write = (size_t)remaining_in_file;
            if (!verify_only) {
                if (write_full(out_fd, plain, to_write) != (ssize_t)to_write) {
                    perror("write"); goto cleanup;
                }
            }
            remaining_in_file -= to_write;
            if (remaining_in_file == 0) {
                if (!verify_only && out_fd >= 0) {
                    close(out_fd);
                    out_fd = -1;
                    fchmodat(AT_FDCWD, cur_path, saved_mode, 0);
                    struct timespec times[2] = { {0, UTIME_OMIT}, {saved_msec, saved_mnsec} };
                    utimensat(AT_FDCWD, cur_path, times, 0);
                }
                in_file = 0;
                files_done++;
            }
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) { ret = 0; break; }
    }

    if (ret == 0 && in_file) ret = -1;

cleanup:
    if (out_fd >= 0) close(out_fd);
    if (plain) sodium_free(plain);
    vault_wipe_dek(&vm);
    reader_free(&r);

cleanup_fd:
    if (in_fd >= 0 && in_fd != STDIN_FILENO) close(in_fd);

    if (verify_only) {
        if (verbose) fprintf(stderr, "%s %d files OK\n",
                             ret == 0 ? "Verified" : "FAILED to verify", files_done);
        return ret;
    }

    if (ret == 0) {
        if (rename(staging, outdir) != 0) {
            perror("rename staging to outdir");
            recursive_remove(staging);
            return -1;
        }
        if (verbose) fprintf(stderr, "Extracted %d files to %s\n", files_done, outdir);
    } else {
        recursive_remove(staging);
    }
    return ret;
}

/* ==========================================================================
 * list – show vault contents from the encrypted manifest trailer.
 *
 * Payload frames are walked (skipped via lseek on regular files, read and
 * discarded on pipes) but NOT authenticated; the manifest itself is fully
 * authenticated and AEAD-bound to the header. Use `verify` for full
 * integrity checking. Vaults written before this feature have no trailer
 * and are reported as such.
 * ========================================================================== */

static void sanitize_print(char *s) {
    for (; *s; s++)
        if (!isprint((unsigned char)*s)) *s = '?';
}

static int cmd_list(const char *inpath, const char *password, size_t pw_len,
                    const uint8_t *keyfile_data, size_t keyfile_len,
                    int verbose) {
    int in_fd = -1, ret = -1;
    vault_meta_t vm;

    int use_stdin = (strcmp(inpath, "-") == 0);
    if (use_stdin) {
        in_fd = STDIN_FILENO;
    } else {
        in_fd = open(inpath, O_RDONLY);
        if (in_fd < 0) { perror("open input"); return -1; }
    }

    if (vault_read_header(in_fd, &vm) != 0) {
        fprintf(stderr, "Invalid or unsupported vault\n");
        goto cleanup_fd;
    }
    if (vault_unlock(&vm, password, pw_len, keyfile_data, keyfile_len) != 0) {
        fprintf(stderr, "[FAIL] Wrong password/keyfile, or header tampered\n");
        goto cleanup_fd;
    }

    int seekable = (lseek(in_fd, 0, SEEK_CUR) >= 0);
    off_t bytes_seen = (off_t)vm.raw_len;
    uint8_t *discard = NULL;
    if (!seekable) {
        discard = malloc(256 * 1024);
        if (!discard) { perror("malloc"); goto cleanup_dek; }
    }

    for (;;) {
        if (g_interrupted) { fprintf(stderr, "\nInterrupted\n"); break; }

        uint8_t len4[4];
        ssize_t got = read_full(in_fd, len4, 4);
        if (got == 0) {
            fprintf(stderr, "Note: no manifest in this vault "
                            "(written by an older version)\n");
            ret = 0;
            break;
        }
        if (got != 4) { fprintf(stderr, "[FAIL] Truncated stream\n"); break; }
        bytes_seen += 4;

        /* ---- manifest trailer? ---- */
        if (memcmp(len4, SV_MANIFEST_MAGIC, 4) == 0) {
            uint8_t ver1, nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            uint8_t ml8[8];
            if (read_full(in_fd, &ver1, 1) != 1 || ver1 != SV_MANIFEST_VERSION ||
                read_full(in_fd, nonce, sizeof(nonce)) != (ssize_t)sizeof(nonce) ||
                read_full(in_fd, ml8, sizeof(ml8)) != (ssize_t)sizeof(ml8)) {
                fprintf(stderr, "[FAIL] Malformed manifest trailer\n");
                break;
            }
            uint64_t mlen = get_u64be(ml8);
            if (mlen < crypto_aead_xchacha20poly1305_ietf_ABYTES ||
                mlen > SV_MANIFEST_MAX_CT) {
                fprintf(stderr, "[FAIL] Implausible manifest length\n");
                break;
            }
            unsigned char mkey[crypto_kdf_KEYBYTES];
            unsigned char *ct = malloc((size_t)mlen);
            unsigned char *pt = malloc((size_t)mlen);
            if (!ct || !pt ||
                crypto_kdf_derive_from_key(mkey, sizeof(mkey), 1, "SVmanif1", vm.dek) != 0 ||
                read_full(in_fd, ct, (size_t)mlen) != (ssize_t)mlen) {
                fprintf(stderr, "[FAIL] Manifest read failed\n");
                sodium_memzero(mkey, sizeof(mkey));
                free(ct); free(pt);
                break;
            }
            unsigned long long plen = 0;
            int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt, &plen, NULL, ct, mlen,
                vm.aad, vm.aad_len, nonce, mkey);
            sodium_memzero(mkey, sizeof(mkey));
            sodium_memzero(ct, (size_t)mlen);
            free(ct);
            if (rc != 0) {
                fprintf(stderr, "[FAIL] Manifest authentication failed\n");
                free(pt);
                break;
            }

            printf("%-4s %14s %6s %17s %s\n",
                   "TYPE", "SIZE", "MODE", "MTIME", "PATH");
            size_t pos = 0;
            int nfiles = 0, ndirs = 0;
            off_t total = 0;
            while (pos + 3 <= plen) {
                uint8_t etag = pt[pos];
                uint16_t pl16 = ((uint16_t)pt[pos + 1] << 8) | pt[pos + 2];
                if ((etag != ENTRY_FILE && etag != ENTRY_DIR) ||
                    pos + 3u + pl16 > plen)
                    break;
                char path[MAX_BUNDLE_PATH + 1];
                memcpy(path, pt + pos + 3, pl16);
                path[pl16] = '\0';
                sanitize_print(path);
                const char *shown = path[0] ? path : (etag == ENTRY_FILE ? "-" : ".");
                pos += 3u + pl16;

                char datebuf[32] = "-";
                if (etag == ENTRY_FILE) {
                    if (pos + 24 > plen) break;
                    uint64_t fsz = get_u64be(pt + pos);
                    uint32_t fmode = ((uint32_t)pt[pos + 8] << 24) |
                                     ((uint32_t)pt[pos + 9] << 16) |
                                     ((uint32_t)pt[pos + 10] << 8) |
                                     (uint32_t)pt[pos + 11];
                    int64_t msec = (int64_t)get_u64be(pt + pos + 12);
                    pos += 24;
                    time_t ttv = (time_t)msec;
                    struct tm tmv;
                    if (localtime_r(&ttv, &tmv))
                        strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %H:%M", &tmv);
                    printf("%-4s %14llu 0%04o %17s %s\n", "f",
                           (unsigned long long)fsz, fmode & 0777, datebuf, shown);
                    nfiles++;
                    total += (off_t)fsz;
                } else {
                    if (pos + 4 > plen) break;
                    uint32_t dmode = ((uint32_t)pt[pos] << 24) |
                                     ((uint32_t)pt[pos + 1] << 16) |
                                     ((uint32_t)pt[pos + 2] << 8) |
                                     (uint32_t)pt[pos + 3];
                    pos += 4;
                    printf("%-4s %14s 0%04o %17s %s\n", "d", "-", dmode & 0777, "-", shown);
                    ndirs++;
                }
            }
            sodium_memzero(pt, (size_t)plen);
            free(pt);
            fflush(stdout);
            fprintf(stderr, "%d files, %d dirs, %lld bytes total\n",
                    nfiles, ndirs, (long long)total);
            ret = 0;
            break;
        }

        /* ---- payload frame: skip it ---- */
        uint32_t clen = ((uint32_t)len4[0] << 24) | ((uint32_t)len4[1] << 16) |
                        ((uint32_t)len4[2] << 8) | (uint32_t)len4[3];
        if (clen < crypto_secretstream_xchacha20poly1305_ABYTES ||
            clen > CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES) {
            fprintf(stderr, "[FAIL] Corrupt frame length\n");
            break;
        }
        if (seekable && lseek(in_fd, (off_t)clen, SEEK_CUR) < 0) {
            fprintf(stderr, "[FAIL] Seek failed\n");
            break;
        }
        if (!seekable) {
            off_t left = (off_t)clen;
            while (left > 0) {
                size_t want = left > 256 * 1024 ? 256 * 1024 : (size_t)left;
                ssize_t r = read_full(in_fd, discard, want);
                if (r <= 0) { left = -1; break; }
                left -= r;
            }
            if (left != 0) { fprintf(stderr, "[FAIL] Truncated stream\n"); break; }
        }
        bytes_seen += (off_t)clen;
        progress_update(bytes_seen, -1);
    }

    if (ret == 0 && verbose)
        fprintf(stderr, "Walked %lld bytes of frames\n", (long long)bytes_seen);
    progress_finish();
    free(discard);

cleanup_dek:
    vault_wipe_dek(&vm);

cleanup_fd:
    if (in_fd >= 0 && in_fd != STDIN_FILENO) close(in_fd);
    return ret;
}

/* ==========================================================================
 * Key-slot management (v7): addkey / passwd / delkey / rekey
 * ========================================================================== */

#define PASS_BUF_CAP 4096

/* Read a NUL-terminated password from fd into a locked buffer (strips CR/LF). */
static char *read_pass_from_fd(int fd) {
    char *buf = sodium_malloc(PASS_BUF_CAP);
    if (!buf) return NULL;
    if (sodium_mlock(buf, PASS_BUF_CAP) != 0)
        fprintf(stderr, "Warning: could not lock password buffer\n");
    size_t off = 0;
    ssize_t r = 0;
    while (off < PASS_BUF_CAP - 1 &&
           (r = read_full(fd, buf + off, PASS_BUF_CAP - 1 - off)) > 0)
        off += (size_t)r;
    if (r < 0 ||
        (off == PASS_BUF_CAP - 1 && read_full(fd, buf + off, 1) > 0)) {
        fprintf(stderr, "Error: password read failed or too long\n");
        sodium_memzero(buf, PASS_BUF_CAP);
        sodium_free(buf);
        return NULL;
    }
    if (off > 0 && buf[off - 1] == '\n') off--;
    if (off > 0 && buf[off - 1] == '\r') off--;
    buf[off] = '\0';
    return buf;
}

/* Open a vault for an in-place slot operation. */
static int slot_op_open(const char *path, int *out_fd, vault_meta_t *vm) {
    memset(vm, 0, sizeof(*vm));
    int fd = open(path, O_RDWR);
    if (fd < 0) { perror("open vault"); return -1; }
    if (vault_read_header(fd, vm) != 0) {
        fprintf(stderr, "Invalid or unsupported vault\n");
        close(fd);
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int vault_rewrite_header(int fd, const vault_meta_t *vm) {
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    if (write_full(fd, vm->raw, vm->raw_len) != (ssize_t)vm->raw_len) return -1;
    return fsync(fd);
}

static void wipe_pass_buf(char *buf) {
    if (!buf) return;
    sodium_munlock(buf, PASS_BUF_CAP);
    sodium_memzero(buf, PASS_BUF_CAP);
    sodium_free(buf);
}

/* Load a keyfile into a locked buffer. */
static int load_keyfile(const char *path, size_t max_size,
                        uint8_t **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    FILE *kf = fopen(path, "rb");
    if (!kf) { perror("keyfile open"); return -1; }
    struct stat kst;
    if (fstat(fileno(kf), &kst) < 0 || (size_t)kst.st_size > max_size) {
        fprintf(stderr, "Keyfile invalid or too large (max %zu bytes)\n", max_size);
        fclose(kf);
        return -1;
    }
    size_t n = (size_t)kst.st_size;
    uint8_t *d = sodium_malloc(n > 0 ? n : 1);
    if (!d) { fclose(kf); return -1; }
    sodium_mlock(d, n > 0 ? n : 1);
    rewind(kf);
    if (n > 0 && fread(d, 1, n, kf) != n) {
        fclose(kf);
        sodium_munlock(d, n);
        sodium_free(d);
        return -1;
    }
    fclose(kf);
    *out = d;
    *out_len = n;
    return 0;
}

static void free_keyfile(uint8_t *d, size_t n) {
    if (!d) return;
    sodium_munlock(d, n > 0 ? n : 1);
    sodium_memzero(d, n > 0 ? n : 1);
    sodium_free(d);
}

static int require_v7(const vault_meta_t *vm) {
    if (vm->version < 7) {
        fprintf(stderr, "Vault is v%u – run 'rekey' to migrate it to v7 first\n",
                vm->version);
        return -1;
    }
    return 0;
}

static int cmd_addkey(const char *vault,
                      const char *pw, size_t pw_len, const uint8_t *kf, size_t kf_len,
                      const char *npw, size_t npw_len, const uint8_t *nkf, size_t nkf_len,
                      int allow_empty) {
    int fd = -1, ret = -1;
    vault_meta_t vm;
    if (slot_op_open(vault, &fd, &vm) != 0) return -1;
    if (require_v7(&vm) != 0) goto out;
    if (vault_unlock(&vm, pw, pw_len, kf, kf_len) != 0) {
        fprintf(stderr, "[FAIL] Wrong existing password/keyfile\n");
        goto out;
    }

    /* policy: new credential must not be empty unless explicitly allowed */
    if (npw_len == 0 && nkf_len == 0 && !allow_empty) {
        fprintf(stderr, "Error: empty new password with no keyfile; "
                        "pass --allow-empty-pass to override\n");
        goto out;
    }

    int free_idx = -1;
    for (int i = 0; i < SV7_MAX_SLOTS; i++) {
        if (vm.raw[SV7_FIXED_LEN + i * SV7_SLOT_SIZE] == SV_SLOT_EMPTY) {
            free_idx = i;
            break;
        }
    }
    if (free_idx < 0) {
        fprintf(stderr, "Error: no free key slots (%d/%d used)\n",
                SV7_MAX_SLOTS, SV7_MAX_SLOTS);
        goto out;
    }

    sv7_slot_t *slot = (sv7_slot_t *)(vm.raw + SV7_FIXED_LEN + free_idx * SV7_SLOT_SIZE);
    if (fill_slot(slot, vm.dek, npw, npw_len, nkf, nkf_len,
                  vm.opslimit, (size_t)vm.memlimit) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        goto out;
    }
    vault_wipe_dek(&vm);

    if (vault_rewrite_header(fd, &vm) != 0) { perror("rewrite header"); goto out; }
    fprintf(stderr, "Added key slot %d\n", free_idx);
    ret = 0;

out:
    if (fd >= 0) close(fd);
    return ret;
}

static int cmd_passwd(const char *vault,
                      const char *pw, size_t pw_len, const uint8_t *kf, size_t kf_len,
                      const char *npw, size_t npw_len, const uint8_t *nkf, size_t nkf_len,
                      int allow_empty) {
    int fd = -1, ret = -1, matched = -1;
    vault_meta_t vm;
    if (slot_op_open(vault, &fd, &vm) != 0) return -1;
    if (require_v7(&vm) != 0) goto out;
    if (vault_unlock_ex(&vm, pw, pw_len, kf, kf_len, &matched) != 0 || matched < 0) {
        fprintf(stderr, "[FAIL] Wrong existing password/keyfile\n");
        goto out;
    }

    if (npw_len == 0 && nkf_len == 0 && !allow_empty) {
        fprintf(stderr, "Error: empty new password with no keyfile; "
                        "pass --allow-empty-pass to override\n");
        goto out;
    }

    sv7_slot_t *slot = (sv7_slot_t *)(vm.raw + SV7_FIXED_LEN + matched * SV7_SLOT_SIZE);
    if (fill_slot(slot, vm.dek, npw, npw_len, nkf, nkf_len,
                  vm.opslimit, (size_t)vm.memlimit) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        goto out;
    }
    vault_wipe_dek(&vm);
    if (vault_rewrite_header(fd, &vm) != 0) { perror("rewrite header"); goto out; }
    fprintf(stderr, "Rotated key slot %d\n", matched);
    ret = 0;

out:
    if (fd >= 0) close(fd);
    return ret;
}

static int cmd_delkey(const char *vault, long target_slot,
                      const char *pw, size_t pw_len, const uint8_t *kf, size_t kf_len) {
    int fd = -1, ret = -1;
    vault_meta_t vm;
    if (target_slot < 0 || target_slot >= SV7_MAX_SLOTS) {
        fprintf(stderr, "Error: --slot must be in [0..%d]\n", SV7_MAX_SLOTS - 1);
        return -1;
    }
    if (slot_op_open(vault, &fd, &vm) != 0) return -1;
    if (require_v7(&vm) != 0) goto out;
    if (vault_unlock(&vm, pw, pw_len, kf, kf_len) != 0) {
        fprintf(stderr, "[FAIL] Wrong existing password/keyfile\n");
        goto out;
    }
    vault_wipe_dek(&vm);

    sv7_slot_t *slot = (sv7_slot_t *)(vm.raw + SV7_FIXED_LEN + target_slot * SV7_SLOT_SIZE);
    if (slot->type == SV_SLOT_EMPTY) {
        fprintf(stderr, "Error: slot %ld is already empty\n", target_slot);
        goto out;
    }

    unsigned active = 0;
    for (int i = 0; i < SV7_MAX_SLOTS; i++)
        if (vm.raw[SV7_FIXED_LEN + i * SV7_SLOT_SIZE] != SV_SLOT_EMPTY)
            active++;
    if (active <= 1) {
        fprintf(stderr, "Error: refusing to remove the last key slot\n");
        goto out;
    }

    sodium_memzero(slot, sizeof(*slot));
    slot->type = SV_SLOT_EMPTY;

    if (vault_rewrite_header(fd, &vm) != 0) { perror("rewrite header"); goto out; }
    fprintf(stderr, "Removed key slot %ld\n", target_slot);
    ret = 0;

out:
    if (fd >= 0) close(fd);
    return ret;
}

/* Migrate a v6 vault to a single-slot v7 vault (full re-encryption). */
static int cmd_rekey(const char *src, const char *dst_opt,
                     const char *pw, size_t pw_len, const uint8_t *kf, size_t kf_len,
                     int verbose) {
    size_t slen = strlen(src);
    char *dst = NULL;
    const char *suffix = ".v7.vault";
    if (dst_opt) {
        dst = strdup(dst_opt);
    } else if (slen > 6 && strcmp(src + slen - 6, ".vault") == 0) {
        size_t bl = slen - 6;
        dst = malloc(bl + strlen(suffix) + 1);
        if (dst) { memcpy(dst, src, bl); dst[bl] = '\0'; strcat(dst, suffix); }
    } else {
        if (asprintf(&dst, "%s%s", src, suffix) < 0) dst = NULL;
    }
    if (!dst) { perror("alloc"); return -1; }

    struct stat st_out;
    if (stat(dst, &st_out) == 0) {
        fprintf(stderr, "Output '%s' already exists. Use -o to choose another.\n", dst);
        free(dst);
        return -1;
    }

    char *tmp = NULL;
    if (asprintf(&tmp, "%s.rekey.tmp", dst) < 0 || !tmp) { free(dst); return -1; }

    fprintf(stderr, "Decrypting %s ...\n", src);
    int rc = decrypt_file(src, tmp, pw, pw_len, kf, kf_len, 0, verbose, 1);
    if (rc != 0) {
        fprintf(stderr, "Rekey aborted (decryption failed)\n");
        unlink(tmp); free(tmp); free(dst);
        return -1;
    }

    fprintf(stderr, "Re-encrypting as v7 -> %s\n", dst);
    rc = encrypt_file(tmp, dst, pw, pw_len, kf, kf_len,
                      0, DEFAULT_OPSLIMIT, DEFAULT_MEMLIMIT, 0, verbose, 1);
    secure_delete(tmp, 0);
    unlink(tmp);
    free(tmp);

    if (rc != 0) {
        fprintf(stderr, "Rekey failed during encryption\n");
        unlink(dst);
        free(dst);
        return -1;
    }
    fprintf(stderr, "Migration complete. Verify '%s', then remove the old "
                    "vault when satisfied.\n", dst);
    free(dst);
    return 0;
}

/* ==========================================================================
 * CLI helpers
 * ========================================================================== */


/* ----- keygen: generate a random symmetric keyfile ----- */
static int cmd_keygen(const char *outpath, uint64_t size_k, int force, int verbose) {
    if (!force) {
        struct stat st_out;
        if (stat(outpath, &st_out) == 0) {
            fprintf(stderr, "Output '%s' already exists. Use -f to force overwrite.\n", outpath);
            return -1;
        }
    }
    int fd = open(outpath, O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL), 0600);
    if (fd < 0) { perror("open keyfile"); return -1; }

    uint8_t *buf = malloc((size_t)size_k);
    if (!buf) { perror("malloc"); close(fd); return -1; }
    randombytes_buf(buf, (size_t)size_k);

    if (write_full(fd, buf, (size_t)size_k) != (ssize_t)size_k) {
        perror("write keyfile");
        sodium_memzero(buf, (size_t)size_k);
        free(buf);
        close(fd);
        unlink(outpath);
        return -1;
    }
    fsync(fd);
    close(fd);

    unsigned char dg[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(dg, buf, (size_t)size_k);
    if (verbose) {
        fprintf(stderr, "Generated %llu-byte keyfile '%s', fingerprint ",
                (unsigned long long)size_k, outpath);
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", dg[i]);
        fputc('\n', stderr);
    }
    sodium_memzero(buf, (size_t)size_k);
    free(buf);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "ShadowVault v6.1 – Envelope + XChaCha20-Poly1305 Secretstream\n\n"
        "Usage:\n"
        "  %s enc <file|dir>    [options]\n"
        "  %s dec <vault>       [options]\n"
        "  %s verify <vault>    [options]\n"
        "  %s list <vault>              show contents from encrypted manifest\n"
        "  %s keygen [-o file]  [options]   generate random keyfile\n"
        "  %s addkey <vault>    [options]   add another password/keyfile slot\n"
        "  %s passwd <vault>    [options]   rotate the slot you unlock with\n"
        "  %s delkey --slot N <vault>       remove a key slot\n"
        "  %s rekey <old.vault> [options]   migrate v6 vault to multi-slot v7\n\n"
        "Options:\n"
        "  -p, --password <pw>       Password (\"-\" to prompt)\n"
        "      --pass-fd <n>         Read password from file descriptor n\n"
        "  -k, --keyfile <file>      Key file, combined with password\n"
        "  -o, --output <path>       Output path (\"-\" for stdout)\n"
        "  -c, --compress            Enable zlib compression (file mode only; persisted)\n"
        "  -s, --shred               Securely overwrite + delete original after encrypting\n"
        "  -f, --force               Force overwrite of existing output\n"
        "  -P, --progress            Show progress on stderr\n"
        "  -t, --opslimit <n>        Argon2id opslimit (encrypt only)\n"
        "  -m, --memlimit <n>        Argon2id memlimit in bytes (encrypt only)\n"
        "  -v, --verbose             Verbose output\n"
        "  -h, --help                This help\n"
        "      --exclude <glob>      Skip matching entries in dir mode (repeatable;\n"
        "                            matches relative path or basename, e.g. *.tmp)\n"
        "      --keyfile-max-size <n>  Max keyfile size (default 4 MiB)\n"
        "      --allow-empty-pass    Permit empty password with no keyfile\n"
        "      --size <n>            keygen: keyfile size in bytes (16..4194304)\n"
        "      --new-password <pw>   addkey/passwd: new password (\"-\" to prompt)\n"
        "      --new-pass-fd <n>     addkey/passwd: read new password from fd n\n"
        "      --new-keyfile <file>  addkey/passwd: keyfile for the new slot\n"
        "      --slot <n>            delkey: slot index to remove (0..7)\n\n"
        "Argon2id cost is stored in the file header – no need to repeat at decrypt.\n"
        "Directory mode bundles the whole tree into one authenticated stream.\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    const char *action = NULL, *target = NULL;
    char *password = NULL;
    int ret = 1;
    const char *keyfile_path = NULL, *output = NULL;
    int compress = 0, verbose = 0, shred = 0, verify_only = 0, force_overwrite = 0;
    int progress = 0, allow_empty_pass = 0, pass_fd = -1;
    int new_pass_fd = -1;
    long target_slot = -1;
    char *new_password = NULL;
    const char *new_keyfile_path = NULL;
    uint64_t opslimit = DEFAULT_OPSLIMIT;
    uint64_t memlimit = DEFAULT_MEMLIMIT;
    uint64_t keygen_size = 32;
    size_t keyfile_max_size = DEFAULT_KEYFILE_MAX_SIZE;
    char **excludes = NULL;
    size_t n_excludes = 0, cap_excludes = 0;

    static struct option long_opts[] = {
        {"password",   required_argument, 0, 'p'},
        {"keyfile",    required_argument, 0, 'k'},
        {"output",     required_argument, 0, 'o'},
        {"compress",   no_argument,       0, 'c'},
        {"shred",      no_argument,       0, 's'},
        {"force",      no_argument,       0, 'f'},
        {"progress",   no_argument,       0, 'P'},
        {"opslimit",   required_argument, 0, 't'},
        {"memlimit",   required_argument, 0, 'm'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {"keyfile-max-size", required_argument, 0, 1000},   /* long-only */
        {"allow-empty-pass", no_argument,       0, 1001},
        {"pass-fd",          required_argument, 0, 1002},
        {"size",             required_argument, 0, 1003},
        {"exclude",          required_argument, 0, 1004},
        {"new-password",     required_argument, 0, 1005},
        {"new-pass-fd",      required_argument, 0, 1006},
        {"new-keyfile",      required_argument, 0, 1007},
        {"slot",             required_argument, 0, 1008},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:k:o:cfsPt:m:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': password = optarg; break;
        case 'k': keyfile_path = optarg; break;
        case 'o': output = optarg; break;
        case 'c': compress = 1; break;
        case 's': shred = 1; break;
        case 'f': force_overwrite = 1; break;
        case 'P': progress = 1; break;
        case 't':
            if (parse_u64_arg(optarg, "opslimit",
                              crypto_pwhash_OPSLIMIT_MIN,
                              crypto_pwhash_OPSLIMIT_MAX, &opslimit) != 0) {
                usage(argv[0]); return 1;
            }
            break;
        case 'm': {
            uint64_t mem = 0;
            if (parse_u64_arg(optarg, "memlimit",
                              crypto_pwhash_MEMLIMIT_MIN,
                              crypto_pwhash_MEMLIMIT_MAX, &mem) != 0) {
                usage(argv[0]); return 1;
            }
            memlimit = mem;
            break;
        }
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        case 1000: {
            uint64_t kmax = 0;
            if (parse_u64_arg(optarg, "keyfile-max-size", 1,
                              (uint64_t)SIZE_MAX, &kmax) != 0) {
                usage(argv[0]); return 1;
            }
            keyfile_max_size = (size_t)kmax;
            break;
        }
        case 1001: allow_empty_pass = 1; break;
        case 1002: {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (!optarg[0] || *end != '\0' || v < 0 || v > INT_MAX) {
                fprintf(stderr, "Error: invalid pass-fd '%s'\n", optarg);
                return 1;
            }
            pass_fd = (int)v;
            break;
        }
        case 1003:
            if (parse_u64_arg(optarg, "size", 16,
                              DEFAULT_KEYFILE_MAX_SIZE, &keygen_size) != 0) {
                usage(argv[0]); return 1;
            }
            break;
        case 1004: {
            if (n_excludes >= cap_excludes) {
                cap_excludes = cap_excludes ? cap_excludes * 2 : 8;
                excludes = realloc(excludes, cap_excludes * sizeof(char *));
                if (!excludes) { perror("realloc"); return 1; }
            }
            excludes[n_excludes] = strdup(optarg);
            if (!excludes[n_excludes]) { perror("strdup"); return 1; }
            n_excludes++;
            break;
        }
        case 1005: new_password = optarg; break;
        case 1006: {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (!optarg[0] || *end != '\0' || v < 0 || v > INT_MAX) {
                fprintf(stderr, "Error: invalid new-pass-fd '%s'\n", optarg);
                return 1;
            }
            new_pass_fd = (int)v;
            break;
        }
        case 1007: new_keyfile_path = optarg; break;
        case 1008: {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (!optarg[0] || *end != '\0' || v < 0) {
                fprintf(stderr, "Error: invalid slot '%s'\n", optarg);
                return 1;
            }
            target_slot = v;
            break;
        }
        default: usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: missing action and target\n");
        usage(argv[0]);
        return 1;
    }
    action = argv[optind++];
    g_progress = progress;

    /* keygen needs no target and no password handling */
    if (strcmp(action, "keygen") == 0) {
        const char *kout = output ? output : "shadowvault.key";
        int kret = cmd_keygen(kout, keygen_size, force_overwrite, verbose || progress);
        for (size_t i = 0; i < n_excludes; i++) free(excludes[i]);
        free(excludes);
        fprintf(stderr, kret == 0 ? "[+] Success\n" : "[-] Operation failed\n");
        return kret == 0 ? 0 : 1;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: missing target\n");
        usage(argv[0]);
        return 1;
    }
    target = argv[optind];

    /* --pass-fd: read the password from a file descriptor (kept out of argv) */
    char *ext_pass = NULL;
    if (pass_fd >= 0) {
        if (password && strcmp(password, "-") != 0) {
            fprintf(stderr, "Error: use either -p or --pass-fd, not both\n");
            return 1;
        }
        ext_pass = sodium_malloc(PASS_FD_MAX);
        if (!ext_pass) { perror("sodium_malloc"); return 1; }
        if (sodium_mlock(ext_pass, PASS_FD_MAX) != 0)
            fprintf(stderr, "Warning: could not lock pass-fd buffer\n");
        size_t off = 0;
        ssize_t r = 0;
        while (off < PASS_FD_MAX - 1 &&
               (r = read_full(pass_fd, ext_pass + off, PASS_FD_MAX - 1 - off)) > 0)
            off += (size_t)r;
        if (r < 0) {
            perror("read pass-fd");
            sodium_munlock(ext_pass, PASS_FD_MAX);
            sodium_memzero(ext_pass, PASS_FD_MAX);
            sodium_free(ext_pass);
            return 1;
        }
        if (off == PASS_FD_MAX - 1) {
            char probe;
            if (read_full(pass_fd, &probe, 1) > 0) {
                fprintf(stderr, "Error: password from pass-fd exceeds %d bytes\n",
                        PASS_FD_MAX - 1);
                sodium_munlock(ext_pass, PASS_FD_MAX);
                sodium_memzero(ext_pass, PASS_FD_MAX);
                sodium_free(ext_pass);
                return 1;
            }
        }
        if (off > 0 && ext_pass[off - 1] == '\n') off--;
        if (off > 0 && ext_pass[off - 1] == '\r') off--;
        ext_pass[off] = '\0';
        password = ext_pass;
    }

    char pw_buf[256] = {0};
    /* Lock BEFORE any secret is written so the page cannot hit swap mid-read */
    if (sodium_mlock(pw_buf, sizeof(pw_buf)) != 0)
        fprintf(stderr, "Warning: could not lock password buffer (swap exposure possible)\n");
    if (!password || strcmp(password, "-") == 0) {
        fprintf(stderr, "Password: ");
        fflush(stderr);
        if (!fgets(pw_buf, sizeof(pw_buf), stdin)) {
            fprintf(stderr, "Failed to read password\n");
            return 1;
        }
        pw_buf[strcspn(pw_buf, "\n")] = '\0';
        password = pw_buf;
    }
    size_t pw_len = strlen(password);

    uint8_t *keyfile_data = NULL;
    size_t keyfile_len = 0;
    if (keyfile_path) {
        FILE *kf = fopen(keyfile_path, "rb");
        if (!kf) { perror("keyfile open"); return 1; }
        struct stat kst;
        if (fstat(fileno(kf), &kst) < 0 || (size_t)kst.st_size > keyfile_max_size) {
            fprintf(stderr, "Keyfile invalid or too large (max %zu bytes)\n", keyfile_max_size);
            fclose(kf); return 1;
        }
        keyfile_len = (size_t)kst.st_size;
        keyfile_data = sodium_malloc(keyfile_len > 0 ? keyfile_len : 1);
        if (!keyfile_data) { fclose(kf); return 1; }
        sodium_mlock(keyfile_data, keyfile_len > 0 ? keyfile_len : 1);
        rewind(kf);
        if (fread(keyfile_data, 1, keyfile_len, kf) != keyfile_len) {
            fclose(kf);
            sodium_munlock(keyfile_data, keyfile_len);
            sodium_free(keyfile_data);
            return 1;
        }
        fclose(kf);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* ---- key-slot management actions (v7) ---- */
    if (strcmp(action, "addkey") == 0 || strcmp(action, "passwd") == 0 ||
        strcmp(action, "delkey") == 0 || strcmp(action, "rekey") == 0) {
        int is_rekey = (strcmp(action, "rekey") == 0);
        int is_del   = (strcmp(action, "delkey") == 0);

        if (is_del) {
            if (target_slot < 0) {
                fprintf(stderr, "Error: delkey requires --slot <n> (0..%d)\n",
                        SV7_MAX_SLOTS - 1);
                goto exit_mem;
            }
            ret = cmd_delkey(target, target_slot,
                             password, pw_len, keyfile_data, keyfile_len);
        } else if (is_rekey) {
            ret = cmd_rekey(target, output, password, pw_len,
                            keyfile_data, keyfile_len, verbose);
        } else {
            /* resolve NEW credential for addkey/passwd */
            char *nprompt = NULL;
            const char *npw = NULL;
            uint8_t *nkf = NULL;
            size_t nkf_len = 0;

            if (new_pass_fd >= 0 && new_password &&
                strcmp(new_password, "-") != 0) {
                fprintf(stderr, "Error: use either --new-password or --new-pass-fd\n");
                goto exit_mem;
            }
            if (new_pass_fd >= 0) {
                nprompt = read_pass_from_fd(new_pass_fd);
                if (!nprompt) goto exit_mem;
                npw = nprompt;
            } else if (!new_password || strcmp(new_password, "-") == 0) {
                fprintf(stderr, "New password: ");
                fflush(stderr);
                nprompt = read_pass_from_fd(STDIN_FILENO);
                if (!nprompt) goto exit_mem;
                npw = nprompt;
            } else {
                npw = new_password;
            }
            if (new_keyfile_path &&
                load_keyfile(new_keyfile_path, keyfile_max_size, &nkf, &nkf_len) != 0)
                { wipe_pass_buf(nprompt); goto exit_mem; }

            if (strcmp(action, "addkey") == 0)
                ret = cmd_addkey(target, password, pw_len, keyfile_data, keyfile_len,
                                 npw, strlen(npw), nkf, nkf_len, allow_empty_pass);
            else
                ret = cmd_passwd(target, password, pw_len, keyfile_data, keyfile_len,
                                 npw, strlen(npw), nkf, nkf_len, allow_empty_pass);

            free_keyfile(nkf, nkf_len);
            wipe_pass_buf(nprompt);
        }
        progress_finish();
        fprintf(stderr, ret == 0 ? "[+] Success\n" : "[-] Operation failed\n");
        goto exit_mem;
    }

    if (pw_len == 0 && !keyfile_data) {
        if (!allow_empty_pass) {
            fprintf(stderr, "Error: empty password with no keyfile would create a weak "
                            "vault;\n       pass --allow-empty-pass to override.\n");
            goto exit_mem;
        }
        fprintf(stderr, "Warning: using EMPTY password - security rests entirely "
                        "on the keyfile\n");
    }

    /* For non-stdin targets, resolve real path for safety checks */
    struct stat st;
    int use_stdin = (strcmp(target, "-") == 0);
    if (!use_stdin && stat(target, &st) < 0) {
        perror("stat target");
        goto exit_mem;
    }

    char target_real[PATH_MAX] = {0};
    if (!use_stdin) {
        if (realpath(target, target_real) == NULL) {
            perror("realpath target");
            goto exit_mem;
        }
    }

    char output_real[PATH_MAX * 2] = {0};
    char default_out[PATH_MAX];

    if (strcmp(action, "enc") == 0) {
        if (!use_stdin && S_ISDIR(st.st_mode)) {
            if (!output) {
                snprintf(default_out, sizeof(default_out), "%s.vault", target);
                output = default_out;
            }
            if (realpath(output, output_real) == NULL) {
                char tmp_out[PATH_MAX];
                strncpy(tmp_out, output, sizeof(tmp_out)-1);
                tmp_out[sizeof(tmp_out)-1] = '\0';
                char *dir = dirname(tmp_out);
                char dir_real[PATH_MAX];
                if (realpath(dir, dir_real) != NULL) {
                    snprintf(output_real, sizeof(output_real), "%s/%s",
                             dir_real, basename((char *)output));
                } else {
                    output_real[0] = '\0';
                    strncat(output_real, output, sizeof(output_real) - 1);
                }
            }
            if (is_path_inside(target_real, output_real)) {
                fprintf(stderr, "Error: output vault must not be inside the input directory\n");
                goto exit_mem;
            }
            ret = encrypt_dir(target, output, password, pw_len,
                              keyfile_data, keyfile_len,
                              opslimit, memlimit, verbose, force_overwrite,
                              excludes, n_excludes);
        } else {
            if (!output) {
                snprintf(default_out, sizeof(default_out), "%s.vault", target);
                output = default_out;
            }
            ret = encrypt_file(target, output, password, pw_len,
                               keyfile_data, keyfile_len,
                               compress, opslimit, memlimit,
                               shred, verbose, force_overwrite);
        }
    } else if (strcmp(action, "list") == 0) {
        ret = cmd_list(target, password, pw_len,
                       keyfile_data, keyfile_len, verbose);
    } else if (strcmp(action, "dec") == 0 || strcmp(action, "verify") == 0) {
        verify_only = (strcmp(action, "verify") == 0);
        int is_bundle = 0;
        if (!use_stdin) {
            FILE *f = fopen(target, "rb");
            if (f) {
                uint8_t peek[8];
                if (fread(peek, 1, sizeof(peek), f) == sizeof(peek) &&
                    memcmp(peek, "SV0", 3) == 0 &&
                    (peek[3] == '6' || peek[3] == '7')) {
                    is_bundle = (peek[5] & FLAG_DIRECTORY) != 0;
                }
                fclose(f);
            }
        } else {
            /* Cannot peek stdin; assume single file */
            is_bundle = 0;
        }
        if (is_bundle) {
            if (!output && !verify_only) {
                snprintf(default_out, sizeof(default_out), "%s_extracted", target);
                output = default_out;
            }
            ret = decrypt_dir_bundle(target, verify_only ? NULL : output,
                                     password, pw_len,
                                     keyfile_data, keyfile_len,
                                     verify_only, verbose, force_overwrite);
        } else {
            if (!output && !verify_only) {
                size_t len = strlen(target);
                if (len > 6 && strcmp(target + len - 6, ".vault") == 0) {
                    size_t base_len = len - 6;
                    if (base_len >= sizeof(default_out)) base_len = sizeof(default_out) - 1;
                    memcpy(default_out, target, base_len);
                    default_out[base_len] = '\0';
                } else {
                    snprintf(default_out, sizeof(default_out), "%s.dec", target);
                }
                output = default_out;
            }
            ret = decrypt_file(target, verify_only ? NULL : output,
                               password, pw_len,
                               keyfile_data, keyfile_len,
                               verify_only, verbose, force_overwrite);
        }
    } else {
        fprintf(stderr, "Unknown action: %s\n", action);
        usage(argv[0]);
        ret = 1;
    }

    progress_finish();
    fprintf(stderr, ret == 0 ? "[+] Success\n" : "[-] Operation failed\n");

exit_mem:
    if (ext_pass) {
        sodium_munlock(ext_pass, PASS_FD_MAX);
        sodium_memzero(ext_pass, PASS_FD_MAX);
        sodium_free(ext_pass);
    }
    for (size_t i = 0; i < n_excludes; i++) free(excludes[i]);
    free(excludes);
    sodium_munlock(pw_buf, sizeof(pw_buf));
    sodium_memzero(pw_buf, sizeof(pw_buf));
    if (keyfile_data) {
        sodium_munlock(keyfile_data, keyfile_len);
        sodium_memzero(keyfile_data, keyfile_len);
        sodium_free(keyfile_data);
    }
    return ret;
}
