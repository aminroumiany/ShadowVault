/*
 * ShadowVault  – Envelope Encryption + XChaCha20-Poly1305 Secretstream
 *
 * Build: gcc -O2 -Wall -Wextra -o shadowvault shadowvault_v6.c -lsodium -lz
 * Usage: ./shadowvault <enc|dec|verify> <file|dir> [options]
*/

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64   /* ensure off_t is 64-bit everywhere */
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
#include <ftw.h>
#include <sodium.h>
#include <zlib.h>
#include <limits.h>            /* for PATH_MAX */

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

/* Argon2id defaults, persisted */
#define DEFAULT_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define DEFAULT_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

/* Bundle entry tags */
#define ENTRY_FILE 1
#define ENTRY_END  0

/* Maximum path length inside a bundle */
#define MAX_BUNDLE_PATH 4095

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
#pragma pack(pop)

static volatile sig_atomic_t g_interrupted = 0;
static const char *g_output_path = NULL;

static void signal_handler(int sig) { (void)sig; g_interrupted = 1; }

/* ----- Network-byte-order helpers ----- */
static void put_u64be(uint8_t *out, uint64_t v) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint64_t get_u64be(const uint8_t *in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
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
        if (r == 0) return 0; /* EOF */
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
        if (r == 0) return -1; /* Should not happen for regular files */
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

    if (password && pw_len) memcpy(combined, password, pw_len);
    if (keyfile_data && keyfile_len) memcpy(combined + pw_len, keyfile_data, keyfile_len);

    int ret = crypto_pwhash(kek, DEK_SIZE,
                             (const char *)combined, total_len,
                             salt, opslimit, memlimit,
                             crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(combined, total_len > 0 ? total_len : 1);
    sodium_free(combined);
    return ret;
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
        /* Try to make the file owner-writable so the overwrite can proceed. */
        if (chmod(path, S_IRUSR | S_IWUSR) == 0)
            fd = open(path, O_RDWR);
    }
    if (fd < 0) {
        perror("open for shred");
        return -1;
    }

    uint8_t *buf = malloc(CHUNK_SIZE);
    if (!buf) { close(fd); return -1; }

    for (int pass = 0; pass < 3; pass++) {
        if (lseek(fd, 0, SEEK_SET) < 0) break;
        off_t remaining = size;
        while (remaining > 0) {
            size_t want = remaining > CHUNK_SIZE ? CHUNK_SIZE : (size_t)remaining;
            if (pass < 2) randombytes_buf(buf, want);
            else memset(buf, 0, want);
            ssize_t w = write_full(fd, buf, want);
            if (w < 0) break;
            remaining -= w;
        }
        fsync(fd);
    }
    free(buf);
    close(fd);

    /* Rename before unlink as a best-effort extra step to obscure the name.
       Use mkstemp in the same directory to guarantee the rename succeeds
       (cross-device rename would fail). */
    char *dup = strdup(path);
    if (dup) {
        char *dirp = dirname(dup);
        char tmpl[PATH_MAX];
        if (snprintf(tmpl, sizeof(tmpl), "%s/.sv_shred_XXXXXX", dirp) < (int)sizeof(tmpl)) {
            int tfd = mkstemp(tmpl);
            if (tfd >= 0) {
                close(tfd);
                unlink(tmpl); /* remove it immediately so it doesn't exist */
                if (rename(path, tmpl) == 0) {
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
    if (r->saw_final) return -1; /* extra data after FINAL */

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

/* ==========================================================================
 * Single file encrypt / decrypt
 * ========================================================================== */

static int encrypt_stream_body(int in_fd, sv_writer_t *w, int use_zlib,
                                off_t *processed_out) {
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

    n = read_full(in_fd, cur_buf, CHUNK_SIZE);
    if (n < 0) goto done;

    /* Fix: Handle empty files properly by emitting a single FINAL block */
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
            size_t cap = CHUNK_SIZE + CHUNK_SIZE / 10 + 64;
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

        ssize_t next_n = read_full(in_fd, next_buf, CHUNK_SIZE);
        if (next_n < 0) { if (comp_buf) free(comp_buf); goto done; }

        uint8_t tag = (next_n == 0) ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                     : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        if (writer_push(w, data, data_len, tag) != 0) {
            if (comp_buf) free(comp_buf);
            goto done;
        }
        if (comp_buf) free(comp_buf);

        processed += n;
        n = next_n;
        /* swap buffers */
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
                         int shred_original, int verbose) {
    int in_fd = -1, out_fd = -1, ret = -1;
    uint8_t dek[DEK_SIZE];
    sv_writer_t w; memset(&w, 0, sizeof(w));
    int writer_ok = 0;

    if (is_same_file(inpath, outpath)) {
        fprintf(stderr, "Error: input and output are the same file\n");
        return -1;
    }
    in_fd = open(inpath, O_RDONLY);
    if (in_fd < 0) { perror("open input"); goto cleanup; }
    struct stat st;
    if (fstat(in_fd, &st) < 0) { perror("fstat"); goto cleanup; }

    out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) { perror("open output"); goto cleanup; }
    g_output_path = outpath;

    sv_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, SV_MAGIC, 4);
    hdr.version = SV_VERSION;
    hdr.flags = compress ? FLAG_COMPRESSED : 0;
    put_u64be(hdr.opslimit_be, opslimit);
    put_u64be(hdr.memlimit_be, memlimit);
    randombytes_buf(hdr.salt, SALT_SIZE);

    if (verbose) {
        fprintf(stderr, "opslimit=%llu memlimit=%llu flags=0x%02x\n",
                (unsigned long long)opslimit, (unsigned long long)memlimit,
                hdr.flags);
    }

    {
        uint8_t kek[DEK_SIZE];
        if (derive_kek(password, pw_len, keyfile_data, keyfile_len, hdr.salt, kek,
                       opslimit, (size_t)memlimit) != 0) {
            fprintf(stderr, "Key derivation failed\n");
            goto cleanup;
        }
        randombytes_buf(dek, DEK_SIZE);
        randombytes_buf(hdr.wrap_nonce, WRAP_NONCE_SIZE);
        int wrap_rc = crypto_secretbox_easy(hdr.wrapped_dek, dek, DEK_SIZE,
                                            hdr.wrap_nonce, kek);
        sodium_memzero(kek, DEK_SIZE);
        if (wrap_rc != 0) { fprintf(stderr, "DEK wrap failed\n"); goto cleanup; }
    }

    /* The packed struct is used directly as the Authenticated Data */
    if (writer_init(&w, out_fd, dek, hdr.stream_header, (const uint8_t *)&hdr, sizeof(hdr)) != 0) {
        fprintf(stderr, "Stream init failed\n");
        goto cleanup;
    }
    writer_ok = 1;

    if (write_full(out_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("write header");
        goto cleanup;
    }

    off_t processed = 0;
    if (encrypt_stream_body(in_fd, &w, compress, &processed) != 0) {
        fprintf(stderr, "Encryption failed or interrupted\n");
        goto cleanup;
    }
    if (verbose) fprintf(stderr, "Encrypted %lld bytes -> %s\n",
                         (long long)processed, outpath);

    ret = 0;

    if (shred_original && ret == 0) {
        close(in_fd); in_fd = -1;
        fprintf(stderr, "Shredding original (overwrite-based; see header comment on SSD/COW caveats)...\n");
        if (secure_delete(inpath, st.st_size) != 0)
            fprintf(stderr, "Warning: secure deletion failed\n");
    }

cleanup:
    sodium_memzero(dek, DEK_SIZE);
    if (writer_ok) writer_free(&w);
    if (in_fd >= 0) close(in_fd);
    if (out_fd >= 0) {
        close(out_fd);
        if (ret != 0 && g_output_path) unlink(g_output_path);
    }
    return ret;
}

static int decrypt_file(const char *inpath, const char *outpath,
                         const char *password, size_t pw_len,
                         const uint8_t *keyfile_data, size_t keyfile_len,
                         int verify_only, int verbose) {
    int in_fd = -1, out_fd = -1, ret = -1;
    uint8_t dek[DEK_SIZE];
    sv_reader_t r; memset(&r, 0, sizeof(r));
    int reader_ok = 0;
    z_stream zstrm; memset(&zstrm, 0, sizeof(zstrm));
    int zlib_ok = 0;

    in_fd = open(inpath, O_RDONLY);
    if (in_fd < 0) { perror("open input"); goto cleanup; }

    if (!verify_only) {
        if (is_same_file(inpath, outpath)) {
            fprintf(stderr, "Error: output would overwrite input\n");
            goto cleanup;
        }
        out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (out_fd < 0) { perror("open output"); goto cleanup; }
        g_output_path = outpath;
    }

    sv_header_t hdr;
    if (read_full(in_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr, "Invalid or truncated vault file (header)\n");
        goto cleanup;
    }
    if (memcmp(hdr.magic, SV_MAGIC, 4) != 0) {
        fprintf(stderr, "Invalid magic bytes (not a v6 vault, or corrupted)\n");
        goto cleanup;
    }
    if (hdr.version != SV_VERSION) {
        fprintf(stderr, "Unsupported version: %d\n", hdr.version);
        goto cleanup;
    }
    if (hdr.flags & FLAG_DIRECTORY) {
        fprintf(stderr, "This is a directory bundle, not a single file\n");
        goto cleanup;
    }

    uint64_t opslimit = get_u64be(hdr.opslimit_be);
    uint64_t memlimit = get_u64be(hdr.memlimit_be);

    {
        uint8_t kek[DEK_SIZE];
        if (derive_kek(password, pw_len, keyfile_data, keyfile_len, hdr.salt, kek,
                       opslimit, (size_t)memlimit) != 0) {
            fprintf(stderr, "Key derivation failed\n");
            goto cleanup;
        }
        int unwrap_rc = crypto_secretbox_open_easy(dek, hdr.wrapped_dek,
                                                    sizeof(hdr.wrapped_dek),
                                                    hdr.wrap_nonce, kek);
        sodium_memzero(kek, DEK_SIZE);
        if (unwrap_rc != 0) {
            fprintf(stderr, "[FAIL] Wrong password/keyfile, or header tampered\n");
            goto cleanup;
        }
    }

    if (reader_init(&r, in_fd, dek, hdr.stream_header, (const uint8_t *)&hdr, sizeof(hdr)) != 0) {
        fprintf(stderr, "Stream init failed\n");
        goto cleanup;
    }
    reader_ok = 1;

    if (hdr.flags & FLAG_COMPRESSED) {
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
        if (rc == 0) break; /* clean end */

        if (!verify_only) {
            if (zlib_ok) {
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

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
    }
    sodium_free(plain);

    if (verbose) fprintf(stderr, "%s %lld bytes OK\n",
                         verify_only ? "Verified" : "Decrypted",
                         (long long)decrypted_size);
    ret = 0;

cleanup:
    sodium_memzero(dek, DEK_SIZE);
    if (zlib_ok) inflateEnd(&zstrm);
    if (reader_ok) reader_free(&r);
    if (in_fd >= 0) close(in_fd);
    if (out_fd >= 0) {
        close(out_fd);
        if (ret != 0 && g_output_path) unlink(g_output_path);
    }
    return ret;
}

/* ==========================================================================
 * Directory bundle mode
 * ========================================================================== */

static int bundle_write_entry_header(sv_writer_t *w, const char *relpath,
                                     off_t size, mode_t mode) {
    size_t rlen = strlen(relpath);
    if (rlen > MAX_BUNDLE_PATH) {
        fprintf(stderr, "Path too long for bundle entry (max %d): %s\n",
                MAX_BUNDLE_PATH, relpath);
        return -1;
    }
    uint16_t plen = (uint16_t)rlen;
    uint8_t hdrbuf[1 + 2 + MAX_BUNDLE_PATH + 8 + 4];
    size_t o = 0;
    hdrbuf[o++] = ENTRY_FILE;
    hdrbuf[o++] = (uint8_t)(plen >> 8);
    hdrbuf[o++] = (uint8_t)(plen & 0xff);
    memcpy(hdrbuf + o, relpath, plen); o += plen;
    put_u64be(hdrbuf + o, (uint64_t)size); o += 8;
    hdrbuf[o++] = (uint8_t)((mode >> 24) & 0xff);
    hdrbuf[o++] = (uint8_t)((mode >> 16) & 0xff);
    hdrbuf[o++] = (uint8_t)((mode >> 8) & 0xff);
    hdrbuf[o++] = (uint8_t)(mode & 0xff);
    return writer_push(w, hdrbuf, o, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
}

static int bundle_add_tree(sv_writer_t *w, const char *base_in, const char *rel,
                           int *file_count) {
    char full[PATH_MAX * 2];
    int wrote = snprintf(full, sizeof(full), "%s/%s", base_in,
                         rel && rel[0] ? rel : "");
    if (wrote < 0 || (size_t)wrote >= sizeof(full)) {
        fprintf(stderr, "Path too long, aborting: %s/%s\n", base_in, rel ? rel : "");
        return -1;
    }
    DIR *d = opendir(full);
    if (!d) { perror("opendir"); return -1; }
    struct dirent *entry;
    int errors = 0;
    while ((entry = readdir(d)) != NULL) {
        if (g_interrupted) { errors++; break; }
        /* Fix: Only skip "." and "..", do not skip all dotfiles */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char child_rel[PATH_MAX];
        int w1 = (rel && rel[0])
                 ? snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, entry->d_name)
                 : snprintf(child_rel, sizeof(child_rel), "%s", entry->d_name);
        if (w1 < 0 || (size_t)w1 >= sizeof(child_rel)) {
            fprintf(stderr, "Relative path too long, skipping: %s\n", entry->d_name);
            errors++; continue;
        }

        char child_full[PATH_MAX * 2];
        int w2 = snprintf(child_full, sizeof(child_full), "%s/%s", base_in, child_rel);
        if (w2 < 0 || (size_t)w2 >= sizeof(child_full)) {
            fprintf(stderr, "Full path too long, skipping: %s\n", child_rel);
            errors++; continue;
        }
        struct stat st;
        if (lstat(child_full, &st) < 0) continue;
        if (S_ISLNK(st.st_mode)) continue; /* Explicitly skip symlinks for security */

        if (S_ISDIR(st.st_mode)) {
            if (bundle_add_tree(w, base_in, child_rel, file_count) != 0) errors++;
        } else if (S_ISREG(st.st_mode)) {
            int fd = open(child_full, O_RDONLY);
            if (fd < 0) { perror("open"); errors++; continue; }
            if (bundle_write_entry_header(w, child_rel, st.st_size, st.st_mode) != 0) {
                close(fd); errors++; continue;
            }
            uint8_t *buf = malloc(CHUNK_SIZE);
            ssize_t n;
            while ((n = read_full(fd, buf, CHUNK_SIZE)) > 0) {
                if (g_interrupted) { errors++; break; }
                if (writer_push(w, buf, (size_t)n,
                                crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
                    errors++; break;
                }
            }
            free(buf);
            close(fd);
            (*file_count)++;
        }
        if (g_interrupted) { errors++; break; }
    }
    closedir(d);
    return errors ? -1 : 0;
}

static int encrypt_dir(const char *dirpath, const char *outpath,
                        const char *password, size_t pw_len,
                        const uint8_t *keyfile_data, size_t keyfile_len,
                        uint64_t opslimit, uint64_t memlimit, int verbose) {
    int out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) { perror("open output"); return -1; }
    g_output_path = outpath;

    uint8_t dek[DEK_SIZE];
    sv_header_t hdr; memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, SV_MAGIC, 4);
    hdr.version = SV_VERSION;
    hdr.flags = FLAG_DIRECTORY;
    put_u64be(hdr.opslimit_be, opslimit);
    put_u64be(hdr.memlimit_be, memlimit);
    randombytes_buf(hdr.salt, SALT_SIZE);

    if (verbose) {
        fprintf(stderr, "opslimit=%llu memlimit=%llu flags=0x%02x\n",
                (unsigned long long)opslimit, (unsigned long long)memlimit,
                hdr.flags);
    }

    uint8_t kek[DEK_SIZE];
    if (derive_kek(password, pw_len, keyfile_data, keyfile_len, hdr.salt, kek,
                   opslimit, (size_t)memlimit) != 0) {
        fprintf(stderr, "Key derivation failed\n"); close(out_fd); return -1;
    }
    randombytes_buf(dek, DEK_SIZE);
    randombytes_buf(hdr.wrap_nonce, WRAP_NONCE_SIZE);
    int wrap_rc = crypto_secretbox_easy(hdr.wrapped_dek, dek, DEK_SIZE,
                                        hdr.wrap_nonce, kek);
    sodium_memzero(kek, DEK_SIZE);
    if (wrap_rc != 0) { fprintf(stderr, "DEK wrap failed\n"); close(out_fd); return -1; }

    sv_writer_t w; memset(&w, 0, sizeof(w));
    if (writer_init(&w, out_fd, dek, hdr.stream_header, (const uint8_t *)&hdr, sizeof(hdr)) != 0) {
        fprintf(stderr, "Stream init failed\n"); close(out_fd); return -1;
    }

    if (write_full(out_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("write header"); writer_free(&w); close(out_fd); return -1;
    }

    int file_count = 0;
    int ret = bundle_add_tree(&w, dirpath, "", &file_count);

    /* Final empty TAG_FINAL block marks end of bundle. */
    if (ret == 0) {
        uint8_t end_marker[1] = { ENTRY_END };
        if (writer_push(&w, end_marker, 1,
                        crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0)
            ret = -1;
    }

    if (verbose) fprintf(stderr, "Bundled %d files from %s -> %s\n",
                         file_count, dirpath, outpath);

    sodium_memzero(dek, DEK_SIZE);
    writer_free(&w);
    close(out_fd);
    if (ret != 0) unlink(outpath);
    return ret;
}

static int decrypt_dir_bundle(const char *inpath, const char *outdir,
                               const char *password, size_t pw_len,
                               const uint8_t *keyfile_data, size_t keyfile_len,
                               int verify_only, int verbose) {
    int in_fd = open(inpath, O_RDONLY);
    if (in_fd < 0) { perror("open input"); return -1; }

    sv_header_t hdr;
    if (read_full(in_fd, &hdr, sizeof(hdr)) != sizeof(hdr) ||
        memcmp(hdr.magic, SV_MAGIC, 4) != 0 || hdr.version != SV_VERSION) {
        fprintf(stderr, "Invalid or unsupported vault bundle\n");
        close(in_fd); return -1;
    }

    uint64_t opslimit = get_u64be(hdr.opslimit_be);
    uint64_t memlimit = get_u64be(hdr.memlimit_be);

    uint8_t dek[DEK_SIZE], kek[DEK_SIZE];
    if (derive_kek(password, pw_len, keyfile_data, keyfile_len, hdr.salt, kek,
                   opslimit, (size_t)memlimit) != 0) {
        fprintf(stderr, "Key derivation failed\n"); close(in_fd); return -1;
    }
    int unwrap_rc = crypto_secretbox_open_easy(dek, hdr.wrapped_dek,
                                                sizeof(hdr.wrapped_dek),
                                                hdr.wrap_nonce, kek);
    sodium_memzero(kek, DEK_SIZE);
    if (unwrap_rc != 0) {
        fprintf(stderr, "[FAIL] Wrong password/keyfile, or header tampered\n");
        close(in_fd); return -1;
    }

    sv_reader_t r;
    if (reader_init(&r, in_fd, dek, hdr.stream_header, (const uint8_t *)&hdr, sizeof(hdr)) != 0) {
        fprintf(stderr, "Stream init failed\n"); close(in_fd); return -1;
    }

    char staging[PATH_MAX * 2] = {0};
    if (!verify_only) {
        snprintf(staging, sizeof(staging), "%s.svtmp.XXXXXX", outdir);
        if (mkdtemp(staging) == NULL) {
            perror("mkdtemp staging");
            reader_free(&r);
            close(in_fd);
            return -1;
        }
    }

    uint8_t *plain = sodium_malloc(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    int ret = -1, files_done = 0;
    int out_fd = -1;
    off_t remaining_in_file = 0;
    int in_file = 0;
    char cur_path[PATH_MAX * 2] = {0};

    for (;;) {
        size_t plen; uint8_t tag;
        int rc = reader_pull(&r, plain, &plen, &tag);
        if (rc < 0) {
            fprintf(stderr, "[FAIL] Bundle authentication failed: tampered, "
                    "reordered, or truncated\n");
            goto cleanup;
        }
        if (rc == 0) { ret = 0; break; }

        if (remaining_in_file == 0) {
            if (plen < 1) goto cleanup;
            if (plain[0] == ENTRY_END) {
                ret = 0;
                if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
                continue;
            }
            if (plain[0] != ENTRY_FILE || plen < 1 + 2) goto cleanup;
            uint16_t path_len = ((uint16_t)plain[1] << 8) | plain[2];
            if (plen < (size_t)(1 + 2 + path_len + 8 + 4)) goto cleanup;
            char relpath[PATH_MAX];
            if (path_len >= sizeof(relpath)) goto cleanup;
            memcpy(relpath, plain + 3, path_len);
            relpath[path_len] = '\0';
            if (relpath[0] == '/' || strstr(relpath, "..") != NULL) {
                fprintf(stderr, "Refusing unsafe path in bundle: %s\n", relpath);
                goto cleanup;
            }
            uint64_t fsize = get_u64be(plain + 3 + path_len);
            remaining_in_file = (off_t)fsize;
            in_file = 1;

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
                /* mkdir -p equivalent */
                char tmp[PATH_MAX * 2];
                strncpy(tmp, cur_path, sizeof(tmp)-1);
                tmp[sizeof(tmp)-1] = '\0';
                for (char *p = tmp + strlen(staging) + 1; *p; p++) {
                    if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
                }
                out_fd = open(cur_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (out_fd < 0) { perror("open output entry"); goto cleanup; }
                if (remaining_in_file == 0) { close(out_fd); out_fd = -1; in_file = 0; files_done++; }
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
                if (!verify_only && out_fd >= 0) { close(out_fd); out_fd = -1; }
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
    sodium_memzero(dek, DEK_SIZE);
    reader_free(&r);
    close(in_fd);

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
 * CLI helpers
 * ========================================================================== */

static void usage(const char *prog) {
    fprintf(stderr,
        "ShadowVault v6 - Envelope + XChaCha20-Poly1305 Secretstream\n\n"
        "Usage:\n"
        "  %s enc <file|dir>   [options]\n"
        "  %s dec <vault>      [options]\n"
        "  %s verify <vault>   [options]\n\n"
        "Options:\n"
        "  -p, --password <pw>   Password (\"-\" to prompt)\n"
        "  -k, --keyfile <file>  Key file, combined with password\n"
        "  -o, --output <path>   Output path\n"
        "  -c, --compress        Enable zlib compression (file mode only; persisted)\n"
        "  -s, --shred           Securely overwrite + delete original after encrypting\n"
        "  -v, --verbose         Verbose output\n"
        "  -h, --help            This help\n\n"
        "Argon2id cost is stored in the file header – no need to repeat at decrypt.\n"
        "Directory mode bundles the whole tree into one authenticated stream.\n",
        prog, prog, prog);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    const char *action = NULL, *target = NULL;
    char *password = NULL;
    const char *keyfile_path = NULL, *output = NULL;
    int compress = 0, verbose = 0, shred = 0, verify_only = 0;

    static struct option long_opts[] = {
        {"password", required_argument, 0, 'p'},
        {"keyfile",  required_argument, 0, 'k'},
        {"output",   required_argument, 0, 'o'},
        {"compress", no_argument,       0, 'c'},
        {"shred",    no_argument,       0, 's'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:k:o:csvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': password = optarg; break;
        case 'k': keyfile_path = optarg; break;
        case 'o': output = optarg; break;
        case 'c': compress = 1; break;
        case 's': shred = 1; break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: missing action and target\n");
        usage(argv[0]);
        return 1;
    }
    action = argv[optind++];
    if (optind >= argc) {
        fprintf(stderr, "Error: missing target\n");
        usage(argv[0]);
        return 1;
    }
    target = argv[optind];

    char pw_buf[256] = {0};
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
        if (fstat(fileno(kf), &kst) < 0 || kst.st_size > 1024 * 1024) {
            fprintf(stderr, "Keyfile invalid or too large (max 1 MiB)\n");
            fclose(kf); return 1;
        }
        keyfile_len = (size_t)kst.st_size;
        keyfile_data = sodium_malloc(keyfile_len > 0 ? keyfile_len : 1);
        rewind(kf);
        if (!keyfile_data || fread(keyfile_data, 1, keyfile_len, kf) != keyfile_len) {
            fclose(kf);
            if (keyfile_data) sodium_free(keyfile_data);
            return 1;
        }
        fclose(kf);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART; /* Restart interrupted syscalls */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct stat st;
    if (stat(target, &st) < 0) {
        perror("stat target");
        if (keyfile_data) sodium_free(keyfile_data);
        return 1;
    }

    char target_real[PATH_MAX];
    if (realpath(target, target_real) == NULL) {
        perror("realpath target");
        if (keyfile_data) sodium_free(keyfile_data);
        return 1;
    }

    char output_real[PATH_MAX] = {0};
    char default_out[PATH_MAX];
    int ret;

    if (strcmp(action, "enc") == 0) {
        if (S_ISDIR(st.st_mode)) {
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
                    strncpy(output_real, output, sizeof(output_real)-1);
                }
            }
            if (is_path_inside(target_real, output_real)) {
                fprintf(stderr, "Error: output vault must not be inside the input directory\n");
                if (keyfile_data) sodium_free(keyfile_data);
                return 1;
            }
            ret = encrypt_dir(target, output, password, pw_len,
                              keyfile_data, keyfile_len,
                              DEFAULT_OPSLIMIT, DEFAULT_MEMLIMIT, verbose);
        } else {
            if (!output) {
                snprintf(default_out, sizeof(default_out), "%s.vault", target);
                output = default_out;
            }
            ret = encrypt_file(target, output, password, pw_len,
                               keyfile_data, keyfile_len,
                               compress, DEFAULT_OPSLIMIT, DEFAULT_MEMLIMIT,
                               shred, verbose);
        }
    } else if (strcmp(action, "dec") == 0 || strcmp(action, "verify") == 0) {
        verify_only = (strcmp(action, "verify") == 0);
        int is_bundle = 0;
        {
            FILE *f = fopen(target, "rb");
            if (f) {
                sv_header_t peek;
                if (fread(&peek, 1, sizeof(peek), f) == sizeof(peek) &&
                    memcmp(peek.magic, SV_MAGIC, 4) == 0) {
                    is_bundle = (peek.flags & FLAG_DIRECTORY) != 0;
                }
                fclose(f);
            }
        }
        if (is_bundle) {
            if (!output && !verify_only) {
                snprintf(default_out, sizeof(default_out), "%s_extracted", target);
                output = default_out;
            }
            ret = decrypt_dir_bundle(target, verify_only ? NULL : output,
                                     password, pw_len,
                                     keyfile_data, keyfile_len,
                                     verify_only, verbose);
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
                               verify_only, verbose);
        }
    } else {
        fprintf(stderr, "Unknown action: %s\n", action);
        usage(argv[0]);
        ret = 1;
    }

    /* Fix: securely zero the entire password buffer, not just strlen */
    explicit_bzero(pw_buf, sizeof(pw_buf));
    if (keyfile_data) { sodium_memzero(keyfile_data, keyfile_len); sodium_free(keyfile_data); }

    fprintf(stderr, ret == 0 ? "[+] Success\n" : "[-] Operation failed\n");
    return ret;
}
