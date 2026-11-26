#include "tls_ja3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- MD5 (RFC 1321) ---------- */
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
static const uint8_t R[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rotl32(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

void ja3_md5_hex(const uint8_t *msg, size_t n, char out[33])
{
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    size_t padded = ((n + 8) / 64 + 1) * 64;
    uint8_t *m = calloc(padded, 1);
    if (!m) { out[0] = 0; return; }
    if (n) memcpy(m, msg, n);
    m[n] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) m[padded - 8 + i] = (uint8_t)(bits >> (8 * i));

    for (size_t off = 0; off < padded; off += 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++)
            M[i] = (uint32_t)m[off + 4*i] | ((uint32_t)m[off + 4*i + 1] << 8) |
                   ((uint32_t)m[off + 4*i + 2] << 16) | ((uint32_t)m[off + 4*i + 3] << 24);
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; i++) {
            uint32_t F; int g;
            if (i < 16)      { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
            else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
            F = F + A + K[i] + M[g];
            A = D; D = C; C = B;
            B = B + rotl32(F, R[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    free(m);

    uint32_t h[4] = { a0, b0, c0, d0 };
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            sprintf(out + (i * 4 + j) * 2, "%02x", (h[i] >> (8 * j)) & 0xff);
    out[32] = 0;
}

/* ---------- helpers ---------- */
static unsigned be16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }

/* GREASE values (0x0a0a, 0x1a1a, ... 0xfafa) are random placeholders; JA3 ignores them. */
static int is_grease(unsigned v) { return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff); }

struct sbuf { char *s; size_t n, cap; };

/* append a number, with a '-' in front if the list already has entries */
static void sb_num(struct sbuf *b, unsigned v)
{
    int w = snprintf(b->s + b->n, b->cap - b->n, "%s%u", b->n ? "-" : "", v);
    if (w > 0 && (size_t)w < b->cap - b->n) b->n += (size_t)w;
}

/* ---------- ClientHello parser ---------- */
int tls_parse_client_hello(const uint8_t *buf, size_t len, struct tls_info *out)
{
    memset(out, 0, sizeof *out);
    if (len < 9 || buf[0] != 0x16 || buf[1] != 0x03) return 0;          /* TLS handshake record */
    size_t reclen = be16(buf + 3);
    if (len < 5 + reclen) return 0;

    const uint8_t *p = buf + 5, *end = buf + 5 + reclen;
    if (end - p < 4 || p[0] != 0x01) return 0;                          /* handshake type 1 = ClientHello */
    size_t hl = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
    p += 4;
    if ((size_t)(end - p) < hl) return 0;       /* hello spread over several TLS records: not handled */
    end = p + hl;

    if (end - p < 2 + 32 + 1) return 0;
    unsigned legacy = be16(p);                  /* version field used by JA3 */
    p += 2 + 32;                                /* version + random */
    size_t sl = *p++;                           /* session id */
    if ((size_t)(end - p) < sl + 2) return 0;
    p += sl;
    size_t cl = be16(p); p += 2;                /* cipher suites */
    if ((cl & 1) || (size_t)(end - p) < cl + 1) return 0;
    const uint8_t *ciph = p; p += cl;
    size_t cm = *p++;                           /* compression methods */
    if ((size_t)(end - p) < cm) return 0;
    p += cm;

    char ciph_s[2048] = "", ext_s[2048] = "", grp_s[2048] = "", pf_s[512] = "";
    struct sbuf SC = { ciph_s, 0, sizeof ciph_s }, SE = { ext_s, 0, sizeof ext_s };
    struct sbuf SG = { grp_s, 0, sizeof grp_s },   SP = { pf_s, 0, sizeof pf_s };

    for (size_t i = 0; i + 2 <= cl; i += 2) {
        unsigned c = be16(ciph + i);
        if (!is_grease(c)) sb_num(&SC, c);
    }

    unsigned max_ver = 0;
    if (end - p >= 2) {
        size_t el = be16(p); p += 2;
        if ((size_t)(end - p) < el) return 0;
        const uint8_t *ee = p + el;
        while (ee - p >= 4) {
            unsigned type = be16(p);
            size_t elen = be16(p + 2);
            const uint8_t *d = p + 4;
            if ((size_t)(ee - d) < elen) return 0;
            if (!is_grease(type)) sb_num(&SE, type);

            if (type == 0 && elen >= 5) {                       /* server_name */
                const uint8_t *q = d + 2, *qe = d + elen;       /* skip the list length */
                while (qe - q >= 3) {
                    unsigned nt = q[0];
                    size_t nl = be16(q + 1);
                    q += 3;
                    if ((size_t)(qe - q) < nl) break;
                    if (nt == 0 && out->sni[0] == 0) {
                        size_t k = nl < sizeof out->sni - 1 ? nl : sizeof out->sni - 1;
                        for (size_t i = 0; i < k; i++) {
                            unsigned char ch = q[i];
                            out->sni[i] = (ch > 0x20 && ch < 0x7f && ch != '"' && ch != '\\') ? (char)ch : '?';
                        }
                        out->sni[k] = 0;
                    }
                    q += nl;
                }
            } else if (type == 10 && elen >= 2) {               /* supported_groups (elliptic curves) */
                size_t gl = be16(d);
                for (size_t i = 0; i + 2 <= gl && 2 + i + 2 <= elen; i += 2) {
                    unsigned g = be16(d + 2 + i);
                    if (!is_grease(g)) sb_num(&SG, g);
                }
            } else if (type == 11 && elen >= 1) {               /* ec_point_formats */
                size_t pl = d[0];
                for (size_t i = 0; i < pl && 1 + i < elen; i++) sb_num(&SP, d[1 + i]);
            } else if (type == 43 && elen >= 1) {               /* supported_versions */
                size_t vl = d[0];
                for (size_t i = 0; i + 2 <= vl && 1 + i + 2 <= elen; i += 2) {
                    unsigned v = be16(d + 1 + i);
                    if (!is_grease(v) && v > max_ver) max_ver = v;
                }
            }
            p = d + elen;
        }
    }

    char ja3_str[7000];
    int n = snprintf(ja3_str, sizeof ja3_str, "%u,%s,%s,%s,%s", legacy, ciph_s, ext_s, grp_s, pf_s);
    if (n < 0 || (size_t)n >= sizeof ja3_str) return 0;
    ja3_md5_hex((const uint8_t *)ja3_str, (size_t)n, out->ja3);

    unsigned v = max_ver ? max_ver : legacy;
    const char *vs = v == 0x0304 ? "1.3" : v == 0x0303 ? "1.2" : v == 0x0302 ? "1.1" : v == 0x0301 ? "1.0" : "?";
    strcpy(out->version, vs);
    out->valid = 1;
    return 1;
}

/* ---------- collecting the client's first bytes ---------- */
void tls_stream_free(struct tls_stream *s)
{
    free(s->buf);
    s->buf = NULL;
}

void tls_stream_feed(struct tls_stream *s, int syn, uint32_t seq, const uint8_t *pl, size_t plen)
{
    if (s->state == 2) return;
    if (syn) { s->base = seq + 1; s->have_base = 1; return; }
    if (plen == 0) return;
    if (!s->have_base) { s->base = seq; s->have_base = 1; }       /* capture began after the SYN */

    uint32_t off = seq - s->base;                                 /* wraps correctly */

    if (s->state == 0) {
        if (off != 0 || plen < 3 || pl[0] != 0x16 || pl[1] != 0x03) { s->state = 2; return; }  /* not TLS */
        s->buf = malloc(TLS_BUF_MAX);
        if (!s->buf) { s->state = 2; return; }
        s->len = 0;
        s->state = 1;
    }

    if (off > s->len) { s->state = 2; tls_stream_free(s); return; }   /* a gap: give up */
    size_t skip = s->len - off;                                       /* bytes already held (retransmission) */
    if (skip >= plen) return;
    size_t room = TLS_BUF_MAX - s->len;
    size_t take = plen - skip < room ? plen - skip : room;
    memcpy(s->buf + s->len, pl + skip, take);
    s->len += (uint32_t)take;

    if (s->len >= 5) {
        size_t reclen = be16(s->buf + 3);
        if (5 + reclen > TLS_BUF_MAX) { s->state = 2; tls_stream_free(s); return; }
        if (s->len >= 5 + reclen) {
            tls_parse_client_hello(s->buf, s->len, &s->info);
            s->state = 2;
            tls_stream_free(s);
        }
    }
}
