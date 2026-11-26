/* tls_ja3.h - find the TLS ClientHello in a TCP flow, read SNI/version, compute the JA3 fingerprint. */
#ifndef TLS_JA3_H
#define TLS_JA3_H
#include <stddef.h>
#include <stdint.h>

#define TLS_BUF_MAX 8192   /* most we will buffer while waiting for a complete ClientHello */

struct tls_info {
    int  valid;            /* 1 once a ClientHello was parsed */
    char version[4];       /* highest TLS version the client offers: "1.3", "1.2", ... */
    char sni[256];         /* server name, "" if the client sent none */
    char ja3[33];          /* 32 hex chars + NUL */
};

/* Per-flow state for collecting the first bytes the client sends. Zero-initialise it. */
struct tls_stream {
    uint8_t  state;        /* 0 = waiting for first data, 1 = collecting, 2 = finished */
    uint8_t  have_base;
    uint32_t base;         /* TCP sequence number of the first payload byte */
    uint32_t len;          /* bytes collected so far */
    uint8_t *buf;
    struct tls_info info;
};

/* Call for every client->server TCP packet of the flow, in capture order.
   syn = 1 for the client's SYN (so we learn the initial sequence number). */
void tls_stream_feed(struct tls_stream *s, int syn, uint32_t seq, const uint8_t *payload, size_t plen);
void tls_stream_free(struct tls_stream *s);

/* Parse one complete TLS record holding a ClientHello. Returns 1 on success. */
int tls_parse_client_hello(const uint8_t *buf, size_t len, struct tls_info *out);

/* MD5 as 32 lowercase hex chars (exposed for testing). */
void ja3_md5_hex(const uint8_t *msg, size_t n, char out[33]);
#endif
