/* flows_json.c - read a pcap, group packets into flows, print one JSON line per flow.
 *
 * build:  gcc -Wall -Wextra -o flows_json flows_json.c tls_ja3.c -lpcap
 * run:    ./flows_json capture.pcap > flows.jsonl
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "tls_ja3.h"

#define MAX_PKTS 50          /* how many packets per flow we keep sizes/timings for */

struct flow {
    uint32_t a_ip, b_ip;     /* A = initiator (sent the first packet we saw), network byte order */
    uint16_t a_port, b_port; /* host byte order */
    uint8_t  proto;
    double   ts_start, ts_end;
    unsigned pkts_out, pkts_in;          /* out = A -> B, in = B -> A */
    unsigned long bytes_out, bytes_in;
    unsigned n;                          /* entries used in the three arrays below */
    uint16_t size[MAX_PKTS];             /* frame length in bytes */
    double   iat_ms[MAX_PKTS];           /* ms since the previous packet of this flow (0 for the first) */
    uint8_t  dir[MAX_PKTS];              /* 0 = A -> B, 1 = B -> A */
    struct tls_stream tls;               /* ClientHello collection + result (see tls_ja3.c) */
};

static struct flow *flows = NULL;
static size_t nflows = 0, cap = 0;
static unsigned long skipped = 0;

/* Find the flow this packet belongs to, or create it. *outbound = 1 if A -> B. */
static struct flow *find_or_create(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                                   uint8_t proto, int *outbound)
{
    for (size_t i = 0; i < nflows; i++) {
        struct flow *f = &flows[i];
        if (f->proto != proto) continue;
        if (f->a_ip == sip && f->b_ip == dip && f->a_port == sp && f->b_port == dp) {
            *outbound = 1; return f;
        }
        if (f->a_ip == dip && f->b_ip == sip && f->a_port == dp && f->b_port == sp) {
            *outbound = 0; return f;
        }
    }
    if (nflows == cap) {
        cap = cap ? cap * 2 : 1024;
        flows = realloc(flows, cap * sizeof *flows);
        if (!flows) { perror("realloc"); exit(1); }
    }
    struct flow *f = &flows[nflows++];
    memset(f, 0, sizeof *f);
    f->a_ip = sip;  f->b_ip = dip;
    f->a_port = sp; f->b_port = dp;
    f->proto = proto;
    *outbound = 1;
    return f;
}

static void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    (void)user;
    if (h->caplen < sizeof(struct ether_header) + sizeof(struct ip)) { skipped++; return; }

    /* Copy each header into a local struct: packet bytes are not guaranteed to be aligned. */
    struct ether_header eth_copy;
    memcpy(&eth_copy, bytes, sizeof eth_copy);
    if (ntohs(eth_copy.ether_type) != ETHERTYPE_IP) { skipped++; return; }   /* ARP, IPv6, ... */

    struct ip ip_copy;
    memcpy(&ip_copy, bytes + sizeof(struct ether_header), sizeof ip_copy);
    const struct ip *ip = &ip_copy;
    unsigned ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len < 20 || sizeof(struct ether_header) + ip_hdr_len > h->caplen) { skipped++; return; }

    const u_char *l4 = bytes + sizeof(struct ether_header) + ip_hdr_len;
    size_t avail = h->caplen - sizeof(struct ether_header) - ip_hdr_len;
    int is_fragment = (ntohs(ip->ip_off) & IP_OFFMASK) != 0;   /* later fragments carry no ports */

    uint16_t sp = 0, dp = 0;
    if (ip->ip_p == IPPROTO_TCP) {
        if (is_fragment || avail < sizeof(struct tcphdr)) { skipped++; return; }
        struct tcphdr tcp_copy;
        memcpy(&tcp_copy, l4, sizeof tcp_copy);
        sp = ntohs(tcp_copy.source); dp = ntohs(tcp_copy.dest);
    } else if (ip->ip_p == IPPROTO_UDP) {
        if (is_fragment || avail < sizeof(struct udphdr)) { skipped++; return; }
        struct udphdr udp_copy;
        memcpy(&udp_copy, l4, sizeof udp_copy);
        sp = ntohs(udp_copy.source); dp = ntohs(udp_copy.dest);
    }

    double ts = h->ts.tv_sec + h->ts.tv_usec / 1e6;
    int outbound;
    struct flow *f = find_or_create(ip->ip_src.s_addr, ip->ip_dst.s_addr, sp, dp, ip->ip_p, &outbound);

    int first = (f->pkts_out + f->pkts_in == 0);
    double iat = first ? 0.0 : (ts - f->ts_end) * 1000.0;
    if (iat < 0) iat = 0;                       /* packets slightly out of order */

    if (first) f->ts_start = ts;
    f->ts_end = ts;

    if (outbound) { f->pkts_out++; f->bytes_out += h->len; }
    else          { f->pkts_in++;  f->bytes_in  += h->len; }

    if (f->n < MAX_PKTS) {
        f->size[f->n]   = (uint16_t)(h->len > 65535 ? 65535 : h->len);
        f->iat_ms[f->n] = iat;
        f->dir[f->n]    = outbound ? 0 : 1;
        f->n++;
    }

    /* TLS: the client (the side that sent the first packet) sends the ClientHello */
    if (ip->ip_p == IPPROTO_TCP && outbound) {
        struct tcphdr t;
        memcpy(&t, l4, sizeof t);                     /* TCP header size was checked above */
        size_t thl = (size_t)t.doff * 4, plen = 0;
        size_t iplen = ntohs(ip->ip_len);
        if (thl >= sizeof(struct tcphdr) && thl <= avail && iplen >= ip_hdr_len + thl) {
            plen = iplen - ip_hdr_len - thl;          /* use the IP length: Ethernet may add padding */
            if (plen > avail - thl) plen = avail - thl;
        }
        tls_stream_feed(&f->tls, t.syn && !t.ack, ntohl(t.seq), l4 + thl, plen);
    }
}

static void print_flow(const struct flow *f)
{
    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], pn[16];
    inet_ntop(AF_INET, &f->a_ip, a, sizeof a);
    inet_ntop(AF_INET, &f->b_ip, b, sizeof b);
    if      (f->proto == IPPROTO_TCP)  strcpy(pn, "tcp");
    else if (f->proto == IPPROTO_UDP)  strcpy(pn, "udp");
    else if (f->proto == IPPROTO_ICMP) strcpy(pn, "icmp");
    else snprintf(pn, sizeof pn, "ip%u", f->proto);

    printf("{\"flow_id\":\"%s:%u-%s:%u-%s\",\"ts_start\":%.6f,\"ts_end\":%.6f,"
           "\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"proto\":\"%s\","
           "\"pkts_out\":%u,\"pkts_in\":%u,\"bytes_out\":%lu,\"bytes_in\":%lu,",
           a, f->a_port, b, f->b_port, pn, f->ts_start, f->ts_end,
           a, b, f->a_port, f->b_port, pn,
           f->pkts_out, f->pkts_in, f->bytes_out, f->bytes_in);

    printf("\"pkt_sizes\":[");
    for (unsigned i = 0; i < f->n; i++) printf("%s%u", i ? "," : "", f->size[i]);
    printf("],\"iat_ms\":[");
    for (unsigned i = 0; i < f->n; i++) printf("%s%.3f", i ? "," : "", f->iat_ms[i]);
    printf("],\"pkt_dirs\":[");
    for (unsigned i = 0; i < f->n; i++) printf("%s%u", i ? "," : "", f->dir[i]);
    printf("],\"tls\":");
    if (f->tls.info.valid) {
        printf("{\"version\":\"%s\",\"sni\":", f->tls.info.version);
        if (f->tls.info.sni[0]) printf("\"%s\"", f->tls.info.sni); else printf("null");
        printf(",\"ja3\":\"%s\"}", f->tls.info.ja3);
    } else {
        printf("null");
    }
    printf(",\"dns\":null}\n");
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s file.pcap > flows.jsonl\n", argv[0]); return 1; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);
    if (!p) { fprintf(stderr, "error: %s\n", errbuf); return 1; }
    if (pcap_datalink(p) != DLT_EN10MB) {
        fprintf(stderr, "not an Ethernet capture\n"); return 1;
    }

    pcap_loop(p, 0, handler, NULL);
    pcap_close(p);

    for (size_t i = 0; i < nflows; i++) print_flow(&flows[i]);
    fprintf(stderr, "%zu flows written, %lu packets skipped (non-IPv4 or truncated)\n", nflows, skipped);

    for (size_t i = 0; i < nflows; i++) tls_stream_free(&flows[i].tls);
    free(flows);
    return 0;
}
