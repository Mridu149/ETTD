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

struct flow {
    uint32_t a_ip, b_ip;        /* A = initiator (sent the first packet), network byte order */
    uint16_t a_port, b_port;    /* host byte order */
    uint8_t  proto;
    double   ts_start, ts_end;
    unsigned pkts_out, pkts_in;
    unsigned long bytes_out, bytes_in;
};

static struct flow *flows = NULL;
static size_t nflows = 0, cap = 0;

/* Find the flow this packet belongs to, or create it. Sets *outbound to 1 if
   the packet goes A -> B, 0 if B -> A. */
static struct flow *find_or_create(uint32_t sip, uint32_t dip,
                                   uint16_t sp, uint16_t dp,
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

    if (nflows == cap) {                       /* grow the array when full */
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
    if (h->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;

    const struct ether_header *eth = (const struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;       /* IPv4 only for now */

    const struct ip *ip = (const struct ip *)(bytes + sizeof(struct ether_header));
    unsigned ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len < 20) return;                              /* malformed */

    uint16_t sp = 0, dp = 0;
    const u_char *l4 = (const u_char *)ip + ip_hdr_len;
    size_t avail = h->caplen - sizeof(struct ether_header) - ip_hdr_len;

    if (ip->ip_p == IPPROTO_TCP && avail >= sizeof(struct tcphdr)) {
        const struct tcphdr *t = (const struct tcphdr *)l4;
        sp = ntohs(t->source); dp = ntohs(t->dest);
    } else if (ip->ip_p == IPPROTO_UDP && avail >= sizeof(struct udphdr)) {
        const struct udphdr *u = (const struct udphdr *)l4;
        sp = ntohs(u->source); dp = ntohs(u->dest);
    }

    double ts = h->ts.tv_sec + h->ts.tv_usec / 1e6;
    int outbound;
    struct flow *f = find_or_create(ip->ip_src.s_addr, ip->ip_dst.s_addr,
                                    sp, dp, ip->ip_p, &outbound);

    if (f->pkts_out + f->pkts_in == 0) f->ts_start = ts;
    f->ts_end = ts;

    if (outbound) { f->pkts_out++; f->bytes_out += h->len; }
    else          { f->pkts_in++;  f->bytes_in  += h->len; }
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s file.pcap\n", argv[0]); return 1; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);
    if (!p) { fprintf(stderr, "error: %s\n", errbuf); return 1; }
    if (pcap_datalink(p) != DLT_EN10MB) {
        fprintf(stderr, "not an Ethernet capture\n"); return 1;
    }

    pcap_loop(p, 0, handler, NULL);
    pcap_close(p);

    for (size_t i = 0; i < nflows; i++) {
        struct flow *f = &flows[i];
        char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], pn[8];
        inet_ntop(AF_INET, &f->a_ip, a, sizeof a);
        inet_ntop(AF_INET, &f->b_ip, b, sizeof b);
        if (f->proto == IPPROTO_TCP)      strcpy(pn, "tcp");
        else if (f->proto == IPPROTO_UDP) strcpy(pn, "udp");
        else snprintf(pn, sizeof pn, "p%u", f->proto);

        printf("%s %s:%u <-> %s:%u  pkts out/in=%u/%u  bytes out/in=%lu/%lu  dur=%.3fs\n",
               pn, a, f->a_port, b, f->b_port,
               f->pkts_out, f->pkts_in, f->bytes_out, f->bytes_in,
               f->ts_end - f->ts_start);
    }
    fprintf(stderr, "%zu flows\n", nflows);

    free(flows);
    return 0;
}
