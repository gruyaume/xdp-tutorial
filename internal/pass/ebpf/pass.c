// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#define LOG_IP(msg, ip) bpf_printk(msg " %pI4\n", ip)

/*----------------------------------------------------------
 * IPv4 checksum helpers
 *---------------------------------------------------------*/
#define MAX_CHECKING 4    /* bound for carry folding */
#define MAX_CSUM_WORDS 30 /* up to a 60-byte IPv4 header */

static inline __u16 csum_fold_helper(__u32 csum)
{
    for (__u8 i = 0; (csum >> 16) && i < MAX_CHECKING; i++)
        csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

static __always_inline __u32 sum16(const void *data,
                                   __u32 size,
                                   const void *data_end)
{
    __u32 s = 0;
    __u16 *buf = (__u16 *)data;

/* force a 30-way unroll */
#pragma unroll 30
    for (int i = 0; i < MAX_CSUM_WORDS; i++)
    {
        if ((__u32)(2 * i) >= size)
            break;
        if ((void *)(buf + 1) > data_end)
            return 0;
        s += *buf++;
    }

    return s;
}

static inline __u16 ip_checksum(void *data, void *data_end)
{
    struct iphdr *ip = data;
    __u32 hdr_len = ip->ihl * 4;

    /* bounds-check full header */
    if ((void *)ip + hdr_len > data_end)
        return 0;

    /* zero old checksum */
    ip->check = 0;

    /* sum & fold, then convert to network order */
    __u32 raw = sum16(ip, hdr_len, data_end);
    return bpf_htons(csum_fold_helper(raw));
}

/*----------------------------------------------------------
 * Maps
 *---------------------------------------------------------*/

// 1) Per-action counters
struct datarec
{
    __u64 packets, bytes;
};
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, XDP_REDIRECT + 1);
} xdp_stats_map SEC(".maps");

// 2) LPM-trie for routing
struct route_key
{
    __u32 prefixlen, addr;
};
struct next_hop
{
    __u32 ifindex, gateway;
};
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct route_key);
    __type(value, struct next_hop);
} routes_map SEC(".maps");

// 3) MAC-rewrite helpers
struct ifmac
{
    __u8 mac[6];
};
struct neighbor
{
    __u8 mac[6];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct ifmac);
} ifmap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct neighbor);
} neigh_map SEC(".maps");

/*----------------------------------------------------------
 * XDP entry point
 *---------------------------------------------------------*/
SEC("xdp")
int router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 0) DROP by default, bump counter
    __u32 act = XDP_DROP;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &act);
    if (rec)
    {
        __sync_fetch_and_add(&rec->packets, 1);
        __sync_fetch_and_add(&rec->bytes, data_end - data);
    }

    // 1) Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto == ETH_P_ARP)
        return XDP_PASS;
    if (h_proto != ETH_P_IP)
        return XDP_DROP;

    // 2) Parse IPv4
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_DROP;
    LOG_IP("saw IPv4 pkt, dst", &ip->daddr);

    __u32 dst = bpf_ntohl(ip->daddr);
    // pass router-local addrs 10.0.0.254, 10.1.0.254
    if (dst == 0x0A0000FE || dst == 0x0A0100FE)
        return XDP_PASS;

    // 3) LPM lookup
    struct route_key rk = {.prefixlen = 32, .addr = dst};
    struct next_hop *nh = NULL;
#pragma unroll
    for (int i = 32; i > 0; i--)
    {
        rk.prefixlen = i;
        nh = bpf_map_lookup_elem(&routes_map, &rk);
        if (nh)
            break;
    }
    if (!nh)
    {
        LOG_IP("no route for dst", &ip->daddr);
        return XDP_DROP;
    }
    LOG("-> ifindex %u, gateway %pI4", nh->ifindex, &nh->gateway);

    // 4) Rewrite L2
    struct ifmac *src = bpf_map_lookup_elem(&ifmap, &nh->ifindex);
    if (src)
        __builtin_memcpy(eth->h_source, src->mac, 6);
    else
        LOG("missing ifmap for idx %u", nh->ifindex);

    struct neighbor *dst_n = bpf_map_lookup_elem(&neigh_map, &dst);
    if (dst_n)
        __builtin_memcpy(eth->h_dest, dst_n->mac, 6);
    else
        LOG("missing neigh for %pI4", &dst);

    // 5) TTL-- + full IPv4 checksum recompute
    ip->ttl--;
    ip->check = ip_checksum(ip, data_end);
    LOG("new TTL %u, new csum 0x%04x", ip->ttl, bpf_ntohs(ip->check));

    // 6) Redirect out the chosen interface
    return bpf_redirect(nh->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
