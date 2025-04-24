// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Logging macros
#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#define LOG_IP(msg, ip) bpf_printk(msg " %pI4\n", ip)

// Constants for checksum unrolling
#define MAX_CSUM_WORDS 30

// IPv4 checksum calculation
static inline __u16 fold_csum(__u32 sum)
{
    // Fold carries
    for (int i = 0; (sum >> 16) && i < 4; i++)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

static __always_inline __u32 sum16(const void *data, __u32 len, const void *end)
{
    __u32 sum = 0;
    const __u16 *ptr = data;
    // Unroll loop for BPF verifier
#pragma unroll 30
    for (int i = 0; i < MAX_CSUM_WORDS; i++)
    {
        if ((2U * i) >= len || ptr + 1 > (__u16 *)end)
            break;
        sum += bpf_ntohs(*ptr++);
    }
    return sum;
}

static inline __u16 compute_checksum(struct iphdr *ip, void *data_end)
{
    __u32 hdr_len = ip->ihl * 4;
    if ((void *)ip + hdr_len > data_end)
        return 0;
    ip->check = 0;
    __u32 sum = sum16(ip, hdr_len, data_end);
    return bpf_htons(fold_csum(sum));
}

// Per-action statistics
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

// LPM trie for IPv4 routing
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

// MAC rewrite maps
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

// XDP entry point
SEC("xdp")
int router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Default to DROP and record stats
    __u32 action = XDP_DROP;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (rec)
    {
        __sync_fetch_and_add(&rec->packets, 1);
        __sync_fetch_and_add(&rec->bytes, data_end - data);
    }

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    __u16 proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_ARP)
        return XDP_PASS;
    if (proto != ETH_P_IP)
        return XDP_DROP;

    // Parse IPv4 header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_DROP;
    LOG_IP("saw IPv4 pkt, dst", &ip->daddr);

    __u32 dst = bpf_ntohl(ip->daddr);
    // Pass local addresses 10.0.0.254 and 10.1.0.254
    if (dst == 0x0A0000FE || dst == 0x0A0100FE)
        return XDP_PASS;

    // Lookup route via LPM
    struct route_key rk = {.prefixlen = 32, .addr = dst};
    struct next_hop *nh = NULL;
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

    // Rewrite MAC addresses
    struct ifmac *src = bpf_map_lookup_elem(&ifmap, &nh->ifindex);
    if (src)
        __builtin_memcpy(eth->h_source, src->mac, 6);
    else
        LOG("missing ifmap for idx %u", nh->ifindex);

    struct neighbor *dst_n = bpf_map_lookup_elem(&neigh_map, &dst);
    if (dst_n)
        __builtin_memcpy(eth->h_dest, dst_n->mac, 6);
    else
        LOG("missing neighbor for dst");

    // Decrement TTL and update checksum
    ip->ttl--;
    ip->check = compute_checksum(ip, data_end);
    LOG("new TTL %u, new csum 0x%04x", ip->ttl, bpf_ntohs(ip->check));

    // Redirect packet
    return bpf_redirect(nh->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
