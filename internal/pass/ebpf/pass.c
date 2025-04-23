#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#define LOG_IP(msg, ip) bpf_printk(msg " %pI4\n", ip)

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

// 1) Per-action counters
struct datarec
{
    __u64 packets;
    __u64 bytes;
};
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

// 2) LPM-trie for routing
struct route_key
{
    __u32 prefixlen;
    __u32 addr;
};
struct next_hop
{
    __u32 ifindex;
    __u32 gateway;
};
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct route_key);
    __type(value, struct next_hop);
} routes_map SEC(".maps");

// 3) MAC-rewrite helper maps
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

// 4) XDP entry point
SEC("xdp")
int router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 4.a) Default-DROP, bump DROP counter
    __u32 action = XDP_DROP;
    struct datarec *r = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (r)
    {
        __sync_fetch_and_add(&r->packets, 1);
        __sync_fetch_and_add(&r->bytes, data_end - data);
    }

    // 4.b) L2 parse
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return action;
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto == ETH_P_ARP)
        return XDP_PASS;
    if (h_proto != ETH_P_IP)
        return action;

    // 4.c) L3 parse
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return action;
    LOG_IP("saw IPv4 pkt, dst", &ip->daddr);

    // 4.d) Compute host-order dst
    __u32 dst_host = bpf_ntohl(ip->daddr);

    // 4.e) Pass router-local IPs
    __be32 r1 = (__be32)bpf_htonl((10 << 24) | (0 << 16) | (0 << 8) | 254);
    __be32 r2 = (__be32)bpf_htonl((10 << 24) | (1 << 16) | (0 << 8) | 254);
    if (ip->daddr == r1 || ip->daddr == r2)
        return XDP_PASS;

    // 4.f) LPM-trie lookup
    struct route_key key = {.prefixlen = 32, .addr = dst_host};
    struct next_hop *nh = NULL;
#pragma unroll
    for (int i = 32; i > 0; i--)
    {
        key.prefixlen = i;
        nh = bpf_map_lookup_elem(&routes_map, &key);
        if (nh)
            break;
    }
    if (!nh)
    {
        LOG_IP("no route for dst", &ip->daddr);
        return action;
    }
    LOG_IP("route found for dst", &ip->daddr);
    LOG("-> ifindex %u, gateway %pI4", nh->ifindex, &nh->gateway);

    // 4.g) Rewrite Ethernet header
    // Log original MACs
    LOG("orig src %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    LOG("orig dst %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    struct ifmac *src = bpf_map_lookup_elem(&ifmap, &nh->ifindex);
    if (!src)
    {
        LOG("missing ifmap entry for ifindex %u", nh->ifindex);
    }
    else
    {
        __builtin_memcpy(eth->h_source, src->mac, 6);
    }
    struct neighbor *dst = bpf_map_lookup_elem(&neigh_map, &nh->gateway);
    if (!dst)
    {
        LOG("missing neigh entry for gateway %pI4", &nh->gateway);
    }
    else
    {
        __builtin_memcpy(eth->h_dest, dst->mac, 6);
    }

    // Log new MACs
    LOG("new    src %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    LOG("new    dst %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // 4.h) Manual TTL decrement + checksum fix
    __u32 old_ttl_be = (__u32)ip->ttl << 8;
    __u32 old_csum32 = (__u32)ip->check;
    __u32 csum_diff = bpf_csum_diff(&old_ttl_be, sizeof(old_ttl_be),
                                    &old_csum32, sizeof(old_csum32), 0);
    // Log checksum before
    LOG("old csum 0x%04x, diff %u", old_csum32, csum_diff);
    ip->ttl--;
    ip->check = ~(__sum16)csum_diff;
    // Log checksum after
    LOG("new csum 0x%04x", ip->check);

    // 4.i) Redirect
    return bpf_redirect(nh->ifindex, 0);
}

char _license[] SEC("license") = "GPL";