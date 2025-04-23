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

// 1) Counters
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

// 2) Routing LPM-trie
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

// 3) MAC maps
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
    __type(key, __u32); // ifindex
    __type(value, struct ifmac);
} ifmap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32); // IP in network order
    __type(value, struct neighbor);
} neigh_map SEC(".maps");

// 4) XDP program
SEC("xdp")
int router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // a) default drop
    __u32 action = XDP_DROP;
    struct datarec *r = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (r)
    {
        __sync_fetch_and_add(&r->packets, 1);
        __sync_fetch_and_add(&r->bytes, data_end - data);
    }

    // b) parse L2
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return action;
    __u16 hproto = bpf_ntohs(eth->h_proto);
    if (hproto == ETH_P_ARP)
        return XDP_PASS;
    if (hproto != ETH_P_IP)
        return action;

    // c) parse L3
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return action;
    LOG_IP("saw IPv4 pkt, dst", &ip->daddr);

    // d) route key in network order
    __u32 dst = ip->daddr;

    // e) local IPs (return to kernel)
    if (dst == bpf_htonl(0x0A0000FE) || dst == bpf_htonl(0x0A0100FE))
        return XDP_PASS;

    // f) LPM lookup
    struct route_key key = {.prefixlen = 32, .addr = dst};
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

    // g) log & rewrite MACs
    LOG("orig src %pM", eth->h_source);
    LOG("orig dst %pM", eth->h_dest);
    struct ifmac *im = bpf_map_lookup_elem(&ifmap, &nh->ifindex);
    if (im)
        __builtin_memcpy(eth->h_source, im->mac, 6);
    else
        LOG("no ifmap for ifidx %u", nh->ifindex);
    struct neighbor *nm = bpf_map_lookup_elem(&neigh_map, &dst);
    if (nm)
        __builtin_memcpy(eth->h_dest, nm->mac, 6);
    else
        LOG("no neigh for ip %pI4", &dst);
    LOG("new    src %pM", eth->h_source);
    LOG("new    dst %pM", eth->h_dest);

    // h) TTL & checksum
    __u32 old_ttl_be = (__u32)ip->ttl << 8;
    __u32 old_csum32 = (__u32)ip->check;
    __u32 diff = bpf_csum_diff(&old_ttl_be, sizeof(old_ttl_be),
                               &old_csum32, sizeof(old_csum32), 0);
    LOG("old csum 0x%04x diff %u", old_csum32, diff);
    ip->ttl--;
    ip->check = ~(__sum16)diff;
    LOG("new csum 0x%04x", ip->check);

    // i) redirect
    return bpf_redirect(nh->ifindex, 0);
}

char _license[] SEC("license") = "GPL";