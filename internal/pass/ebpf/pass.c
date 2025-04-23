#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/* one counter struct per XDP action */
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

/* LPM-trie keys for routing */
struct route_key
{
    __u32 prefixlen; /* subnet mask length in bits */
    __u32 addr;      /* network order IPv4 address */
};

/* next-hop info */
struct next_hop
{
    __u32 ifindex; /* output interface index */
    __u32 gateway; /* next-hop gateway IP (optional) */
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct route_key);
    __type(value, struct next_hop);
} routes_map SEC(".maps");

/* Literal-only logging */
#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)

SEC("xdp")
int router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* increment counters for PASS action */
    __u32 action = XDP_DROP;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (rec)
    {
        __sync_fetch_and_add(&rec->packets, 1);
        __sync_fetch_and_add(&rec->bytes, data_end - data);
    }

    /* parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return action;

    /* parse IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return action;

    /* longest-prefix-match route lookup */
    struct route_key key = {.prefixlen = 32, .addr = ip->daddr};
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
        LOG("no route for dst=0x%08x", ip->daddr);
        return action;
    }
    LOG("route found: dst=0x%08x -> ifindex=%u", ip->daddr, nh->ifindex);

    /* decrement TTL and update IPv4 checksum */
    __u32 old_ttl_be = (__u32)ip->ttl << 8;
    /* cast ip->check to __be32* to match bpf_csum_diff signature */
    __u32 csum = bpf_csum_diff(&old_ttl_be, sizeof(old_ttl_be),
                               (__be32 *)&ip->check, sizeof(ip->check), 0);
    ip->ttl--;
    /* truncate new checksum back to 16 bits */
    ip->check = (__sum16)(~csum);

    /* forward on the selected interface */
    return bpf_redirect(nh->ifindex, 0);
}

char _license[] SEC("license") = "GPL";