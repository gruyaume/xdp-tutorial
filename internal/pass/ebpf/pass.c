#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
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

/* LPM-trie key and value */
struct route_key
{
    __u32 prefixlen;
    __u32 addr; /* network byte order */
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

/*
 * Logging macros:
 *  - LOG: generic
 *  - LOG_IP: prints IPv4 in human format
 */
#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#define LOG_IP(msg, ip) bpf_printk(msg " %pI4\n", ip)

SEC("xdp")
int router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* default drop */
    __u32 action = XDP_DROP;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (rec)
    {
        __sync_fetch_and_add(&rec->packets, 1);
        __sync_fetch_and_add(&rec->bytes, data_end - data);
    }

    /* parse ethernet header */
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return action;
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    /* allow ARP through so kernel can resolve neighbor */
    if (h_proto == ETH_P_ARP)
        return XDP_PASS;
    if (h_proto != ETH_P_IP)
        return action;

    /* parse IPv4 */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return action;

    /* debug: saw IPv4 packet */
    LOG_IP("saw IPv4 pkt, dst", &ip->daddr);

    /* 1) Pass anything destined to 10.0.0.1 right up to the kernel: */
    //  10.0.0.1 in network order is 0x0A000001
    /* Convert dst to host-endian for comparisons/lookups */
    __u32 dst_host = bpf_ntohl(ip->daddr);

    /* 1) Pass anything destined to 10.0.0.1 right up to the kernel */
    const __u32 MY_IP = (10 << 24) | (0 << 16) | (0 << 8) | 1;
    if (dst_host == MY_IP)
    {
        return XDP_PASS;
    }

    /* lookup route */
    struct route_key key = {
        .prefixlen = 32,
        .addr = dst_host, /* use host‐order value */
    };
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

    /* decrement TTL + checksum */
    __u32 old_ttl_be = (__u32)ip->ttl << 8;
    __u32 csum = bpf_csum_diff(&old_ttl_be, sizeof(old_ttl_be),
                               (__be32 *)&ip->check, sizeof(ip->check), 0);
    ip->ttl--;
    ip->check = (__sum16)(~csum);

    /* forward */
    return bpf_redirect(nh->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
