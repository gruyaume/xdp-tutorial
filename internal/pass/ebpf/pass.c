#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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

/* LOG only works with literal fmt strings */
#define LOG(fmt, ...) \
    bpf_printk(fmt "\n", ##__VA_ARGS__)

SEC("xdp")
int pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    if ((long)pkt_len < 0)
    {
        LOG("malformed pkt, data_end < data");
        return XDP_PASS;
    }

    __u32 action = XDP_PASS;
    LOG("received packet, len=%llu, action=%u", pkt_len, action);

    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (!rec)
    {
        LOG("map lookup failed for action %u", action);
        return action;
    }

    /* atomically bump counters */
    __sync_fetch_and_add(&rec->packets, 1);
    __sync_fetch_and_add(&rec->bytes, pkt_len);

    LOG("counters bumped for key %u", action);
    return action;
}

char _license[] SEC("license") = "GPL";
