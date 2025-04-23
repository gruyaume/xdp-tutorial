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

SEC("xdp")
int pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* calculate packet length */
    __u64 pkt_len = data_end - data;
    if ((long)pkt_len < 0)
        return XDP_PASS; /* malformed, just pass */

    /* choose action—here always PASS, but you could branch */
    __u32 action = XDP_PASS;

    /* lookup the counter for this action */
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (rec)
    {
        /* atomic updates */
        __sync_fetch_and_add(&rec->packets, 1);
        __sync_fetch_and_add(&rec->bytes, pkt_len);
    }

    return action;
}

char _license[] SEC("license") = "GPL";
