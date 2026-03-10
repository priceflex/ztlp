#include <linux/bpf.h>
#include "ztlp_xdp.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int ztlp_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    /* IP */
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    __be32 src_ip = ip->saddr;

    /* UDP */
    __u32 ihl = ip->ihl * 4;
    struct udphdr *udp = (void *)ip + ihl;
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(udp->dest) != ZTLP_PORT)
        return XDP_PASS;

    /* Payload */
    unsigned char *payload = (unsigned char *)(udp + 1);
    if (payload + 2 > data_end) {
        increment_stat(STAT_LAYER1_DROPS);
        return XDP_DROP;
    }
    __u16 magic = *(__u16 *)payload;
    magic = bpf_ntohs(magic);
    if (magic != ZTLP_MAGIC) {
        increment_stat(STAT_LAYER1_DROPS);
        return XDP_DROP;
    }

    if (payload + 4 > data_end) {
        increment_stat(STAT_LAYER1_DROPS);
        return XDP_DROP;
    }
    __u16 ver_hdr = *(__u16 *)(payload + 2);
    __u16 hdrlen = bpf_ntohs(ver_hdr) & 0x0FFF; // lower 12 bits

    __u32 sess_offset;
    if (hdrlen == HDRLEN_HANDSHAKE)
        sess_offset = 11;
    else if (hdrlen == HDRLEN_DATA)
        sess_offset = 6;
    else {
        increment_stat(STAT_LAYER2_DROPS);
        return XDP_DROP;
    }

    if (payload + sess_offset + 12 > data_end) {
        increment_stat(STAT_LAYER2_DROPS);
        return XDP_DROP;
    }
    struct session_id sid = {};
    __builtin_memcpy(sid.id, payload + sess_offset, 12);

    __u8 *active = bpf_map_lookup_elem(&session_map, &sid);
    if (active) {
        increment_stat(STAT_PASSED);
        return XDP_PASS;
    }

    /* HELLO handling */
    __u8 msgtype = 0;
    if (hdrlen == HDRLEN_HANDSHAKE) {
        if (payload + 7 > data_end) {
            increment_stat(STAT_LAYER2_DROPS);
            return XDP_DROP;
        }
        msgtype = *(payload + 6);
    }
    if (msgtype != MSGTYPE_HELLO) {
        increment_stat(STAT_LAYER2_DROPS);
        return XDP_DROP;
    }

    /* Rate limiting */
    struct hello_bucket *bucket = bpf_map_lookup_elem(&hello_rate_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();
    const __u64 refill_interval_ns = 100000000ULL; // 0.1s per token => 10 per sec
    const __u64 capacity = 10ULL;

    if (!bucket) {
        struct hello_bucket init = {
            .tokens = capacity - 1,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&hello_rate_map, &src_ip, &init, BPF_ANY);
        increment_stat(STAT_PASSED);
        return XDP_PASS;
    }

    // Refill tokens
    __u64 elapsed = now - bucket->last_refill_ns;
    if (elapsed >= refill_interval_ns) {
        __u64 add = elapsed / refill_interval_ns;
        __u64 new_tokens = bucket->tokens + add;
        if (new_tokens > capacity)
            new_tokens = capacity;
        bucket->tokens = new_tokens;
        bucket->last_refill_ns = now;
    }

    if (bucket->tokens == 0) {
        increment_stat(STAT_HELLO_RATE_DROPS);
        return XDP_DROP;
    }
    bucket->tokens--;
    bucket->last_refill_ns = now;
    increment_stat(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
