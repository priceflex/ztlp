/*
 * ZTLP XDP eBPF Header
 *
 * Shared definitions for the XDP program and userspace loader.
 */

#ifndef ZTLP_XDP_H
#define ZTLP_XDP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Constants */
#define ZTLP_PORT 23095
#define ZTLP_MAGIC 0x5A37
#define HDRLEN_HANDSHAKE 24
#define HDRLEN_DATA 11
#define MSGTYPE_HELLO 0x01

/* Map key/value definitions */
/* SessionID is 12 bytes (96 bits) */
struct session_id {
    __u8 id[12];
};

/* hello rate limiting bucket per source IPv4 */
struct hello_bucket {
    __u64 tokens;            /* current token count */
    __u64 last_refill_ns;    /* timestamp of last refill */
};

/* Statistics index */
enum {
    STAT_LAYER1_DROPS = 0,
    STAT_LAYER2_DROPS,
    STAT_HELLO_RATE_DROPS,
    STAT_PASSED,
    STAT_MAX
};

/* BPF map declarations */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_id);
    __type(value, __u8); /* active flag */
    __uint(max_entries, 1024);
} session_map SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32); /* source IPv4 */
    __type(value, struct hello_bucket);
    __uint(max_entries, 1024);
} hello_rate_map SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
} stats_map SEC("maps");

static __always_inline void increment_stat(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

#endif /* ZTLP_XDP_H */
