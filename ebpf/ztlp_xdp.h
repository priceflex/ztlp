/*
 * ZTLP XDP eBPF Header — ztlp_xdp.h
 *
 * Shared definitions between the XDP kernel program (ztlp_xdp.c) and
 * the userspace loader (loader.c).  Both sides include this header to
 * ensure consistent map layouts, key/value structs, and constants.
 *
 * ZTLP and Zero Trust Layer Protocol are trademarks of Steven Price.
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#ifndef ZTLP_XDP_H
#define ZTLP_XDP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── Protocol constants ──────────────────────────────────────────── */

/* Default ZTLP UDP port — 23095 decimal = 0x5A37, matching the magic. */
#define ZTLP_PORT 23095

/* ZTLP magic bytes — first 16 bits of every valid ZTLP packet ('Z7').
 * A single compare at this offset is enough to reject ~99.99% of non-ZTLP
 * UDP traffic at near-zero cost (Layer 1 of the admission pipeline). */
#define ZTLP_MAGIC 0x5A37

/* HdrLen field values — encoded in bits [11:0] of the Ver|HdrLen word.
 * Used to discriminate packet type:
 *   24 = handshake header (95 bytes) — carries HELLO/HELLO_ACK/REKEY etc.
 *   11 = compact data header (42 bytes) — steady-state encrypted traffic */
#define HDRLEN_HANDSHAKE 24
#define HDRLEN_DATA 11

/* MsgType byte for HELLO (first handshake message).
 * HELLOs are rate-limited rather than session-checked, since they
 * establish new sessions and have no prior SessionID to look up. */
#define MSGTYPE_HELLO 0x01

/* ── Map key/value structures ────────────────────────────────────── */

/*
 * SessionID — 96 bits (12 bytes), randomly generated during handshake.
 * This is the routing key for the admission pipeline's Layer 2 check:
 * if a packet's SessionID isn't in the BPF hash map, it's dropped
 * before any cryptographic work occurs.
 */
struct session_id {
    __u8 id[12];
};

/*
 * Token bucket for per-source-IP HELLO rate limiting.
 * Prevents volumetric HELLO floods from exhausting the handshake path.
 * Each source IP gets its own bucket; tokens refill at a constant rate.
 */
struct hello_bucket {
    __u64 tokens;            /* current token count (0 = exhausted → drop) */
    __u64 last_refill_ns;    /* ktime_ns of last refill — used to compute elapsed time */
};

/* ── Statistics counters ─────────────────────────────────────────── */

/*
 * Per-CPU stat indices for the stats_map.  Using PERCPU_ARRAY avoids
 * lock contention — each CPU core has its own counter copy.  The
 * userspace loader sums across CPUs when reporting.
 */
enum {
    STAT_LAYER1_DROPS = 0,   /* Bad magic — not a ZTLP packet at all */
    STAT_LAYER2_DROPS,       /* Valid magic but unknown SessionID */
    STAT_HELLO_RATE_DROPS,   /* HELLO packet from a rate-limited source IP */
    STAT_PASSED,             /* Packet passed all checks → XDP_PASS to kernel stack */
    STAT_MAX                 /* Sentinel — also used as max_entries for the array map */
};

/* ── BPF map definitions ─────────────────────────────────────────
 *
 * These BTF-style map definitions are shared between kernel and userspace.
 * The kernel program uses them directly; the loader discovers them via
 * libbpf's skeleton or bpf_object__find_map_by_name().
 * ──────────────────────────────────────────────────────────────── */

/*
 * session_map — O(1) hash lookup for the Layer 2 SessionID check.
 * Key:   12-byte SessionID (struct session_id)
 * Value: __u8 flag (presence is what matters; value is always 1)
 * The userspace loader populates this when sessions are established
 * and removes entries on session close/timeout.
 * max_entries 1024 is a starting point — production deployments
 * should tune this to expected concurrent sessions.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_id);
    __type(value, __u8);
    __uint(max_entries, 1024);
} session_map SEC("maps");

/*
 * hello_rate_map — per-source-IPv4 token bucket for HELLO rate limiting.
 * Key:   __be32 source IP (network byte order, straight from IP header)
 * Value: struct hello_bucket (tokens + last_refill_ns)
 * Prevents a single IP from flooding HELLO packets to exhaust the
 * handshake processing path.  The XDP program refills tokens based on
 * elapsed nanoseconds since last_refill_ns.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct hello_bucket);
    __uint(max_entries, 1024);
} hello_rate_map SEC("maps");

/*
 * stats_map — per-CPU counters indexed by the enum above.
 * BPF_MAP_TYPE_PERCPU_ARRAY gives each CPU its own copy, eliminating
 * atomic contention on the hot path.  Userspace reads all CPU copies
 * and sums them for aggregate stats.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
} stats_map SEC("maps");

/*
 * increment_stat — atomically bump a per-CPU counter.
 * __always_inline ensures the BPF verifier sees this as straight-line
 * code rather than a function call (eBPF has limited call support).
 */
static __always_inline void increment_stat(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

#endif /* ZTLP_XDP_H */
