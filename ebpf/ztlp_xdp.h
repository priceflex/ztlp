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

/* Inter-relay mesh port — separate from the client-facing port.
 * Mesh traffic (discovery, sync, forwarding) uses this port so that
 * the XDP program can apply different admission logic (peer allowlist
 * instead of SessionID lookup). */
#define ZTLP_MESH_PORT 23096

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

/* ── Inter-relay mesh constants ──────────────────────────────────── */

/* Inter-relay message types — first byte of mesh UDP payload.
 * These map to the Elixir constants in ZtlpRelay.InterRelay:
 *   0x01 RELAY_HELLO, 0x02 RELAY_HELLO_ACK, 0x03 RELAY_PING,
 *   0x04 RELAY_PONG, 0x05 RELAY_FORWARD, 0x06 RELAY_SESSION_SYNC,
 *   0x07 RELAY_LEAVE, 0x08 RELAY_DRAIN, 0x09 RELAY_DRAIN_CANCEL */
#define MESH_MSG_JOIN          0x01
#define MESH_MSG_SYNC          0x02
#define MESH_MSG_PING          0x03
#define MESH_MSG_PONG          0x04
#define MESH_MSG_FORWARD       0x05
#define MESH_MSG_SESSION       0x06
#define MESH_MSG_LEAVE         0x07
#define MESH_MSG_DRAIN         0x08
#define MESH_MSG_DRAIN_CANCEL  0x09

/* Mesh common header size: type(1) + sender_node_id(16) + timestamp(8) = 25 */
#define MESH_COMMON_HEADER_SIZE 25

/* FORWARD-specific fields after the common header:
 *   ttl(1) + path_len(1) = 2 bytes before the variable-length path
 *   Then: path(path_len * 16) + inner_len(4) + inner(variable) */
#define MESH_FORWARD_FIXED_SIZE  (MESH_COMMON_HEADER_SIZE + 2)  /* 27 bytes to ttl+path_len */

/* Relay Admission Token (RAT) size — 93 bytes.
 * Structure: version(1) + NodeID(16) + IssuerID(16) + IssuedAt(8) +
 *            ExpiresAt(8) + SessionScope(12) + MAC(32) = 93
 * RATs are present in HELLO extension areas for transit relay admission.
 * Actual RAT verification (HMAC-BLAKE2s) is too expensive for XDP —
 * we only check for RAT presence and size here. */
#define RAT_SIZE 93

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

/*
 * Mesh peer NodeID — 128-bit identifier for authorized relay nodes.
 * Used as the key in mesh_peer_map to allowlist mesh peers.
 * Corresponds to the 16-byte sender_node_id in inter-relay messages.
 */
struct mesh_peer_id {
    __u8 id[16];  /* 128-bit NodeID */
};

/* ── Statistics counters ─────────────────────────────────────────── */

/*
 * Per-CPU stat indices for the stats_map.  Using PERCPU_ARRAY avoids
 * lock contention — each CPU core has its own counter copy.  The
 * userspace loader sums across CPUs when reporting.
 *
 * NOTE: New counters are appended at the end to maintain backward
 * compatibility with existing stats_map entries 0–3.  The max_entries
 * of stats_map changes from 4 (old STAT_MAX) to 8 (new STAT_MAX),
 * which requires reloading the BPF program.
 */
enum {
    STAT_LAYER1_DROPS = 0,       /* Bad magic — not a ZTLP packet at all */
    STAT_LAYER2_DROPS,           /* Valid magic but unknown SessionID */
    STAT_HELLO_RATE_DROPS,       /* HELLO packet from a rate-limited source IP */
    STAT_PASSED,                 /* Packet passed all checks → XDP_PASS to kernel stack */
    STAT_MESH_PASSED,            /* Mesh packet passed peer allowlist check */
    STAT_MESH_PEER_DROPS,        /* Mesh packet from unauthorized (unknown) peer */
    STAT_MESH_FORWARD_PASSED,    /* Forwarded mesh packet passed inner ZTLP magic check */
    STAT_RAT_HELLO_PASSED,       /* HELLO with RAT-sized extension passed */
    STAT_MAX                     /* Sentinel — also used as max_entries for the array map */
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
 * mesh_peer_map — allowlist of authorized relay NodeIDs.
 *
 * Key:   16-byte NodeID (struct mesh_peer_id)
 * Value: __u8 flag (presence is the check; value is always 1)
 *
 * Populated by userspace when mesh peers are discovered via RELAY_HELLO
 * exchanges or manual configuration.  The XDP program checks incoming
 * mesh packets against this map — unknown sender NodeIDs are dropped
 * before reaching the relay daemon.
 *
 * max_entries 256 is generous for typical mesh deployments.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mesh_peer_id);
    __type(value, __u8);
    __uint(max_entries, 256);
} mesh_peer_map SEC("maps");

/*
 * rat_bypass_map — configuration flags for RAT-aware HELLO handling.
 *
 * Key:   __u32 flag index (currently only index 0 used)
 * Value: __u8 (0 = RAT HELLOs go through rate limiter, 1 = bypass)
 *
 * When flag[0] == 1, HELLO packets that carry a valid-sized RAT
 * bypass the per-source-IP rate limiter.  This allows pre-authenticated
 * nodes (those with RATs from an ingress relay) to avoid being throttled
 * during reconnection bursts.
 *
 * Default: 0 (RAT HELLOs still rate-limited — safe default).
 * Set to 1 via the loader for deployments that trust RAT presence.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} rat_bypass_map SEC("maps");

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
