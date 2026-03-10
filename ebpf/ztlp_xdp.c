/*
 * ZTLP XDP Packet Filter — ztlp_xdp.c
 *
 * eBPF/XDP program implementing the first two layers of the ZTLP admission
 * pipeline directly in the NIC driver, before packets reach the kernel
 * network stack.  This is "Profile 1 — Software Enforcement" from the
 * ZTLP spec §13.1.
 *
 * Decision flow:
 *   1. Non-UDP / non-ZTLP-port traffic → XDP_PASS (not our concern)
 *   2. Layer 1: Magic 0x5A37 check → XDP_DROP on failure
 *   3. Layer 2: HdrLen-based SessionID extraction → BPF hash map lookup
 *      - Known SessionID → XDP_PASS
 *      - HELLO message → rate-limit check → XDP_PASS or XDP_DROP
 *      - Unknown SessionID, not HELLO → XDP_DROP
 *
 * Layer 3 (HeaderAuthTag AEAD verification) is NOT done here — it requires
 * session keys and ChaCha20-Poly1305, which is too expensive for XDP and
 * would require the kernel to hold secret key material.  Layer 3 runs in
 * the userspace ZTLP daemon after the packet passes the kernel stack.
 *
 * ZTLP and Zero Trust Layer Protocol are trademarks of Steven Price.
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#include <linux/bpf.h>
#include "ztlp_xdp.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/*
 * ztlp_xdp_prog — main XDP entry point.
 *
 * Attached to a network interface via XDP_FLAGS_SKB_MODE or native mode.
 * Processes every incoming packet before the kernel allocates an sk_buff.
 *
 * Returns:
 *   XDP_PASS — packet continues to kernel network stack (non-ZTLP or valid)
 *   XDP_DROP — packet silently discarded at the driver level
 */
SEC("xdp")
int ztlp_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Parse Ethernet header ────────────────────────────────────
     * Every bounds check is mandatory — the BPF verifier rejects
     * programs that access memory beyond data_end.  We XDP_PASS
     * anything we can't parse or that isn't IP/UDP, since it's not
     * ZTLP traffic and might be legitimate (ARP, ICMP, etc.).
     * ──────────────────────────────────────────────────────────── */
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;  // Not IPv4 — let it through

    /* ── Parse IP header ──────────────────────────────────────── */
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;  // Not UDP — let it through

    /* Save source IP for rate limiting (needed later for HELLO checks) */
    __be32 src_ip = ip->saddr;

    /* ── Parse UDP header ─────────────────────────────────────── */
    __u32 ihl = ip->ihl * 4;  // IP header length in bytes (variable due to options)
    struct udphdr *udp = (void *)ip + ihl;
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(udp->dest) != ZTLP_PORT)
        return XDP_PASS;  // Not destined for ZTLP port — let it through

    /* ── ZTLP payload starts here ─────────────────────────────── */
    unsigned char *payload = (unsigned char *)(udp + 1);

    /* ── LAYER 1: Magic byte check ────────────────────────────────
     * Cost: single 16-bit comparison, nanoseconds, zero crypto.
     * Rejects ~99.99% of non-ZTLP UDP traffic that happens to
     * arrive on port 23095 (scanners, misconfigurations, etc.).
     * ──────────────────────────────────────────────────────────── */
    if (payload + 2 > data_end) {
        increment_stat(STAT_LAYER1_DROPS);
        return XDP_DROP;  // Too short to even contain magic
    }
    __u16 magic = *(__u16 *)payload;
    magic = bpf_ntohs(magic);
    if (magic != ZTLP_MAGIC) {
        increment_stat(STAT_LAYER1_DROPS);
        return XDP_DROP;  // Bad magic — not a ZTLP packet
    }

    /* ── LAYER 2: SessionID lookup ────────────────────────────────
     * Cost: O(1) BPF hash map read, microseconds, zero crypto.
     *
     * Step 1: Read the Ver|HdrLen word to determine packet type.
     * The HdrLen field (lower 12 bits) tells us where the SessionID
     * lives in the header:
     *   HdrLen 24 (handshake) → SessionID at byte offset 11
     *   HdrLen 11 (data)      → SessionID at byte offset 6
     * ──────────────────────────────────────────────────────────── */
    if (payload + 4 > data_end) {
        increment_stat(STAT_LAYER1_DROPS);
        return XDP_DROP;  // Can't read Ver|HdrLen
    }
    __u16 ver_hdr = *(__u16 *)(payload + 2);
    __u16 hdrlen = bpf_ntohs(ver_hdr) & 0x0FFF;  // Lower 12 bits = HdrLen

    /* Determine SessionID byte offset based on header type */
    __u32 sess_offset;
    if (hdrlen == HDRLEN_HANDSHAKE)
        sess_offset = 11;   // Handshake: after magic(2)+verhdr(2)+flags(2)+msgtype(1)+crypto(2)+keyid(2)
    else if (hdrlen == HDRLEN_DATA)
        sess_offset = 6;    // Data: after magic(2)+verhdr(2)+flags(2)
    else {
        increment_stat(STAT_LAYER2_DROPS);
        return XDP_DROP;  // Unknown header type — reject
    }

    /* Extract the 12-byte SessionID from the packet */
    if (payload + sess_offset + 12 > data_end) {
        increment_stat(STAT_LAYER2_DROPS);
        return XDP_DROP;  // Truncated — can't read SessionID
    }
    struct session_id sid = {};
    __builtin_memcpy(sid.id, payload + sess_offset, 12);

    /* Look up SessionID in the BPF hash map — O(1) */
    __u8 *active = bpf_map_lookup_elem(&session_map, &sid);
    if (active) {
        /* Known session — pass to kernel stack for Layer 3 (AEAD) check */
        increment_stat(STAT_PASSED);
        return XDP_PASS;
    }

    /* ── HELLO handling ───────────────────────────────────────────
     * SessionID wasn't found.  The only legitimate reason is a HELLO
     * (first handshake message) which establishes a NEW session.
     * HELLOs can't be in the map yet because the session doesn't exist.
     * Non-HELLO packets with unknown SessionIDs are always dropped.
     * ──────────────────────────────────────────────────────────── */
    __u8 msgtype = 0;
    if (hdrlen == HDRLEN_HANDSHAKE) {
        /* MsgType is at byte offset 6 in the handshake header */
        if (payload + 7 > data_end) {
            increment_stat(STAT_LAYER2_DROPS);
            return XDP_DROP;
        }
        msgtype = *(payload + 6);
    }
    if (msgtype != MSGTYPE_HELLO) {
        /* Not a HELLO and SessionID unknown → drop */
        increment_stat(STAT_LAYER2_DROPS);
        return XDP_DROP;
    }

    /* ── HELLO rate limiting (token bucket) ───────────────────────
     * Prevents volumetric HELLO floods.  Each source IP gets a bucket
     * with capacity=10 tokens, refilling at 1 token per 100ms (= 10/sec).
     * This limits the handshake processing path without blocking
     * legitimate new connections.
     * ──────────────────────────────────────────────────────────── */
    struct hello_bucket *bucket = bpf_map_lookup_elem(&hello_rate_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();
    const __u64 refill_interval_ns = 100000000ULL;  // 100ms = 0.1s per token → 10 tokens/sec
    const __u64 capacity = 10ULL;                    // Max burst size

    if (!bucket) {
        /* First HELLO from this IP — create a new bucket */
        struct hello_bucket init = {
            .tokens = capacity - 1,   // Consume one token for this packet
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&hello_rate_map, &src_ip, &init, BPF_ANY);
        increment_stat(STAT_PASSED);
        return XDP_PASS;
    }

    /* Refill tokens based on elapsed time since last refill */
    __u64 elapsed = now - bucket->last_refill_ns;
    if (elapsed >= refill_interval_ns) {
        __u64 add = elapsed / refill_interval_ns;
        __u64 new_tokens = bucket->tokens + add;
        if (new_tokens > capacity)
            new_tokens = capacity;  // Cap at bucket capacity
        bucket->tokens = new_tokens;
        bucket->last_refill_ns = now;
    }

    /* Consume a token — drop if empty */
    if (bucket->tokens == 0) {
        increment_stat(STAT_HELLO_RATE_DROPS);
        return XDP_DROP;  // Rate limit exceeded for this source IP
    }
    bucket->tokens--;
    bucket->last_refill_ns = now;
    increment_stat(STAT_PASSED);
    return XDP_PASS;
}

/*
 * License string — required by the kernel for BPF programs that use
 * GPL-only helper functions (bpf_ktime_get_ns, etc.).
 *
 * "Dual MIT/GPL" means: the eBPF program source is MIT-licensed, but it
 * declares GPL compatibility so the kernel allows loading.  This is
 * standard practice for eBPF (used by Cilium, Cloudflare, Meta) and is
 * consistent with the Linux kernel's syscall exception — eBPF programs
 * interact via the stable BPF syscall interface, not by linking to
 * kernel internals.  The rest of ZTLP remains Apache-2.0/MIT.
 */
char _license[] SEC("license") = "Dual MIT/GPL";
