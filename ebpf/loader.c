/*
 * ZTLP XDP Loader — loader.c
 *
 * Userspace companion for the ztlp_xdp.c eBPF/XDP program.
 * Uses libbpf to:
 *   - Load and attach the compiled XDP object (ztlp_xdp.o) to a NIC
 *   - Detach the XDP program from a NIC
 *   - Add/remove SessionIDs in the BPF session_map (allowlist management)
 *   - Add/remove mesh peer NodeIDs in mesh_peer_map (peer allowlist)
 *   - Configure RAT bypass for HELLO rate limiting
 *   - Read and aggregate per-CPU pipeline statistics (including mesh stats)
 *
 * Usage examples:
 *   # Attach XDP filter to eth0 and keep running:
 *   sudo ./ztlp-xdp-loader eth0
 *
 *   # Attach and pre-populate a session:
 *   sudo ./ztlp-xdp-loader eth0 --add-session a1b2c3d4e5f6a7b8c9d0e1f2
 *
 *   # Add a mesh peer to the allowlist:
 *   sudo ./ztlp-xdp-loader eth0 --add-peer 0123456789abcdef0123456789abcdef
 *
 *   # Show all pipeline stats (including mesh):
 *   sudo ./ztlp-xdp-loader eth0 --stats
 *
 *   # Show mesh-specific stats only:
 *   sudo ./ztlp-xdp-loader eth0 --mesh-stats
 *
 *   # Enable RAT bypass for HELLO rate limiting:
 *   sudo ./ztlp-xdp-loader eth0 --rat-bypass 1
 *
 *   # Detach XDP from eth0:
 *   sudo ./ztlp-xdp-loader eth0 --detach
 *
 * The loader must run as root (or with CAP_BPF + CAP_NET_ADMIN) because
 * attaching XDP programs and accessing BPF maps require elevated privileges.
 *
 * ZTLP and Zero Trust Layer Protocol are trademarks of Steven Price.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include "ztlp_xdp.h"

/* Default compiled XDP object file — built by the Makefile */
static const char *default_obj = "ztlp_xdp.o";

/*
 * usage — print CLI help and exit.
 */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <ifname> [options]\n"
        "\n"
        "Session management:\n"
        "  --add-session <hexid>      Add SessionID to allowlist (24 hex chars)\n"
        "  --remove-session <hexid>   Remove SessionID from allowlist\n"
        "\n"
        "Mesh peer management:\n"
        "  --add-peer <hexid>         Add mesh peer NodeID to allowlist (32 hex chars)\n"
        "  --remove-peer <hexid>      Remove mesh peer NodeID from allowlist\n"
        "  --list-peers               Show all authorized mesh peers\n"
        "\n"
        "Configuration:\n"
        "  --rat-bypass <0|1>         Enable/disable RAT HELLO rate limit bypass\n"
        "\n"
        "Statistics:\n"
        "  --stats                    Dump all statistics (client + mesh)\n"
        "  --mesh-stats               Dump mesh-specific statistics only\n"
        "\n"
        "Lifecycle:\n"
        "  --detach                   Detach program from interface\n"
        "  -h, --help                 Show this help\n",
        prog);
    exit(EXIT_FAILURE);
}

/*
 * hex_to_bytes — parse a hex string into a byte array.
 *
 * SessionIDs are 12 bytes (24 hex chars), NodeIDs are 16 bytes (32 hex chars).
 * This function validates the length and parses each byte pair.
 *
 * @hex:    input hex string
 * @out:    output byte buffer
 * @outlen: expected byte count
 *
 * Returns 0 on success, -1 on invalid input.
 */
static int hex_to_bytes(const char *hex, __u8 *out, size_t outlen)
{
    size_t len = strlen(hex);
    if (len != outlen * 2) {
        fprintf(stderr, "Invalid hex length %zu, expected %zu\n", len, outlen*2);
        return -1;
    }
    for (size_t i = 0; i < outlen; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%2x", &byte) != 1)
            return -1;
        out[i] = (__u8)byte;
    }
    return 0;
}

/*
 * bytes_to_hex — format a byte array as a hex string.
 *
 * @in:     input byte buffer
 * @inlen:  number of bytes
 * @out:    output buffer (must be at least inlen*2 + 1 bytes)
 */
static void bytes_to_hex(const __u8 *in, size_t inlen, char *out)
{
    for (size_t i = 0; i < inlen; i++)
        sprintf(out + i*2, "%02x", in[i]);
    out[inlen*2] = '\0';
}

/*
 * attach_xdp — load and attach the XDP program to a network interface.
 *
 * Finds the "ztlp_xdp_prog" section in the loaded BPF object, gets its
 * file descriptor, resolves the interface name to an ifindex, and calls
 * bpf_set_link_xdp_fd() to install the program.
 *
 * After attach, all packets arriving on this interface pass through
 * ztlp_xdp_prog() before reaching the kernel network stack.
 *
 * @ifname: network interface name (e.g. "eth0", "ens3")
 * @obj:    loaded BPF object containing the XDP program
 *
 * Returns 0 on success, -1 on failure.
 */
static int attach_xdp(const char *ifname, struct bpf_object *obj)
{
    /* Find the XDP program by its function name */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ztlp_xdp_prog");
    if (!prog) {
        fprintf(stderr, "Program 'ztlp_xdp_prog' not found\n");
        return -1;
    }

    /* Get the program's file descriptor — needed for the attach syscall */
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get prog fd: %s\n", strerror(errno));
        return -1;
    }

    /* Resolve interface name → ifindex (kernel's numeric identifier) */
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return -1;
    }

    /* Attach the XDP program to this interface.
     * Flag 0 = let the kernel choose SKB or native mode. */
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "bpf_set_link_xdp_fd failed: %s\n", strerror(-err));
        return -1;
    }
    printf("Attached XDP program to %s (ifindex %d)\n", ifname, ifindex);
    return 0;
}

/*
 * detach_xdp — remove any XDP program from a network interface.
 *
 * Passing fd=-1 to bpf_set_link_xdp_fd() removes the currently attached
 * program.  After detach, packets flow directly to the kernel stack.
 *
 * @ifname: network interface name
 *
 * Returns 0 on success, -1 on failure.
 */
static int detach_xdp(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return -1;
    }
    /* fd=-1 detaches the XDP program */
    int err = bpf_set_link_xdp_fd(ifindex, -1, 0);
    if (err < 0) {
        fprintf(stderr, "Detach failed: %s\n", strerror(-err));
        return -1;
    }
    printf("Detached XDP program from %s\n", ifname);
    return 0;
}

/*
 * modify_session — add or remove a SessionID from the BPF session_map.
 *
 * This is the runtime allowlist management interface.  When a ZTLP
 * session is established (Noise_XX handshake completes), the userspace
 * daemon calls this to whitelist the new SessionID.  On session close
 * or timeout, it removes the entry.
 *
 * @obj:   loaded BPF object (to find the map by name)
 * @add:   true = add to allowlist, false = remove
 * @hexid: 24-character hex string representing the 12-byte SessionID
 *
 * Returns 0 on success, -1 on failure.
 */
static int modify_session(struct bpf_object *obj, bool add, const char *hexid)
{
    /* Look up the session_map by name in the BPF object */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "session_map");
    if (!map) {
        fprintf(stderr, "session_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);

    /* Parse the hex SessionID string into a struct session_id */
    struct session_id sid = {};
    if (hex_to_bytes(hexid, sid.id, sizeof(sid.id)) != 0) {
        fprintf(stderr, "Invalid SessionID hex (expected 24 hex chars for 12 bytes)\n");
        return -1;
    }

    __u8 val = 1;  // Value doesn't matter — presence in the map is the check
    int ret;
    if (add)
        ret = bpf_map_update_elem(map_fd, &sid, &val, BPF_ANY);
    else
        ret = bpf_map_delete_elem(map_fd, &sid);

    if (ret != 0) {
        fprintf(stderr, "%s session failed: %s\n", add?"Add":"Remove", strerror(errno));
        return -1;
    }
    printf("%s SessionID %s %s map\n", add?"Added":"Removed", hexid, add?"to":"from");
    return 0;
}

/*
 * modify_peer — add or remove a mesh peer NodeID from mesh_peer_map.
 *
 * Mesh peers are authorized relay nodes that can send inter-relay
 * traffic to this host.  The XDP program checks the sender NodeID
 * of every mesh packet against this map and drops unknown peers.
 *
 * @obj:   loaded BPF object (to find the map by name)
 * @add:   true = add to allowlist, false = remove
 * @hexid: 32-character hex string representing the 16-byte NodeID
 *
 * Returns 0 on success, -1 on failure.
 */
static int modify_peer(struct bpf_object *obj, bool add, const char *hexid)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "mesh_peer_map");
    if (!map) {
        fprintf(stderr, "mesh_peer_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);

    struct mesh_peer_id peer = {};
    if (hex_to_bytes(hexid, peer.id, sizeof(peer.id)) != 0) {
        fprintf(stderr, "Invalid NodeID hex (expected 32 hex chars for 16 bytes)\n");
        return -1;
    }

    __u8 val = 1;
    int ret;
    if (add)
        ret = bpf_map_update_elem(map_fd, &peer, &val, BPF_ANY);
    else
        ret = bpf_map_delete_elem(map_fd, &peer);

    if (ret != 0) {
        fprintf(stderr, "%s peer failed: %s\n", add?"Add":"Remove", strerror(errno));
        return -1;
    }
    printf("%s mesh peer %s %s allowlist\n", add?"Added":"Removed", hexid, add?"to":"from");
    return 0;
}

/*
 * list_peers — iterate mesh_peer_map and print all authorized NodeIDs.
 *
 * Uses bpf_map_get_next_key() to iterate through the hash map.
 *
 * @obj: loaded BPF object (to find the mesh_peer_map)
 *
 * Returns 0 on success, -1 on failure.
 */
static int list_peers(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "mesh_peer_map");
    if (!map) {
        fprintf(stderr, "mesh_peer_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);

    struct mesh_peer_id key = {}, next_key = {};
    char hex_buf[33];  /* 16 bytes * 2 + null */
    int count = 0;

    printf("Authorized mesh peers:\n");

    /* Iterate with bpf_map_get_next_key — passing NULL key returns the first entry */
    if (bpf_map_get_next_key(map_fd, NULL, &next_key) != 0) {
        printf("  (none)\n");
        return 0;
    }

    do {
        key = next_key;
        bytes_to_hex(key.id, sizeof(key.id), hex_buf);
        printf("  %s\n", hex_buf);
        count++;
    } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0);

    printf("Total: %d peer(s)\n", count);
    return 0;
}

/*
 * set_rat_bypass — configure whether RAT-carrying HELLOs bypass rate limiting.
 *
 * @obj:   loaded BPF object
 * @value: 0 = rate limit all HELLOs, 1 = bypass rate limit for RAT HELLOs
 *
 * Returns 0 on success, -1 on failure.
 */
static int set_rat_bypass(struct bpf_object *obj, __u8 value)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "rat_bypass_map");
    if (!map) {
        fprintf(stderr, "rat_bypass_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);

    __u32 key = 0;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret != 0) {
        fprintf(stderr, "Set RAT bypass failed: %s\n", strerror(errno));
        return -1;
    }
    printf("RAT bypass for HELLO rate limiting: %s\n", value ? "ENABLED" : "DISABLED");
    return 0;
}

/*
 * dump_stats — read and display per-CPU pipeline statistics.
 *
 * The stats_map is BPF_MAP_TYPE_PERCPU_ARRAY, meaning each CPU core
 * has its own counter.  For a simple display, we read each index —
 * libbpf automatically returns the sum across CPUs for a single
 * lookup_elem call when the value is a scalar __u64.
 *
 * @obj: loaded BPF object (to find the stats_map)
 *
 * Returns 0 on success, -1 on failure.
 */
static int dump_stats(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!map) {
        fprintf(stderr, "stats_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);

    /* Human-readable names matching the STAT_* enum in ztlp_xdp.h */
    const char *names[] = {
        "layer1_drops",
        "layer2_drops",
        "hello_rate_drops",
        "passed",
        "mesh_passed",
        "mesh_peer_drops",
        "mesh_forward_passed",
        "rat_hello_passed"
    };

    printf("=== ZTLP XDP Pipeline Statistics ===\n\n");
    printf("Client traffic (port %d):\n", ZTLP_PORT);
    for (uint32_t i = 0; i < 4; i++) {
        __u64 val = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &val) == 0)
            printf("  %-24s %llu\n", names[i], (unsigned long long)val);
    }

    printf("\nMesh traffic (port %d):\n", ZTLP_MESH_PORT);
    for (uint32_t i = 4; i < STAT_MAX; i++) {
        __u64 val = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &val) == 0)
            printf("  %-24s %llu\n", names[i], (unsigned long long)val);
    }

    printf("\nRAT-aware HELLO:\n");
    {
        uint32_t i = STAT_RAT_HELLO_PASSED;
        __u64 val = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &val) == 0)
            printf("  %-24s %llu\n", names[i], (unsigned long long)val);
    }

    return 0;
}

/*
 * dump_mesh_stats — read and display only mesh-specific statistics.
 *
 * @obj: loaded BPF object
 *
 * Returns 0 on success, -1 on failure.
 */
static int dump_mesh_stats(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!map) {
        fprintf(stderr, "stats_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);

    const char *names[] = {
        [STAT_MESH_PASSED]         = "mesh_passed",
        [STAT_MESH_PEER_DROPS]     = "mesh_peer_drops",
        [STAT_MESH_FORWARD_PASSED] = "mesh_forward_passed",
        [STAT_RAT_HELLO_PASSED]    = "rat_hello_passed"
    };

    printf("=== ZTLP Mesh Statistics (port %d) ===\n", ZTLP_MESH_PORT);

    uint32_t mesh_indices[] = {
        STAT_MESH_PASSED,
        STAT_MESH_PEER_DROPS,
        STAT_MESH_FORWARD_PASSED,
        STAT_RAT_HELLO_PASSED
    };

    for (size_t j = 0; j < sizeof(mesh_indices)/sizeof(mesh_indices[0]); j++) {
        uint32_t i = mesh_indices[j];
        __u64 val = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &val) == 0)
            printf("  %-24s %llu\n", names[i], (unsigned long long)val);
    }

    return 0;
}

/*
 * main — CLI entry point.
 *
 * Parses command-line options, then either:
 *   1. Detaches XDP and exits, OR
 *   2. Opens + loads the BPF object, attaches XDP, optionally manages
 *      sessions/peers and stats, then sleeps indefinitely (Ctrl+C to exit).
 *
 * The loader stays alive after attach so the BPF maps remain accessible
 * for runtime session management.  If the loader exits, the XDP program
 * stays attached but the maps become inaccessible via this tool.
 */
int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int opt_index = 0;
    static struct option long_opts[] = {
        {"detach",         no_argument,       0,  0 },
        {"add-session",    required_argument, 0,  0 },
        {"remove-session", required_argument, 0,  0 },
        {"add-peer",       required_argument, 0,  0 },
        {"remove-peer",    required_argument, 0,  0 },
        {"list-peers",     no_argument,       0,  0 },
        {"rat-bypass",     required_argument, 0,  0 },
        {"stats",          no_argument,       0,  0 },
        {"mesh-stats",     no_argument,       0,  0 },
        {"help",           no_argument,       0, 'h'},
        {0,0,0,0}
    };
    bool do_detach = false, do_stats = false, do_mesh_stats = false;
    bool do_list_peers = false;
    const char *add_sid = NULL, *rem_sid = NULL;
    const char *add_peer = NULL, *rem_peer = NULL;
    const char *rat_bypass_str = NULL;

    /* Parse long options */
    while (1) {
        int c = getopt_long(argc, argv, "h", long_opts, &opt_index);
        if (c == -1) break;
        switch (c) {
            case 0:
                if (strcmp(long_opts[opt_index].name, "detach") == 0) do_detach = true;
                else if (strcmp(long_opts[opt_index].name, "add-session") == 0) add_sid = optarg;
                else if (strcmp(long_opts[opt_index].name, "remove-session") == 0) rem_sid = optarg;
                else if (strcmp(long_opts[opt_index].name, "add-peer") == 0) add_peer = optarg;
                else if (strcmp(long_opts[opt_index].name, "remove-peer") == 0) rem_peer = optarg;
                else if (strcmp(long_opts[opt_index].name, "list-peers") == 0) do_list_peers = true;
                else if (strcmp(long_opts[opt_index].name, "rat-bypass") == 0) rat_bypass_str = optarg;
                else if (strcmp(long_opts[opt_index].name, "stats") == 0) do_stats = true;
                else if (strcmp(long_opts[opt_index].name, "mesh-stats") == 0) do_mesh_stats = true;
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }

    /* Interface name is the first positional argument (required) */
    if (optind >= argc) {
        fprintf(stderr, "Interface name required\n");
        usage(argv[0]);
    }
    ifname = argv[optind];

    struct bpf_object *obj = NULL;
    int err = 0;

    if (!do_detach) {
        /* Open the compiled BPF object file — this parses the ELF and
         * discovers maps, programs, and BTF info */
        obj = bpf_object__open_file(default_obj, NULL);
        if (libbpf_get_error(obj)) {
            fprintf(stderr, "Failed to open %s: %s\n", default_obj, strerror(errno));
            return 1;
        }

        /* Load the BPF object into the kernel — this creates maps, runs
         * the BPF verifier on each program, and JIT-compiles them */
        err = bpf_object__load(obj);
        if (err) {
            fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
            return 1;
        }

        /* Attach the XDP program to the specified interface */
        if (attach_xdp(ifname, obj) != 0)
            return 1;
    } else {
        /* Detach mode — remove XDP from the interface and exit */
        if (detach_xdp(ifname) != 0) return 1;
        return 0;
    }

    /* Process optional session management commands */
    if (add_sid)
        modify_session(obj, true, add_sid);
    if (rem_sid)
        modify_session(obj, false, rem_sid);

    /* Process mesh peer management commands */
    if (add_peer)
        modify_peer(obj, true, add_peer);
    if (rem_peer)
        modify_peer(obj, false, rem_peer);
    if (do_list_peers)
        list_peers(obj);

    /* Process RAT bypass configuration */
    if (rat_bypass_str) {
        __u8 val = (rat_bypass_str[0] == '1') ? 1 : 0;
        set_rat_bypass(obj, val);
    }

    /* Process stats commands */
    if (do_stats)
        dump_stats(obj);
    if (do_mesh_stats)
        dump_mesh_stats(obj);

    /* Keep the process alive so BPF maps stay accessible for future
     * session management operations via /proc or map pinning.
     * The XDP program stays attached even if this process exits,
     * but the maps become inaccessible unless pinned to bpffs. */
    printf("Press Ctrl+C to exit...\n");
    while (1) pause();

    bpf_object__close(obj);
    return 0;
}
