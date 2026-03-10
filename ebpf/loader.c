#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include "ztlp_xdp.h"

static const char *default_obj = "ztlp_xdp.o";

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <ifname> [options]\n"
            "Options:\n"
            "  --detach                 Detach program from interface\n"
            "  --add-session <hexid>    Add SessionID to allowlist\n"
            "  --remove-session <hexid> Remove SessionID\n"
            "  --stats                  Dump statistics\n"
            "  -h, --help               Show this help\n",
            prog);
    exit(EXIT_FAILURE);
}

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
        out[i] = ( __u8)byte;
    }
    return 0;
}

static int attach_xdp(const char *ifname, struct bpf_object *obj)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ztlp_xdp_prog");
    if (!prog) {
        fprintf(stderr, "Program 'ztlp_xdp_prog' not found\n");
        return -1;
    }
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get prog fd: %s\n", strerror(errno));
        return -1;
    }
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return -1;
    }
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "bpf_set_link_xdp_fd failed: %s\n", strerror(-err));
        return -1;
    }
    printf("Attached XDP program to %s (ifindex %d)\n", ifname, ifindex);
    return 0;
}

static int detach_xdp(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return -1;
    }
    int err = bpf_set_link_xdp_fd(ifindex, -1, 0);
    if (err < 0) {
        fprintf(stderr, "Detach failed: %s\n", strerror(-err));
        return -1;
    }
    printf("Detached XDP program from %s\n", ifname);
    return 0;
}

static int modify_session(struct bpf_object *obj, bool add, const char *hexid)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "session_map");
    if (!map) {
        fprintf(stderr, "session_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);
    struct session_id sid = {};
    if (hex_to_bytes(hexid, sid.id, sizeof(sid.id)) != 0) {
        fprintf(stderr, "Invalid SessionID hex\n");
        return -1;
    }
    __u8 val = 1;
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

static int dump_stats(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!map) {
        fprintf(stderr, "stats_map not found\n");
        return -1;
    }
    int map_fd = bpf_map__fd(map);
    const char *names[] = {"layer1_drops", "layer2_drops", "hello_rate_drops", "passed"};
    for (uint32_t i = 0; i < STAT_MAX; i++) {
        __u64 val = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &val) == 0)
            printf("%s: %llu\n", names[i], (unsigned long long)val);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int opt_index = 0;
    static struct option long_opts[] = {
        {"detach",        no_argument,       0,  0 },
        {"add-session",   required_argument, 0,  0 },
        {"remove-session",required_argument, 0,  0 },
        {"stats",         no_argument,       0,  0 },
        {"help",          no_argument,       0, 'h'},
        {0,0,0,0}
    };
    bool do_detach = false, do_stats = false;
    const char *add_sid = NULL, *rem_sid = NULL;
    while (1) {
        int c = getopt_long(argc, argv, "h", long_opts, &opt_index);
        if (c == -1) break;
        switch (c) {
            case 0:
                if (strcmp(long_opts[opt_index].name, "detach") == 0) do_detach = true;
                else if (strcmp(long_opts[opt_index].name, "add-session") == 0) add_sid = optarg;
                else if (strcmp(long_opts[opt_index].name, "remove-session") == 0) rem_sid = optarg;
                else if (strcmp(long_opts[opt_index].name, "stats") == 0) do_stats = true;
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Interface name required\n");
        usage(argv[0]);
    }
    ifname = argv[optind];

    struct bpf_object *obj = NULL;
    int err = 0;

    if (!do_detach) {
        obj = bpf_object__open_file(default_obj, NULL);
        if (libbpf_get_error(obj)) {
            fprintf(stderr, "Failed to open %s: %s\n", default_obj, strerror(errno));
            return 1;
        }
        err = bpf_object__load(obj);
        if (err) {
            fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
            return 1;
        }
        if (attach_xdp(ifname, obj) != 0)
            return 1;
    } else {
        if (detach_xdp(ifname) != 0) return 1;
        return 0;
    }

    if (add_sid)
        modify_session(obj, true, add_sid);
    if (rem_sid)
        modify_session(obj, false, rem_sid);
    if (do_stats)
        dump_stats(obj);

    /* keep process alive until interrupted to allow map ops */
    printf("Press Ctrl+C to exit...\n");
    while (1) pause();

    bpf_object__close(obj);
    return 0;
}
