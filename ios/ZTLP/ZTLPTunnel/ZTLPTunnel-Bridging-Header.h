//
//  ZTLPTunnel-Bridging-Header.h
//  ZTLPTunnel (Network Extension)
//
//  Bridging header to expose the ZTLP C FFI to the tunnel extension.
//  Both the main app and the extension link against libztlp_proto.a.
//

#ifndef ZTLPTunnel_Bridging_Header_h
#define ZTLPTunnel_Bridging_Header_h

#include "ztlp.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#ifndef MAX_KCTL_NAME
#define MAX_KCTL_NAME 96
#endif

#ifndef AF_SYS_CONTROL
#define AF_SYS_CONTROL 2
#endif

struct ztlp_ctl_info {
    uint32_t ctl_id;
    char ctl_name[MAX_KCTL_NAME];
};

struct ztlp_sockaddr_ctl {
    uint8_t sc_len;
    uint8_t sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
    uint32_t sc_reserved[5];
};

#ifndef ZTLP_CTLIOCGINFO
#define ZTLP_CTLIOCGINFO _IOWR('N', 3, struct ztlp_ctl_info)
#endif

static inline int32_t ztlp_find_utun_fd(void) {
    struct ztlp_ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strncpy(ctlInfo.ctl_name, "com.apple.net.utun_control", MAX_KCTL_NAME - 1);

    for (int32_t fd = 0; fd <= 1024; fd++) {
        struct ztlp_sockaddr_ctl addr;
        memset(&addr, 0, sizeof(addr));
        socklen_t len = (socklen_t)sizeof(addr);
        int ret = getpeername(fd, (struct sockaddr *)&addr, &len);
        if (ret != 0 || addr.sc_family != AF_SYSTEM) {
            continue;
        }
        if (ctlInfo.ctl_id == 0) {
            ret = ioctl(fd, ZTLP_CTLIOCGINFO, &ctlInfo);
            if (ret != 0) {
                continue;
            }
        }
        if (addr.sc_id == ctlInfo.ctl_id) {
            return fd;
        }
    }
    return -1;
}

#endif /* ZTLPTunnel_Bridging_Header_h */
