/*
 * Stub implementation of the ztlp_ios.h contract.
 *
 * COMPILE CHECKS AND SIMULATOR UNIT TESTS ONLY. Every call fails or reports
 * "not enrolled"; nothing here talks to a network. build-and-install.sh
 * refuses to sign or install a build linked against this.
 */
#include <stdint.h>
#include <string.h>

#include "ztlp_ios.h"

static const char STUB_ERROR[] = "ZTLP stub library: the Rust agent is not linked into this build.";
static const char STUB_STATUS[] =
    "{\"running\":false,\"enrolled\":false,\"node_name\":\"\",\"zone\":\"\","
    "\"vips\":0,\"tunnels\":0,\"ca_ready\":false,"
    "\"last_error\":\"stub library\"}";

int32_t ztlp_ios_init(const char *home_dir) { (void)home_dir; return 0; }
int32_t ztlp_ios_is_enrolled(void) { return 0; }
int32_t ztlp_ios_enroll(const char *enrollment_uri, const char *device_name) {
    (void)enrollment_uri; (void)device_name; return -1;
}
int32_t ztlp_ios_ensure_ca(void) { return -1; }
int32_t ztlp_ios_ca_root_pem(char *buf, uint32_t buf_len) { (void)buf; (void)buf_len; return -1; }
int32_t ztlp_ios_agent_start(const char *dns_ip, const char *vip_cidr) {
    (void)dns_ip; (void)vip_cidr; return -1;
}
int32_t ztlp_ios_agent_stop(void) { return 0; }
int32_t ztlp_ios_network_changed(void) { return 0; }
int32_t ztlp_ios_status_json(char *buf, uint32_t buf_len) {
    uint32_t n = (uint32_t)(sizeof(STUB_STATUS) - 1);
    if (buf == 0 || buf_len < n + 1) return -2;
    memcpy(buf, STUB_STATUS, n + 1);
    return (int32_t)n;
}
const char *ztlp_ios_last_error(void) { return STUB_ERROR; }
