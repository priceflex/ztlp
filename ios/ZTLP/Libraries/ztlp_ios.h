/*
 * ztlp_ios.h - ZTLP native agent for iOS (app + Network Extension).
 *
 * The Network Extension hosts the same agent the desktop runs
 * (proto/src/agent), linked from libztlp_proto.a
 * (cargo build --release --lib --target aarch64-apple-ios, default features).
 * Implementation: proto/src/ios_agent.rs.
 * Contract: docs/plans/2026-11-27-ios-native-agent.md.
 *
 * All functions are thread-safe. Unless noted they return 0 on success and
 * a negative ZTLP_IOS_ERR_* code on failure; ztlp_ios_last_error() then
 * returns the reason. Strings are UTF-8 and NUL-terminated. A NULL or
 * non-UTF-8 argument is an error (ZTLP_IOS_ERR_INVALID_ARGUMENT), never a
 * crash. No function unwinds into the caller.
 *
 * home_dir is the App Group container path. Everything the agent normally
 * keeps in ~/.ztlp lives in <home_dir>/.ztlp:
 *   identity.json, config.toml, agent.toml, ns_trust.toml   enrollment
 *   enrolled_name          the name the device enrolled as
 *   enroll_callback.json   pending enrollment callback for the app to POST
 *   ca/                    device-local CA (root.pem is the cert to trust)
 *   certs/, quic_pins/, ns_cache/, vip_state.json, agent.token, agent.pid
 *   agent.log, agent.log.1 log (1 MiB each, rotated)
 */
#ifndef ZTLP_IOS_H
#define ZTLP_IOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. */
#define ZTLP_IOS_OK                     0
#define ZTLP_IOS_ERR                   (-1) /* see ztlp_ios_last_error() */
#define ZTLP_IOS_ERR_BUFFER_TOO_SMALL  (-2)
#define ZTLP_IOS_ERR_INVALID_ARGUMENT  (-3) /* NULL, bad UTF-8, bad value */
#define ZTLP_IOS_ERR_NOT_INITIALIZED   (-4) /* ztlp_ios_init not called */
#define ZTLP_IOS_ERR_NOT_ENROLLED      (-5)
#define ZTLP_IOS_ERR_ALREADY_ENROLLED  (-6)

/* Call once per process before anything else. Sets the home dir, starts
 * logging to <home_dir>/.ztlp/agent.log (size-capped), installs the iOS
 * memory profile. home_dir must be an absolute path. Calling it again with
 * the same path is harmless. */
int32_t ztlp_ios_init(const char *home_dir);

/* 1 if a complete enrollment exists under home_dir, else 0 (also 0 before
 * ztlp_ios_init). Never negative. */
int32_t ztlp_ios_is_enrolled(void);

/* Enroll with a ztlp://enroll/... URI. Blocking (network; up to roughly
 * 30 s when the name server does not answer): do not call it on the main
 * thread. Writes identity, agent config and name-server trust under
 * home_dir, exactly as `ztlp setup --token <uri> --name <device_name> --yes`
 * does on the desktop. device_name is reduced to a DNS label
 * ("Steve's iPhone" -> "steves-iphone"); NULL or empty means "iphone".
 * Returns ZTLP_IOS_ERR_ALREADY_ENROLLED when an enrollment exists (remove
 * <home_dir>/.ztlp/identity.json and config.toml to enroll again). */
int32_t ztlp_ios_enroll(const char *enrollment_uri, const char *device_name);

/* Create the device-local CA if missing (same chain the desktop builds:
 * root with .ztlp name constraints + intermediate). Idempotent. */
int32_t ztlp_ios_ensure_ca(void);

/* Copy the root CA certificate (PEM) into buf. Returns bytes written
 * (excluding NUL), or negative; -2 = buffer too small (buf_len must be at
 * least the PEM length + 1; 4096 is always enough). */
int32_t ztlp_ios_ca_root_pem(char *buf, uint32_t buf_len);

/* Start the agent in this process on its own threads. dns_ip is the address
 * for the resolver (UDP and TCP port 53), the control endpoint (TCP 4433)
 * and the HTTPS health responder (TCP 8443, https://ztlp-health.ztlp:8443/
 * answers "ztlp-health-ok").
 *
 * vip_cidr says how sites get a local address; its prefix length selects
 * the mode:
 *
 *   "a.b.c.d/32"  Single-address mode (what works on iOS; pass dns_ip
 *                 "127.0.0.1" and vip_cidr "127.0.0.1/32"). Every site name
 *                 resolves to a.b.c.d. The agent listens there on TCP 443
 *                 and 80 only and picks the site from the TLS server name
 *                 (443) or the HTTP Host header (80). The address may equal
 *                 dns_ip. The start fails if port 443 cannot be bound; a
 *                 port 80 failure is logged and https still works. Web
 *                 only: other ports (SSH, RDP, ...) are not served.
 *
 *   wider prefix  Pool mode, e.g. "100.64.77.32/27" (network address form;
 *                 dns_ip must not be inside it): one address per site, the
 *                 agent listens on each. The addresses must already be
 *                 configured on the tunnel interface. Does not work on iOS,
 *                 which never delivers traffic for the tunnel's own
 *                 addresses to a socket.
 *
 * Returns once listeners are bound or failed. Calling it while running
 * returns 0. Returns ZTLP_IOS_ERR_NOT_ENROLLED when there is no enrollment.
 * The mode is written to agent.toml at every start, so the next start may
 * use the other one. */
int32_t ztlp_ios_agent_start(const char *dns_ip, const char *vip_cidr);

/* Stop the agent and free its listeners. Safe to call when not running. */
int32_t ztlp_ios_agent_stop(void);

/* JSON status into buf: {"running":bool,"enrolled":bool,"node_name":str,
 * "zone":str,"vips":int,"tunnels":int,"ca_ready":bool,"last_error":str}.
 * "vips" is the number of sites with an address in pool mode; in
 * single-address mode, the number of site names resolved in the last five
 * minutes.
 * Returns bytes written or negative; -2 = buffer too small (1024 is always
 * enough unless last_error is unusually long; use 4096). Works before
 * ztlp_ios_init and while the agent is stopped. */
int32_t ztlp_ios_status_json(char *buf, uint32_t buf_len);

/* Text of the last error on this thread ("" if none). Valid until the next
 * call on the same thread. Never NULL. */
const char *ztlp_ios_last_error(void);

/* Tell the agent that the device's network changed: call it on every
 * NWPathMonitor update (interface or status change, Wi-Fi <-> cellular) and
 * on wake from sleep.
 *
 * While the agent runs: every tunnel connection to a gateway is closed and
 * forgotten, so the next request dials on the current network; the sites
 * that had an open connection (at most 8) are dialed again in the
 * background at once; every site is resolved again before its next dial.
 * Listeners, resolver, certificates and the list of known sites are not
 * touched. Requests that were waiting for their first answer byte are
 * carried over to the new connection; a download or upload that was in
 * progress is cut (the browser sees the connection close).
 *
 * Safe to call at any time from any thread, also before ztlp_ios_init and
 * while the agent is stopped (then it does nothing). It never blocks: the
 * work happens on the agent's threads. Calls in a burst are coalesced: the
 * first acts at once, the rest of the burst (250 ms) as one more run. One
 * log line per run. Always returns 0. */
int32_t ztlp_ios_network_changed(void);

#ifdef __cplusplus
}
#endif

#endif /* ZTLP_IOS_H */
