 *
 *     // ... application event loop ...
 *
 *     ztlp_config_free(cfg);
 *     ztlp_client_free(client);
 *     ztlp_shutdown();
 *     return 0;
 * }
 * @endcode
 */

#ifndef ZTLP_H
#define ZTLP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Opaque Handle Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Opaque client handle.
 *
 * Wraps the ZTLP protocol engine including tokio runtime, identity, transport,
 * and session state. Thread-safe — may be used from multiple threads.
 *
 * Created with ztlp_client_new(), freed with ztlp_client_free().
 */
typedef struct ZtlpClient ZtlpClient;

/**
 * @brief Opaque session handle.
 *
 * Represents an active ZTLP session with a peer. Provided to callbacks —
 * valid only for the duration of the callback invocation.
 *
 * Do NOT store or free session handles.
 */
typedef struct ZtlpSession ZtlpSession;

/**
 * @brief Opaque identity handle.
 *
 * Wraps a platform identity provider (software or hardware-backed).
 *
 * Created with ztlp_identity_generate(), ztlp_identity_from_file(),
 * or ztlp_identity_from_hardware(). Freed with ztlp_identity_free().
 *
 * @note After passing to ztlp_client_new(), ownership transfers to the client.
 * Do NOT free the identity separately in that case.
 */
typedef struct ZtlpIdentity ZtlpIdentity;

/**
 * @brief Opaque configuration handle.
 *
 * Created with ztlp_config_new(), configured with ztlp_config_set_*(),
 * freed with ztlp_config_free().
 */
typedef struct ZtlpConfig ZtlpConfig;

/**
 * @brief Opaque iOS fd-backed tunnel engine handle.
 *
 * Scaffolding for the Nebula-style iOS data-plane migration. The first phase
 * validates utun fd discovery/lifecycle; production packet I/O is not switched
 * to this engine yet.
 */
typedef struct ZtlpIosTunnelEngine ZtlpIosTunnelEngine;
typedef struct ZtlpPacketRouter ZtlpPacketRouter;

/* ═══════════════════════════════════════════════════════════════════════════
 * Result Codes
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Result codes returned by all ZTLP functions.
 *
 * Zero indicates success. Negative values indicate errors.
 * Call ztlp_last_error() for a human-readable error description.
 */
enum {
    /** Operation succeeded. */
    ZTLP_OK                = 0,
    /** A function argument was null or invalid. */
    ZTLP_INVALID_ARGUMENT  = -1,
    /** Identity generation or loading failed. */
    ZTLP_IDENTITY_ERROR    = -2,
    /** Noise_XX handshake failed. */
    ZTLP_HANDSHAKE_ERROR   = -3,
    /** Network connection failed. */
    ZTLP_CONNECTION_ERROR  = -4,
    /** Operation timed out. */
    ZTLP_TIMEOUT           = -5,
    /** No session found for the given ID. */
    ZTLP_SESSION_NOT_FOUND = -6,
    /** Encryption or decryption failed. */
    ZTLP_ENCRYPTION_ERROR  = -7,
    /** NAT traversal failed. */
    ZTLP_NAT_ERROR         = -8,
    /** Already connected to a peer. */
    ZTLP_ALREADY_CONNECTED = -9,
    /** Not connected — call ztlp_connect first. */
    ZTLP_NOT_CONNECTED     = -10,
    /** Access rejected by gateway policy. */
    ZTLP_REJECTED          = -11,
    /** Packet rejected by anti-replay window (harmless duplicate/retransmit). */
    ZTLP_REPLAY_REJECTED   = -12,
    /** Unspecified internal error. */
    ZTLP_INTERNAL_ERROR    = -99
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Identity Provider Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Platform identity provider types.
 *
 * Used with ztlp_identity_from_hardware() to select the key storage backend.
 */
enum {
    /** Software-only (file-based, default). */
    ZTLP_PROVIDER_SOFTWARE         = 0,
    /** iOS Secure Enclave (P-256 in SE, X25519 derived). */
    ZTLP_PROVIDER_SECURE_ENCLAVE   = 1,
    /** Android Keystore (TEE / StrongBox). */
    ZTLP_PROVIDER_ANDROID_KEYSTORE = 2,
    /** Hardware token (YubiKey, etc.) — reserved. */
    ZTLP_PROVIDER_HARDWARE_TOKEN   = 3
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection State
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Connection state machine values.
 */
enum {
    /** Not connected to any peer. */
    ZTLP_STATE_DISCONNECTED = 0,
    /** STUN/NAT discovery in progress. */
    ZTLP_STATE_DISCOVERING  = 1,
    /** Noise_XX handshake in progress. */
    ZTLP_STATE_HANDSHAKING  = 2,
    /** Active session — data can be sent/received. */
    ZTLP_STATE_CONNECTED    = 3,
    /** Auto-reconnect in progress. */
    ZTLP_STATE_RECONNECTING = 4
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Mobile Event Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Event types emitted by the mobile client.
 */
enum {
    ZTLP_EVENT_CONNECTED      = 1,
    ZTLP_EVENT_DISCONNECTED   = 2,
    ZTLP_EVENT_DATA_RECEIVED  = 3,
    ZTLP_EVENT_STATE_CHANGED  = 4,
    ZTLP_EVENT_ERROR          = 5,
    ZTLP_EVENT_NAT_DISCOVERED = 6
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Callback Types
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Connection result callback.
 *
 * @param user_data  Opaque pointer passed to ztlp_connect/ztlp_listen.
 * @param result     0 on success, negative ZtlpResult on failure.
 * @param peer_addr  Peer address string (e.g. "1.2.3.4:5678").
 *                   NULL on failure. Library-owned — do NOT free.
 *
 * @warning Invoked on the library's background thread. Do NOT block.
 */
typedef void (*ZtlpConnectCallback)(void *user_data, int32_t result,
                                     const char *peer_addr);

/**
 * @brief Callback for iOS fd-engine RouterActions.
 *
 * The callback must synchronously consume/copy data. The pointer is only valid
 * for the duration of the callback invocation.
 */
typedef void (*ZtlpIosRouterActionCallback)(
    void *user_data,
    uint8_t action_type,
    uint32_t stream_id,
    const uint8_t *data,
    size_t data_len
);

/* ═══════════════════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Initialize the ZTLP library.
 *
 * Must be called before any other ZTLP function. Safe to call multiple times.
 *
 * @return ZTLP_OK on success.
 */
int32_t ztlp_init(void);

/**
 * @brief Shut down the ZTLP library.
 *
 * Call when done. No ZTLP functions should be called after this.
 */
void ztlp_shutdown(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * Identity Management
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Generate a new random identity (software provider).
 *
 * @return New identity handle, or NULL on failure. Caller owns.
 *         Free with ztlp_identity_free() unless passed to ztlp_client_new().
 */
ZtlpIdentity *ztlp_identity_generate(void);

/**
 * @brief Load an identity from a JSON file.
 *
 * @param path  Null-terminated file path (UTF-8).
 * @return New identity handle, or NULL on failure. Caller owns.
 */
ZtlpIdentity *ztlp_identity_from_file(const char *path);

/**
 * @brief Create a hardware-backed identity provider.
 *
 * @param provider  ZTLP_PROVIDER_* constant.
 * @return New identity handle, or NULL if provider is unknown.
 *
 * @note The returned handle is a stub. The platform layer (Swift/Kotlin)
 *       must set sign/DH callbacks before the identity is usable.
 */
ZtlpIdentity *ztlp_identity_from_hardware(int32_t provider);

/**
 * @brief Get the hex-encoded Node ID from an identity.
 *
 * @param identity  Valid identity handle.
 * @return Null-terminated hex string (32 chars for 16 bytes), or NULL.
 *         Library-owned — do NOT free. Valid while identity is alive.
 */
const char *ztlp_identity_node_id(const ZtlpIdentity *identity);

/**
 * @brief Get the hex-encoded X25519 public key from an identity.
 *
 * @param identity  Valid identity handle.
 * @return Null-terminated hex string (64 chars for 32 bytes), or NULL.
 *         Library-owned — do NOT free.
 */
const char *ztlp_identity_public_key(const ZtlpIdentity *identity);

/**
 * @brief Save the identity to a JSON file.
 *
 * Only works for software identities. Hardware identities cannot be exported.
 *
 * @param identity  Valid identity handle.
 * @param path      Null-terminated file path (UTF-8).
 * @return ZTLP_OK on success, negative on failure.
 */
int32_t ztlp_identity_save(const ZtlpIdentity *identity, const char *path);

/**
 * @brief Free an identity handle.
 *
 * @param identity  Handle to free, or NULL (safe no-op).
 *
 * @warning Do NOT free an identity that was passed to ztlp_client_new().
 */
void ztlp_identity_free(ZtlpIdentity *identity);

/* ═══════════════════════════════════════════════════════════════════════════
 * Client
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Create a new ZTLP client.
 *
 * @param identity  Identity handle. **Ownership transfers to the client.**
 *                  Do NOT free the identity after this call.
 * @return New client handle, or NULL on failure. Caller owns.
 *         Free with ztlp_client_free().
 */
ZtlpClient *ztlp_client_new(ZtlpIdentity *identity);

/**
 * @brief Free a client handle.
 *
 * Drops the client, runtime, identity, and any active session.
 *
 * @param client  Handle to free, or NULL (safe no-op).
 */
void ztlp_client_free(ZtlpClient *client);

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Create a new configuration with defaults.
 *
 * Defaults: no relay, NAT assist on, timeout 10000ms.
 *
 * @return New config handle (never NULL). Caller owns.
 *         Free with ztlp_config_free().
 */
ZtlpConfig *ztlp_config_new(void);

/**
 * @brief Set the relay server address.
 *
 * @param config  Valid config handle.
 * @param addr    Relay address (e.g. "relay.ztlp.net:4433").
 * @return ZTLP_OK on success.
 */
int32_t ztlp_config_set_relay(ZtlpConfig *config, const char *addr);

/**
 * @brief Set the STUN server for NAT discovery.
 *
 * @param config  Valid config handle.
 * @param addr    STUN server address (e.g. "stun.l.google.com:19302").
 * @return ZTLP_OK on success.
 */
int32_t ztlp_config_set_stun_server(ZtlpConfig *config, const char *addr);

/**
 * @brief Enable or disable NAT traversal assistance.
 *
 * @param config   Valid config handle.
 * @param enabled  true to enable (default), false to disable.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_config_set_nat_assist(ZtlpConfig *config, bool enabled);

/**
 * @brief Set the connection timeout.
 *
 * @param config  Valid config handle.
 * @param ms      Timeout in milliseconds (0 = no timeout).
 * @return ZTLP_OK on success.
 */
int32_t ztlp_config_set_timeout_ms(ZtlpConfig *config, uint64_t ms);

/**
 * @brief Set the target service name for gateway routing.
 *
 * The gateway uses this to determine which backend to forward traffic to.
 * For example, "beta" would route to the "beta" backend.
 *
 * @param config   Valid config handle.
 * @param service  Service name (max 16 bytes).
 * @return ZTLP_OK on success.
 */
int32_t ztlp_config_set_service(ZtlpConfig *config, const char *service);

/**
 * @brief Free a configuration handle.
 *
 * @param config  Handle to free, or NULL (safe no-op).
 */
void ztlp_config_free(ZtlpConfig *config);

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection
 * ═══════════════════════════════════════════════════════════════════════════ */



/* ═══════════════════════════════════════════════════════════════════════════
 * Data Transfer
 * ═══════════════════════════════════════════════════════════════════════════ */







/* ═══════════════════════════════════════════════════════════════════════════
 * Session Info
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Get the peer's Node ID from a session.
 *
 * @param session  Valid session handle (from callback).
 * @return Hex string, or NULL. Library-owned. Valid during callback.
 */
const char *ztlp_session_peer_node_id(const ZtlpSession *session);

/**
 * @brief Get the session ID.
 *
 * @param session  Valid session handle.
 * @return Hex string, or NULL. Library-owned.
 */
const char *ztlp_session_id(const ZtlpSession *session);

/**
 * @brief Get the peer's network address.
 *
 * @param session  Valid session handle.
 * @return Address string (e.g. "1.2.3.4:5678"), or NULL. Library-owned.
 */
const char *ztlp_session_peer_addr(const ZtlpSession *session);

/* ═══════════════════════════════════════════════════════════════════════════
 * TCP Tunnel (Port Forwarding)
 * ═══════════════════════════════════════════════════════════════════════════ */



/* ═══════════════════════════════════════════════════════════════════════════
 * VIP Proxy (Virtual IP — Local TCP → Tunnel)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Register a service with a VIP (Virtual IP) address and port.
 *
 * The VIP proxy will listen on vip:port and forward TCP traffic through
 * the ZTLP tunnel. Call multiple times to register multiple ports for
 * the same service (e.g., 80 and 443).
 *
 * @param client  Valid client handle.
 * @param name    Service name (e.g., "beta"). Null-terminated.
 * @param vip     VIP IPv4 address (e.g., "127.0.55.1"). Null-terminated.
 * @param port    TCP port to listen on (e.g., 80).
 * @return ZTLP_OK on success.
 */
int32_t ztlp_vip_add_service(ZtlpClient *client, const char *name,
                              const char *vip, uint16_t port);

/**
 * @brief Start VIP proxy listeners for all registered services.
 *
 * Requires an active ZTLP session (call ztlp_connect first). Each
 * registered service gets TCP listeners on its VIP:port that pipe data
 * bidirectionally through the tunnel.
 *
 * @param client  Valid, connected client handle.
 * @return ZTLP_OK on success, ZTLP_NOT_CONNECTED if no active session.
 */
int32_t ztlp_vip_start(ZtlpClient *client);

/**
 * @brief Stop all VIP proxy listeners.
 *
 * @param client  Valid client handle.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_vip_stop(ZtlpClient *client);

/* ═══════════════════════════════════════════════════════════════════════════
 * DNS Resolver (*.ztlp → VIP Address)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Start the ZTLP DNS resolver.
 *
 * Resolves *.ztlp domain queries to VIP addresses based on services
 * registered with ztlp_vip_add_service(). Typically bound to
 * "127.0.55.53:53".
 *
 * macOS setup: create /etc/resolver/ztlp with:
 *   nameserver 127.0.55.53
 *
 * @param client       Valid client handle.
 * @param listen_addr  Bind address (e.g., "127.0.55.53:53"). Null-terminated.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_dns_start(ZtlpClient *client, const char *listen_addr);

/**
 * @brief Stop the ZTLP DNS resolver.
 *
 * @param client  Valid client handle.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_dns_stop(ZtlpClient *client);

/* ═══════════════════════════════════════════════════════════════════════════
 * NS Resolution
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Resolve a ZTLP service name via ZTLP-NS.
 *
 * Queries the NS server for a SVC record matching the given name.
 * Returns the resolved endpoint address (e.g., "10.42.42.112:23098").
 *
 * The caller must free the returned string with ztlp_string_free().
 * Returns NULL on failure — check ztlp_last_error() for details.
 *
 * @param service_name  ZTLP-NS name (e.g., "beta.techrockstars.ztlp").
 * @param ns_server     NS server address (e.g., "52.39.59.34:23096").
 * @param timeout_ms    Query timeout in ms (0 = default 5000ms).
 * @return Heap-allocated address string, or NULL on failure.
 */
char *ztlp_ns_resolve(const char *service_name,
                       const char *ns_server,
                       uint32_t timeout_ms);

/* ═══════════════════════════════════════════════════════════════════════════
 * Packet Router (iOS utun / TUN interface)
 * ═══════════════════════════════════════════════════════════════════════════ */






/* ═══════════════════════════════════════════════════════════════════════════
 * Statistics
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Get bytes sent through the active session.
 *
 * @param client  Valid client handle.
 * @return Total bytes sent, or 0 if not connected.
 */
uint64_t ztlp_bytes_sent(const ZtlpClient *client);

/**
 * @brief Get bytes received through the active session.
 *
 * @param client  Valid client handle.
 * @return Total bytes received, or 0 if not connected.
 */
uint64_t ztlp_bytes_received(const ZtlpClient *client);

/* ═══════════════════════════════════════════════════════════════════════════
 * Utility
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Free a string allocated by the library.
 *
 * Only use on strings documented as "caller must free".
 * Most accessor strings are library-owned and should NOT be freed.
 *
 * @param s  String to free, or NULL (safe no-op).
 */
void ztlp_string_free(char *s);

/**
 * @brief Get the library version string.
 *
 * @return Static version string (e.g. "0.3.1"). Do NOT free.
 */
const char *ztlp_version(void);

/**
 * @brief Get the last error message for the calling thread.
 *
 * @return Error string, or NULL if no error. Library-owned.
 *         Valid until the next ZTLP call on this thread.
 */
const char *ztlp_last_error(void);

/* ─── NS Certificate Authority ─────────────────────────────────── */

/**
 * @brief Fetch the CA root certificate (DER) from the ZTLP-NS server.
 *
 * Sends a 0x14 0x01 query to the NS and returns the raw DER bytes.
 * The returned buffer must be freed with ztlp_bytes_free().
 *
 * @param ns_server  NS server address as "host:port"
 * @param timeout_ms Query timeout in milliseconds (0 = default 5000ms)
 * @param out_data   Receives pointer to DER data (caller frees with ztlp_bytes_free)
 * @param out_len    Receives length of DER data
 * @return 0 on success, negative on error (check ztlp_last_error)
 */
int32_t ztlp_ns_fetch_ca_root(
    const char *ns_server,
    uint32_t timeout_ms,
    uint8_t **out_data,
    uint32_t *out_len
);

/**
 * @brief Free a byte buffer returned by ztlp_ns_fetch_ca_root().
 *
 * @param data Pointer returned by ztlp_ns_fetch_ca_root
 * @param len  Length returned by ztlp_ns_fetch_ca_root
 */
void ztlp_bytes_free(uint8_t *data, uint32_t len);

/**
 * @brief Fetch the CA chain (PEM) from the ZTLP-NS server.
 *
 * Returns a null-terminated PEM string containing the intermediate and
 * root certificates. Caller must free with ztlp_string_free().
 *
 * @param ns_server  NS server address as "host:port"
 * @param timeout_ms Query timeout in milliseconds (0 = default 5000ms)
 * @return PEM string on success (free with ztlp_string_free), NULL on error
 */
char *ztlp_ns_fetch_ca_chain_pem(
    const char *ns_server,
    uint32_t timeout_ms
);

/* ═══════════════════════════════════════════════════════════════════════════
 * Gateway Key Pinning (Certificate Pinning)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Pin a gateway's static Noise public key.
 *
 * Stores the key in ~/.ztlp/config.toml so that subsequent connections
 * will reject gateways whose static key doesn't match any pinned key.
 * Multiple keys can be pinned for key rotation support.
 *
 * @param key_hex  Hex-encoded 32-byte X25519 public key (64 hex chars).
 *                 Null-terminated C string.
 * @return ZTLP_OK on success, ZTLP_INVALID_ARGUMENT on bad input,
 *         ZTLP_INTERNAL_ERROR on I/O failure.
 */
int32_t ztlp_pin_gateway_key(const char *key_hex);

/**
 * @brief Verify a gateway's static key against pinned keys.
 *
 * Checks if the given key matches any key in the pinned_gateway_keys
 * configuration list.
 *
 * @param key_hex  Hex-encoded 32-byte X25519 public key (64 hex chars).
 *                 Null-terminated C string.
 * @return 1 if key matches (or no keys pinned), 0 if no match,
 *         negative on error.
 */
int32_t ztlp_verify_gateway_pin(const char *key_hex);

/* ═══════════════════════════════════════════════════════════════════════════
 * Sync Crypto Context (Phase 1: Strip Tokio)
 *
 * Synchronous encrypt/decrypt FFI that does NOT require the tokio runtime.
 * Extract a context after handshake succeeds, then use it for sync
 * packet encryption and decryption. This enables the tokio-free iOS
 * architecture (Option 1 in IOS-MEMORY-OPTIMIZATION.md).
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque handle for sync crypto context. */
typedef struct ZtlpCryptoContext ZtlpCryptoContext;

/** Opaque handle for sync step-by-step handshake state. */
typedef struct ZtlpHandshakeState ZtlpHandshakeState;

/**
 * @brief Blocking synchronous connect using plain UDP (no tokio runtime).
 *
 * Performs the full Noise_XX 3-message handshake via std::net::UdpSocket
 * and returns a ZtlpCryptoContext directly — no runtime, no callbacks,
 * no background threads. The caller (Swift) handles recv via NWConnection.
 *
 * This is the iOS sync-connect entry point. Call it on a background
 * queue so it doesn't block the main thread. After success, use
 * ztlp_encrypt_packet/ztlp_decrypt_packet for all tunnel I/O.
 *
 * @param identity    ZTLP identity (from ztlp_identity_generate or ztlp_identity_from_file).
 *                    Ownership is NOT transferred (identity must outlive the call).
 * @param config      Optional connection config (relay, timeout, service_name), or NULL.
 * @param target      Gateway/peer address as "host:port" (e.g. "relay.ztlp.net:4433").
 * @param timeout_ms  Overall handshake timeout in milliseconds (0 = default 15000).
 * @return ZtlpCryptoContext* on success (caller must free with ztlp_crypto_context_free).
 *         NULL on failure (check ztlp_last_error).
 */

ZtlpHandshakeState *ztlp_handshake_start(
    ZtlpIdentity *identity,
    ZtlpConfig *config,
    const char *target,
    uint8_t *out_msg1,
    size_t out_msg1_len,
    size_t *out_msg1_written
);

int32_t ztlp_handshake_process_msg2(
    ZtlpHandshakeState *state,
    const uint8_t *msg2_data,
    size_t msg2_len,
    uint8_t *out_msg3,
    size_t out_msg3_len,
    size_t *out_msg3_written
);

ZtlpCryptoContext *ztlp_handshake_finalize(
    ZtlpHandshakeState *state,
    const uint8_t *extra_data,
    size_t extra_len
);

void ztlp_handshake_free(ZtlpHandshakeState *state);

ZtlpCryptoContext *ztlp_connect_sync(
    ZtlpIdentity *identity,
    ZtlpConfig *config,
    const char *target,
    uint32_t timeout_ms
);

/**
 * @brief Extract a sync crypto context from a connected client.
 *
 * Call this AFTER ztlp_connect succeeds. The context holds the session
 * keys, sequence counter, and anti-replay window needed for sync
 * encrypt/decrypt without tokio.
 *
 * @param client  Connected ZtlpClient handle (must have active session).
 * @return Opaque context handle on success, NULL on failure.
 *         Caller must free with ztlp_crypto_context_free().
 */
ZtlpCryptoContext *ztlp_crypto_context_extract(ZtlpClient *client);

/**
 * @brief Free a crypto context handle.
 *
 * @param ctx  Context handle, or NULL (safe no-op).
 */
void ztlp_crypto_context_free(ZtlpCryptoContext *ctx);

/** @brief Get the session ID string from a crypto context. */
const char *ztlp_crypto_context_session_id(const ZtlpCryptoContext *ctx);

/** @brief Get the peer address string from a crypto context. */
const char *ztlp_crypto_context_peer_addr(const ZtlpCryptoContext *ctx);

/**
 * @brief Encrypt plaintext into a full ZTLP wire packet (sync, no tokio).
 *
 * Allocates a packet sequence number from the shared atomic counter,
 * encrypts with ChaCha20-Poly1305, builds a DataHeader with auth tag,
 * and serializes the complete ZTLP packet.
 *
 * @param ctx            Crypto context (from ztlp_crypto_context_extract).
 * @param plaintext      Raw payload to encrypt.
 * @param plaintext_len  Length of plaintext.
 * @param out_buf        Output buffer (caller-allocated).
 * @param out_buf_len    Size of out_buf.
 * @param out_written    Receives number of bytes written.
 * @return 0 on success, negative error code on failure.
 */
int32_t ztlp_encrypt_packet(
    ZtlpCryptoContext *ctx,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out_buf, size_t out_buf_len,
    size_t *out_written
);

/**
 * @brief Decrypt a raw ZTLP wire packet (sync, no tokio).
 *
 * Parses the packet header, checks the anti-replay window, and
 * decrypts with ChaCha20-Poly1305.
 *
 * @param ctx         Crypto context.
 * @param packet      Raw UDP payload (complete ZTLP packet).
 * @param packet_len  Length of packet.
 * @param out_buf     Output buffer for decrypted payload.
 * @param out_buf_len Size of out_buf.
 * @param out_written Receives number of bytes written.
 * @return 0 on success, negative error code on failure.
 */
int32_t ztlp_decrypt_packet(
    ZtlpCryptoContext *ctx,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out_buf, size_t out_buf_len,
    size_t *out_written
);

/**
 * @brief Build a FRAME_DATA envelope: [0x00 | data_seq(8 BE) | payload].
 *
 * Wraps raw payload data for tunneling through ZTLP.
 *
 * @param payload        Raw data payload.
 * @param payload_len    Length of payload.
 * @param out_buf        Output buffer.
 * @param out_buf_len    Size of out_buf.
 * @param out_written    Receives frame length (1+8+payload_len).
 * @param data_seq       Data sequence number (caller-managed).
 * @return 0 on success, negative error code on failure.
 */
int32_t ztlp_frame_data(
    const uint8_t *payload, size_t payload_len,
    uint8_t *out_buf, size_t out_buf_len,
    size_t *out_written,
    uint64_t data_seq
);

/**
 * @brief Parse a decrypted frame into type, sequence, and payload.
 *
 * @param decrypted      Decrypted packet payload.
 * @param decrypted_len  Length of decrypted data.
 * @param out_frame_type Receives frame type (0x00=data, 0x01=ack, etc.).
 * @param out_seq        Receives data sequence number (8 bytes BE after type).
 * @param out_payload    Receives pointer to payload start (inside decrypted).
 * @param out_payload_len Receives payload length.
 * @return 0 on success, negative error code on failure.
 */
int32_t ztlp_parse_frame(
    const uint8_t *decrypted, size_t decrypted_len,
    uint8_t *out_frame_type,
    uint64_t *out_seq,
    const uint8_t **out_payload,
    size_t *out_payload_len
);




// ── iOS fd-backed tunnel engine scaffolding ────────────────────────────

/**
 * @brief Start the iOS fd-backed tunnel engine scaffold with a utun fd.
 *
 * Phase 1/2 API for validating Nebula-style fd ownership. This does not switch
 * production packet I/O yet.
 *
 * @param utun_fd     File descriptor for the NE utun interface.
 * @param out_engine  Receives a new engine handle on success.
 * @return 0 on success, negative ZTLP_* error code on failure.
 */
int32_t ztlp_ios_tunnel_engine_start(
    int32_t utun_fd,
    ZtlpIosTunnelEngine **out_engine
);

/**
 * @brief Stop the iOS fd-backed tunnel engine scaffold.
 */
int32_t ztlp_ios_tunnel_engine_stop(ZtlpIosTunnelEngine *engine);

/**
 * @brief Start debug read/drop/log mode for Rust fd ownership smoke testing.
 *
 * Swift packetFlow must be disabled before this is called. The Rust engine reads
 * packets from the utun fd, logs metadata, and drops them instead of routing.
 */
int32_t ztlp_ios_tunnel_engine_start_read_metadata_loop(ZtlpIosTunnelEngine *engine);

/**
 * @brief Start Rust fd-owned utun read -> PacketRouter ingress smoke test.
 *
 * Swift packetFlow must be disabled before this is called. Rust reads packets
 * from the utun fd and feeds the standalone PacketRouter, logging generated
 * router action counts. Router actions are not yet bridged to transport.
 */
/**
 * @brief Register a callback for RouterActions generated by the Rust fd engine.
 *
 * Register before starting router_ingress mode. Pass NULL to clear.
 * Callback data pointers are valid only during the callback; Swift must copy.
 */
int32_t ztlp_ios_tunnel_engine_set_router_action_callback(
    ZtlpIosTunnelEngine *engine,
    ZtlpIosRouterActionCallback callback,
    void *user_data
);

int32_t ztlp_ios_tunnel_engine_start_router_ingress_loop(
    ZtlpIosTunnelEngine *engine,
    ZtlpPacketRouter *router
);

/**
 * @brief Request a reconnect from the iOS fd-backed tunnel engine scaffold.
 */
int32_t ztlp_ios_tunnel_engine_reconnect(
    ZtlpIosTunnelEngine *engine,
    const char *reason
);

/**
 * @brief Bind the engine's Rust-owned UDP socket to 0.0.0.0:0 and set the
 *        peer (gateway or relay VIP). `peer` is a "host:port" literal such
 *        as "34.217.62.46:23096" or "[::1]:23096".
 *
 * Part of the Nebula-style collapse (Phase 1): Rust now owns the UDP
 * transport that was previously an NWConnection inside ZTLPTunnelConnection.
 *
 * @return ZtlpResult::Ok on success, InvalidArgument for bad inputs, or
 *         InternalError if bind/set_peer fails. Sets last error on failure.
 */
int32_t ztlp_ios_tunnel_engine_udp_bind(
    ZtlpIosTunnelEngine *engine,
    const char *peer
);

/**
 * @brief Send bytes to the configured UDP peer.
 *
 * Part of the Nebula-style collapse (Phase 1): Swift calls this in place of
 * its old NWConnection.send for tunnel UDP.
 *
 * @return Number of bytes sent on success (>=0), or a negative ZtlpResult
 *         code on failure. Sets last error on failure.
 */
int32_t ztlp_ios_tunnel_engine_udp_send(
    ZtlpIosTunnelEngine *engine,
    const uint8_t *data,
    size_t len
);

/**
 * @brief Return the local UDP port after `udp_bind`, or a negative error
 *        code if the socket has not been bound.
 */
int32_t ztlp_ios_tunnel_engine_udp_local_port(ZtlpIosTunnelEngine *engine);

/**
 * @brief Start a Rust-owned thread that drains the UDP socket and delivers
 *        each datagram to the router action callback as action_type=252
 *        (raw encrypted packet). In Phase 1 Swift is still responsible for
 *        decrypting and driving the mux; Phase 2 will bypass Swift entirely.
 *
 * Safe to call multiple times; subsequent calls are no-ops while the loop
 * is running.
 *
 * @return ZtlpResult::Ok on success, InternalError on failure.
 */
int32_t ztlp_ios_tunnel_engine_start_udp_recv_loop(ZtlpIosTunnelEngine *engine);

/**
 * @brief Free an iOS tunnel engine handle.
 */
void ztlp_ios_tunnel_engine_free(ZtlpIosTunnelEngine *engine);

// ── MuxEngine FFI (Phase 2: Nebula collapse) ─────────────────────────

/**
 * @brief Opaque handle for a MuxEngine — a pure state machine owning the
 *        tunnel's sequence, ACK, rwnd, cwnd, and retransmit state.
 */
typedef struct ZtlpMuxEngine ZtlpMuxEngine;

/**
 * @brief Callback used by ztlp_mux_take_send_bytes and
 *        ztlp_mux_take_retransmit_bytes. The pointer must NOT be retained
 *        past the callback return — copy bytes if needed.
 */
typedef void (*ZtlpMuxFrameCallback)(
    void *user_data,
    const uint8_t *frame,
    size_t len
);

ZtlpMuxEngine *ztlp_mux_new(void);
void ztlp_mux_free(ZtlpMuxEngine *engine);

int32_t ztlp_mux_enqueue_data(
    ZtlpMuxEngine *engine,
    uint32_t stream_id,
    const uint8_t *data,
    size_t len
);
int32_t ztlp_mux_enqueue_open(
    ZtlpMuxEngine *engine,
    uint32_t stream_id,
    const char *service
);
int32_t ztlp_mux_enqueue_close(ZtlpMuxEngine *engine, uint32_t stream_id);

int32_t ztlp_mux_take_send_bytes(
    ZtlpMuxEngine *engine,
    ZtlpMuxFrameCallback callback,
    void *user_data
);

// ── RTT / goodput instrumentation (Phase A — modern flow control) ────





// ── FRAME_ACK_V2 / byte-unit window (Phase B — modern flow control) ──






// ── Phase D: Autotune (BBR-lite receive-window sizer) ────────────────
//
// The autotuner lives inside MuxEngine and runs on every tick_rwnd call.
// It mutates the advertised byte window directly when the peer speaks
// V2. These FFI entry points let Swift read/configure the tuner without
// reaching into MuxEngine state directly.







// ── Standalone Packet Router (ios-sync: no ZtlpClient needed) ──────────

/**
 * @brief Opaque handle for a standalone PacketRouter.
 * Used in ios-sync builds where ZtlpClient is not available.
 */
/**
 * @brief Create a standalone PacketRouter.
 * @param tunnel_addr Tunnel interface IP (e.g., "10.122.0.1").
 * @return Router handle, or NULL on error.
 */
ZtlpPacketRouter *ztlp_router_new_sync(const char *tunnel_addr);

/**
 * @brief Add a service to a standalone router.
 * @return 0 on success, negative error code on failure.
 */
int32_t ztlp_router_add_service_sync(
    ZtlpPacketRouter *router,
    const char *vip,
    const char *service_name
);

/**
 * @brief Write an IPv4 packet into the standalone router.
 *
 * Returns number of RouterActions generated. Actions are serialized into
 * action_buf as: [1B type][4B stream_id BE][2B data_len BE][data...]
 * Type: 0=OpenStream, 1=SendData, 2=CloseStream.
 *
 * @param router         Router handle.
 * @param data           Raw IPv4 packet from utun.
 * @param len            Packet length.
 * @param action_buf     Output buffer for serialized actions.
 * @param action_buf_len Size of action buffer.
 * @param action_written Receives total bytes written to action_buf.
 * @return Number of actions (>=0), or negative error code.
 */
int32_t ztlp_router_write_packet_sync(
    ZtlpPacketRouter *router,
    const uint8_t *data, size_t len,
    uint8_t *action_buf, size_t action_buf_len,
    size_t *action_written
);

/**
 * @brief Read next outbound IPv4 packet from the standalone router.
 * @return Bytes written (positive), 0 if no packets, negative on error.
 */
int32_t ztlp_router_read_packet_sync(
    ZtlpPacketRouter *router,
    uint8_t *buf, size_t buf_len
);

/**
 * @brief Feed gateway response data into the router for a specific stream.
 * Generates TCP data packets retrievable via ztlp_router_read_packet_sync().
 */
int32_t ztlp_router_gateway_data_sync(
    ZtlpPacketRouter *router,
    uint32_t stream_id,
    const uint8_t *data, size_t len
);

/**
 * @brief Notify the router that the gateway closed a stream.
 */
int32_t ztlp_router_gateway_close_sync(
    ZtlpPacketRouter *router,
    uint32_t stream_id
);

/**
 * @brief Stop and free a standalone router.
 */
void ztlp_router_stop_sync(ZtlpPacketRouter *router);

/**
 * @brief Clean up stale (timed-out) TCP flows in the router.
 *
 * Removes flows that have been inactive longer than the flow timeout.
 * Call periodically from Swift to reclaim flow memory and keep the
 * Network Extension under the iOS memory limit (~15 MB).
 *
 * @param router  Router handle from ztlp_router_new_sync().
 * @return Number of flows removed, or negative on error.
 */
int32_t ztlp_router_cleanup_stale_flows(ZtlpPacketRouter *router);

/**
 * @brief Reset all router runtime state (flows, stream mappings, outbound queue)
 * while preserving the configured service map.
 */
int32_t ztlp_router_reset_runtime_state(ZtlpPacketRouter *router);

/**
 * @brief Get a human-readable stats string for the router.
 *
 * Returns flow count, outbound queue size, and stream info for
 * memory debugging. Caller must free with ztlp_free_string().
 *
 * @param router  Router handle from ztlp_router_new_sync().
 * @return Heap-allocated string, or NULL on error.
 */
char *ztlp_router_stats(ZtlpPacketRouter *router);

/**
 * @brief Free a string allocated by the library.
 *
 * @param s  String to free, or NULL (safe no-op).
 */
void ztlp_free_string(char *s);

// ── Sync NS Resolution (no tokio, ios-safe) ─────────────────────────────

/**
 * @brief Result of a sync NS resolution query.
 *
 * Contains parsed records from a ZTLP-NS query. Free with ztlp_ns_result_free().
 * Available in both default and ios-sync builds (no tokio dependency).
 */
typedef struct ZtlpNsResult {
    size_t count;               /** Number of records found */
    uint8_t *record_types;      /** Array of record types (1=KEY, 2=SVC, 3=RELAY) */
    char **record_names;        /** Array of record name strings */
    uint8_t **record_data;      /** Array of raw CBOR data buffers */
    size_t *record_data_lens;   /** Array of CBOR data lengths */
    char *error;                /** Error message (NULL on success) */
} ZtlpNsResult;

/**
 * @brief Perform a sync NS resolution query.
 *
 * Uses std::net::UdpSocket — no tokio runtime needed.
 * Safe to call from the iOS Network Extension.
 *
 * @param ns_server   NS server address (e.g., "34.217.62.46:23096")
 * @param name        ZTLP name to resolve (e.g., "beta.techrockstars")
 * @param record_type Record type (1=KEY, 2=SVC, 3=RELAY)
 * @param timeout_ms  Query timeout in ms (0 = default 5000ms)
 * @return ZtlpNsResult pointer (NULL only on null args). Free with ztlp_ns_result_free().
 */
ZtlpNsResult *ztlp_ns_resolve_sync(
    const char *ns_server,
    const char *name,
    uint8_t record_type,
    uint32_t timeout_ms
);

/**
 * @brief Free a ZtlpNsResult.
 */
void ztlp_ns_result_free(ZtlpNsResult *result);

/**
 * @brief Get the address string from the first SVC record in an NS result.
 *
 * Convenience for the common case of resolving a service name
 * and getting its "ip:port" address.
 *
 * @return Address string (caller must free with ztlp_string_free), or NULL.
 */
char *ztlp_ns_result_get_address(const ZtlpNsResult *result);

/**
 * @brief Result of relay-specific NS resolution.
 *
 * Contains parsed relay info ready for RelayPool. Free with ztlp_relay_list_free().
 */
typedef struct ZtlpRelayList {
    size_t count;               /** Number of relays found */
    char **addresses;           /** Array of "ip:port" strings */
    char **regions;             /** Array of region strings */
    uint32_t *latency_ms;       /** Array of latency values (ms) */
    uint8_t *load_pct;          /** Array of load percentages (0-100) */
    uint32_t *active_connections; /** Array of connection counts */
    uint8_t *health;            /** Array of health states (0=healthy,1=degraded,2=dead,3=deprioritized) */
    char *error;                /** Error message (NULL on success) */
} ZtlpRelayList;

/**
 * @brief Resolve relays from NS and return parsed relay info.
 *
 * Convenience wrapper that calls ztlp_ns_resolve_sync with record_type=3 (RELAY)
 * and parses CBOR data into typed relay fields.
 *
 * @param ns_server   NS server address
 * @param name        Zone or service name (e.g., "techrockstars")
 * @param timeout_ms  Query timeout (0 = default 5000ms)
 * @return ZtlpRelayList pointer. Free with ztlp_relay_list_free().
 */
ZtlpRelayList *ztlp_ns_resolve_relays_sync(
    const char *ns_server,
    const char *name,
    uint32_t timeout_ms
);

/**
 * @brief Free a ZtlpRelayList.
 */
void ztlp_relay_list_free(ZtlpRelayList *list);

/* ── RelayPool FFI ───────────────────────────────────────────────────── */

/**
 * @brief Opaque handle to a RelayPool.
 *
 * Created by ztlp_relay_pool_new(), freed by ztlp_relay_pool_free().
 */
typedef struct ZtlpRelayPool ZtlpRelayPool;

/**
 * @brief Create a new RelayPool with default configuration.
 *
 * @param gateway_region  Region for relay selection tiebreak (e.g., "us-west-2").
 *                        Can be NULL for no preference.
 * @return Pointer to a new ZtlpRelayPool. Free with ztlp_relay_pool_free().
 */
ZtlpRelayPool *ztlp_relay_pool_new(const char *gateway_region);

/**
 * @brief Update the relay pool with NS-discovered relay data.
 *
 * Feeds a ZtlpRelayList into the pool, preserving health state of existing
 * relays while adding new ones and pruning dead ones not in the NS response.
 *
 * @param pool        Pointer from ztlp_relay_pool_new(). Must not be NULL.
 * @param relay_list  Pointer from ztlp_ns_resolve_relays_sync(). Can be NULL (no-op).
 * @return 0 on success, -1 on error (null pool).
 */
int ztlp_relay_pool_update_from_ns(ZtlpRelayPool *pool, const ZtlpRelayList *relay_list);

/**
 * @brief Select the best available relay from the pool.
 *
 * Uses ranking (latency, load, region preference, health, backoff).
 *
 * @param pool  Pointer from ztlp_relay_pool_new(). Must not be NULL.
 * @return C string with relay address (e.g., "34.219.64.205:443"), or NULL if none available.
 *         Free with ztlp_string_free().
 */
char *ztlp_relay_pool_select(ZtlpRelayPool *pool);

/**
 * @brief Get number of healthy relays in the pool.
 */
size_t ztlp_relay_pool_healthy_count(const ZtlpRelayPool *pool);

/**
 * @brief Get total number of relays (including unhealthy).
 */
size_t ztlp_relay_pool_total_count(const ZtlpRelayPool *pool);

/**
 * @brief Report a successful connection to a relay.
 *
 * @param pool         Pointer from ztlp_relay_pool_new().
 * @param addr         Relay address string (e.g., "34.219.64.205:443").
 * @param latency_ms   Measured RTT in milliseconds.
 */
void ztlp_relay_pool_report_success(ZtlpRelayPool *pool, const char *addr, uint32_t latency_ms);

/**
 * @brief Report a failed connection to a relay.
 *
 * @param pool  Pointer from ztlp_relay_pool_new().
 * @param addr  Relay address string.
 */
void ztlp_relay_pool_report_failure(ZtlpRelayPool *pool, const char *addr);

/**
 * @brief Check if the pool needs an NS refresh.
 *
 * @return true if relay data is stale.
 */
bool ztlp_relay_pool_needs_refresh(const ZtlpRelayPool *pool);

/**
 * @brief Free a ZtlpRelayPool.
 */
void ztlp_relay_pool_free(ZtlpRelayPool *pool);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZTLP_H */
