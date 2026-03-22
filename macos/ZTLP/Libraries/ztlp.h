/**
 * @file ztlp.h
 * @brief ZTLP (Zero Trust Layer Protocol) Mobile SDK — C FFI API
 * @version 0.10.0
 *
 * This header defines the complete C-compatible API for integrating the ZTLP
 * protocol into iOS and Android applications. The library is compiled as a
 * static library (libztlp_proto.a) from Rust source.
 *
 * ## Design Principles
 *
 * 1. **Opaque handles** — All types are forward-declared structs accessed via
 *    pointers. The internal layout is hidden from C.
 *
 * 2. **Error codes** — Every function returns an int32_t result code.
 *    0 = success, negative = error. Call ztlp_last_error() for details.
 *
 * 3. **String handling** — All strings are null-terminated C strings.
 *    - Input strings: caller owns, library reads.
 *    - Output strings from accessors: library owns, valid while handle lives.
 *    - Strings explicitly marked "caller must free": use ztlp_string_free().
 *
 * 4. **Memory safety** — Every _new() has a matching _free(). Passing NULL
 *    to any _free() function is a safe no-op.
 *
 * 5. **Async operations** — Connection and tunnel operations use callbacks.
 *    Callbacks are invoked on a background thread (the Rust tokio runtime).
 *    Do NOT block in callbacks.
 *
 * 6. **Thread safety** — ZtlpClient handles are thread-safe. Multiple threads
 *    can call into the same client handle concurrently.
 *
 * ## Platform Notes
 *
 * ### iOS (Secure Enclave)
 *   - Build with cargo-lipo for universal static library
 *   - Use ztlp_identity_from_hardware(1) for Secure Enclave identity
 *   - Link: libztlp_proto.a + Security.framework
 *   - Min deployment target: iOS 13.0 (Secure Enclave P-256)
 *
 * ### Android (Keystore)
 *   - Build with cargo-ndk for per-ABI shared libraries
 *   - Use ztlp_identity_from_hardware(2) for Android Keystore
 *   - Link: libztlp_proto.so + Android Keystore via JNI
 *   - Min API level: 23 (Android 6.0, Keystore)
 *
 * ## Example Usage
 *
 * @code{.c}
 * #include "ztlp.h"
 * #include <stdio.h>
 *
 * void on_connected(void *user_data, int32_t result, const char *peer_addr) {
 *     if (result == ZTLP_OK) {
 *         printf("Connected to %s\n", peer_addr);
 *     } else {
 *         printf("Connection failed: %s\n", ztlp_last_error());
 *     }
 * }
 *
 * void on_data(void *user_data, const uint8_t *data, size_t len,
 *              ZtlpSession *session) {
 *     printf("Received %zu bytes from %s\n", len,
 *            ztlp_session_peer_node_id(session));
 * }
 *
 * int main(void) {
 *     ztlp_init();
 *
 *     // Generate or load identity
 *     ZtlpIdentity *id = ztlp_identity_generate();
 *     if (!id) {
 *         printf("Error: %s\n", ztlp_last_error());
 *         return 1;
 *     }
 *     printf("Node ID: %s\n", ztlp_identity_node_id(id));
 *
 *     // Save identity for next launch
 *     ztlp_identity_save(id, "identity.json");
 *
 *     // Create client (takes ownership of identity)
 *     ZtlpClient *client = ztlp_client_new(id);
 *     // id is now consumed — do NOT call ztlp_identity_free(id)
 *
 *     // Set data callback
 *     ztlp_set_recv_callback(client, on_data, NULL);
 *
 *     // Connect to peer
 *     ZtlpConfig *cfg = ztlp_config_new();
 *     ztlp_config_set_relay(cfg, "relay.ztlp.net:4433");
 *     ztlp_config_set_timeout_ms(cfg, 5000);
 *
 *     ztlp_connect(client, "peer-node-id-hex", cfg, on_connected, NULL);
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
 * @brief Data received callback.
 *
 * @param user_data  Opaque pointer passed to ztlp_set_recv_callback.
 * @param data       Pointer to received bytes. Valid only during callback.
 * @param len        Number of bytes received.
 * @param session    Session handle. Valid only during callback.
 *
 * @warning Invoked on the library's background thread. Do NOT block.
 */
typedef void (*ZtlpRecvCallback)(void *user_data, const uint8_t *data,
                                  size_t len, ZtlpSession *session);

/**
 * @brief Disconnect callback.
 *
 * @param user_data  Opaque pointer passed to ztlp_set_disconnect_callback.
 * @param session    Session handle. Valid only during callback.
 * @param reason     Disconnect reason (maps to result codes).
 *
 * @warning Invoked on the library's background thread. Do NOT block.
 */
typedef void (*ZtlpDisconnectCallback)(void *user_data, ZtlpSession *session,
                                        int32_t reason);

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

/**
 * @brief Connect to a ZTLP peer (async).
 *
 * Initiates a connection. The callback fires when complete.
 *
 * @param client    Valid client handle.
 * @param target    Target address or Node ID.
 * @param config    Optional config (NULL for defaults). NOT consumed.
 * @param callback  Called on completion (background thread).
 * @param user_data Opaque pointer for callback.
 * @return ZTLP_OK if initiated, negative on immediate failure.
 */
int32_t ztlp_connect(ZtlpClient *client, const char *target,
                      const ZtlpConfig *config, ZtlpConnectCallback callback,
                      void *user_data);

/**
 * @brief Listen for incoming connections (async).
 *
 * @param client     Valid client handle.
 * @param bind_addr  Bind address (e.g. "0.0.0.0:4433").
 * @param config     Optional config (NULL for defaults). NOT consumed.
 * @param callback   Called for each incoming connection.
 * @param user_data  Opaque pointer for callback.
 * @return ZTLP_OK if listening started, negative on failure.
 */
int32_t ztlp_listen(ZtlpClient *client, const char *bind_addr,
                     const ZtlpConfig *config, ZtlpConnectCallback callback,
                     void *user_data);

/* ═══════════════════════════════════════════════════════════════════════════
 * Data Transfer
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Send data through the active session.
 *
 * Data is copied internally — the caller's buffer can be reused immediately.
 *
 * @param client  Valid, connected client handle.
 * @param data    Pointer to data bytes.
 * @param len     Number of bytes to send.
 * @return ZTLP_OK on success, ZTLP_NOT_CONNECTED if no active session.
 */
int32_t ztlp_send(ZtlpClient *client, const uint8_t *data, size_t len);

/**
 * @brief Set the receive data callback.
 *
 * Only one callback at a time. Setting a new one replaces the previous.
 *
 * @param client    Valid client handle.
 * @param callback  Data receive callback.
 * @param user_data Opaque pointer for callback.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_set_recv_callback(ZtlpClient *client, ZtlpRecvCallback callback,
                                void *user_data);

/**
 * @brief Set the disconnect callback.
 *
 * @param client    Valid client handle.
 * @param callback  Disconnect callback.
 * @param user_data Opaque pointer for callback.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_set_disconnect_callback(ZtlpClient *client,
                                      ZtlpDisconnectCallback callback,
                                      void *user_data);

/**
 * @brief Disconnect from the current session.
 *
 * Stops the background recv loop and releases the active session.
 *
 * @param client  Valid client handle.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_disconnect(ZtlpClient *client);

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

/**
 * @brief Start a TCP tunnel (local port forwarding over ZTLP).
 *
 * Listens on local_port and forwards to remote_host:remote_port via ZTLP.
 *
 * @param client       Valid, connected client handle.
 * @param local_port   Local TCP port to listen on.
 * @param remote_host  Hostname on the remote side.
 * @param remote_port  TCP port on the remote side.
 * @param callback     Called when tunnel is established or fails.
 * @param user_data    Opaque pointer for callback.
 * @return ZTLP_OK if initiated, negative on failure.
 */
int32_t ztlp_tunnel_start(ZtlpClient *client, uint16_t local_port,
                           const char *remote_host, uint16_t remote_port,
                           ZtlpConnectCallback callback, void *user_data);

/**
 * @brief Stop the active TCP tunnel.
 *
 * @param client  Valid client handle.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_tunnel_stop(ZtlpClient *client);

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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZTLP_H */
