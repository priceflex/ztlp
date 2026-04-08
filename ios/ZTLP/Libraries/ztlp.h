/**
 * @file ztlp.h
 * @brief ZTLP (Zero Trust Layer Protocol) Mobile SDK — C FFI API
 * @version 0.15.0
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

/**
 * Callback for sending pre-encrypted ACK packets via a platform-native socket.
 *
 * The library encrypts ACK frames into full ZTLP wire packets and invokes
 * this callback with the raw bytes and destination address. The platform
 * should send via a separate UDP socket/NWConnection to avoid kernel
 * contention with the library's internal recv socket.
 *
 * @param user_data  Opaque context passed during registration.
 * @param data       Pre-encrypted ZTLP packet bytes (ready to send as-is).
 * @param len        Length of the data in bytes.
 * @param dest_addr  Destination address as "IP:port" string (e.g., "34.219.64.205:23095").
 *
 * @warning Invoked on the library's background thread. Do NOT block.
 */
typedef void (*ZtlpAckSendCallback)(void *user_data, const uint8_t *data,
                                     size_t len, const char *dest_addr);

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
 * @brief Register a callback for ACK packet sending via platform-native I/O.
 *
 * When registered, the library will invoke this callback with pre-encrypted
 * ACK packets. The platform should send these bytes via a separate UDP
 * socket (e.g., NWConnection on iOS) to avoid kernel contention.
 *
 * @param client     The ZTLP client handle.
 * @param callback   Function pointer for ACK sending.
 * @param user_data  Opaque context passed to the callback.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_set_ack_send_callback(ZtlpClient *client,
                                    ZtlpAckSendCallback callback,
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

/**
 * @brief Disconnect the tunnel transport only (keep VIP proxy listeners alive).
 *
 * Used for reconnect flows — stops the recv loop and clears the session,
 * but preserves VIP proxy TCP listeners and the runtime. After calling this,
 * call ztlp_connect() again and then ztlp_vip_start() to hot-swap the
 * tunnel session into the existing proxy listeners.
 *
 * Sets state to Reconnecting (not Disconnected).
 *
 * @param client  Valid client handle.
 * @return ZTLP_OK on success.
 */
int32_t ztlp_disconnect_transport(ZtlpClient *client);

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

/**
 * @brief Create a new packet router for the iOS utun interface.
 *
 * Initializes a userspace TCP/IP handler that processes raw IPv4 packets
 * from the tunnel interface. Maps destination IPs in 10.122.0.0/16 to
 * ZTLP service names and creates mux streams to the gateway.
 *
 * @param client       Valid client handle.
 * @param tunnel_addr  IPv4 address of the utun interface (e.g., "10.122.0.100").
 *                     Null-terminated C string.
 * @return 0 on success, negative on error.
 */
int32_t ztlp_router_new(ZtlpClient *client, const char *tunnel_addr);

/**
 * @brief Register a VIP service with the packet router.
 *
 * Maps a VIP address to a ZTLP service name. Traffic to this VIP on any
 * port will be routed through a ZTLP mux stream to the named service.
 *
 * Example: ztlp_router_add_service(client, "10.122.0.1", "vault")
 *
 * @param client        Valid client handle.
 * @param vip           VIP IPv4 address (e.g., "10.122.0.1"). Null-terminated.
 * @param service_name  ZTLP service name (e.g., "vault"). Null-terminated.
 * @return 0 on success, negative on error.
 */
int32_t ztlp_router_add_service(ZtlpClient *client,
                                 const char *vip,
                                 const char *service_name);

/**
 * @brief Write a raw IPv4 packet into the packet router.
 *
 * Called from Swift when NEPacketTunnelProvider.readPackets() delivers a
 * packet from the utun interface. The router parses IP/TCP, manages
 * connection state, and queues response packets.
 *
 * After calling this, call ztlp_router_read_packet() to retrieve any
 * outbound response packets (SYN-ACK, ACK, data, FIN).
 *
 * @param client  Valid client handle.
 * @param data    Raw IPv4 packet bytes.
 * @param len     Length of the packet in bytes.
 * @return 0 on success, negative on error.
 */
int32_t ztlp_router_write_packet(ZtlpClient *client,
                                  const uint8_t *data,
                                  size_t len);

/**
 * @brief Read the next outbound IPv4 packet from the router.
 *
 * Returns one complete IPv4 packet to inject back into the utun interface
 * via NEPacketTunnelProvider.writePackets(). Call in a loop until 0 is
 * returned to drain all queued packets.
 *
 * @param client   Valid client handle.
 * @param buf      Output buffer for the IPv4 packet.
 * @param buf_len  Size of the output buffer in bytes.
 * @return Positive: bytes written to buf. 0: no packets available. Negative: error.
 */
int32_t ztlp_router_read_packet(ZtlpClient *client,
                                 uint8_t *buf,
                                 size_t buf_len);

/**
 * @brief Stop and destroy the packet router.
 *
 * Cleans up all TCP flows and releases resources. Call when tearing down
 * the VPN tunnel.
 *
 * @param client  Valid client handle.
 * @return 0 on success, negative on error.
 */
int32_t ztlp_router_stop(ZtlpClient *client);

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

/**
 * @brief Build an ACK frame: [0x01 | ack_seq(8 bytes BE)].
 *
 * @param ack_seq     Acknowledged data sequence number.
 * @param out_buf     Output buffer (needs at least 9 bytes).
 * @param out_buf_len Size of out_buf.
 * @param out_written Receives 9 on success.
 * @return 0 on success, negative error code on failure.
 */
int32_t ztlp_build_ack(
    uint64_t ack_seq,
    uint8_t *out_buf, size_t out_buf_len,
    size_t *out_written
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZTLP_H */
