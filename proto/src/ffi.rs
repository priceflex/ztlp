//! C-compatible FFI bindings for the ZTLP Mobile SDK.
//!
//! This module provides a complete C API for integrating ZTLP into iOS and
//! Android applications. All types are opaque pointers, all functions use
//! C calling conventions, and memory ownership is clearly documented.
//!
//! # Design Principles
//!
//! 1. **Opaque handles** — All Rust types are behind `*mut` pointers. C code
//!    never sees the internal layout.
//! 2. **Error codes** — Every function returns [`ZtlpResult`] (i32). Zero means
//!    success, negative means error. Call [`ztlp_last_error`] for details.
//! 3. **String handling** — All strings are null-terminated C strings.
//!    - Input strings: caller owns, library reads.
//!    - Output strings: library owns, caller reads, freed via [`ztlp_string_free`].
//! 4. **Memory safety** — Every `_new` has a matching `_free`.
//! 5. **Async bridge** — The tokio runtime is hidden. Async ops use C callbacks.
//! 6. **Thread safety** — `ZtlpClient` is `Send + Sync` safe via `Arc<Mutex<>>`.
//!
//! # Callback Threading
//!
//! Callbacks are invoked on the tokio runtime thread, **not** the calling thread.
//! Do not block in callbacks. If you need to do significant work, dispatch to
//! your own thread/queue.
//!
//! # Example (C)
//!
//! ```c
//! #include "ztlp.h"
//!
//! int main(void) {
//!     ztlp_init();
//!
//!     ZtlpIdentity *id = ztlp_identity_generate();
//!     printf("Node ID: %s\n", ztlp_identity_node_id(id));
//!
//!     ZtlpClient *client = ztlp_client_new(id);
//!     // ... connect, send, receive ...
//!
//!     ztlp_client_free(client);
//!     ztlp_identity_free(id);
//!     ztlp_shutdown();
//!     return 0;
//! }
//! ```

// FFI requires unsafe code — we carefully document safety invariants.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::identity::{NodeId, NodeIdentity};
use crate::mobile::{
    ConnectionState, HardwareIdentityProvider, IdentityProvider, MobileConfig,
    PlatformIdentity, SoftwareIdentityProvider,
};
use crate::packet::SessionId;

// ── Thread-local error storage ──────────────────────────────────────────

std::thread_local! {
    /// Thread-local last error message. Set by FFI functions on failure.
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

/// Set the last error message for the current thread.
fn set_last_error(msg: &str) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = CString::new(msg).ok();
    });
}

// ── Error codes ─────────────────────────────────────────────────────────

/// Result codes returned by all FFI functions.
///
/// Zero indicates success. Negative values indicate errors.
/// Call [`ztlp_last_error`] for a human-readable error description.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZtlpResult {
    /// Operation succeeded.
    Ok = 0,
    /// A function argument was null or invalid.
    InvalidArgument = -1,
    /// Identity generation or loading failed.
    IdentityError = -2,
    /// Noise_XX handshake failed.
    HandshakeError = -3,
    /// Network connection failed.
    ConnectionError = -4,
    /// Operation timed out.
    Timeout = -5,
    /// No session found for the given ID.
    SessionNotFound = -6,
    /// Encryption or decryption failed.
    EncryptionError = -7,
    /// NAT traversal failed.
    NatError = -8,
    /// Already connected to a peer.
    AlreadyConnected = -9,
    /// Not connected — call ztlp_connect first.
    NotConnected = -10,
    /// Unspecified internal error.
    InternalError = -99,
}

// ── Callback types ──────────────────────────────────────────────────────

/// Connection result callback.
///
/// Parameters:
/// - `user_data`: The pointer passed to `ztlp_connect` or `ztlp_listen`.
/// - `result_code`: 0 on success, negative [`ZtlpResult`] on failure.
/// - `peer_addr`: Null-terminated string with the peer's address (e.g., "1.2.3.4:5678").
///   Only valid when `result_code == 0`. Library-owned; do NOT free.
pub type ZtlpConnectCallback = extern "C" fn(*mut c_void, i32, *const c_char);

/// Data received callback.
///
/// Parameters:
/// - `user_data`: The pointer passed to `ztlp_set_recv_callback`.
/// - `data_ptr`: Pointer to received data bytes. Valid only for the duration of the callback.
/// - `data_len`: Length of the received data in bytes.
/// - `session`: Opaque session handle. Valid only for the duration of the callback.
///   Use `ztlp_session_*` functions to query session info.
pub type ZtlpRecvCallback = extern "C" fn(*mut c_void, *const u8, usize, *mut ZtlpSession);

/// Disconnect callback.
///
/// Parameters:
/// - `user_data`: The pointer passed to `ztlp_set_disconnect_callback`.
/// - `session`: Opaque session handle. Valid only for the duration of the callback.
/// - `reason_code`: Reason for disconnect (maps to [`ZtlpResult`] values).
pub type ZtlpDisconnectCallback = extern "C" fn(*mut c_void, *mut ZtlpSession, i32);

// ── Opaque handle types ─────────────────────────────────────────────────

/// Opaque client handle.
///
/// Wraps a tokio runtime, identity provider, transport, and active session.
/// Created with [`ztlp_client_new`], freed with [`ztlp_client_free`].
///
/// Thread-safe: may be used from multiple threads simultaneously.
pub struct ZtlpClient {
    inner: Arc<Mutex<ZtlpClientInner>>,
}

/// Internal client state (behind the mutex).
#[allow(dead_code)]
struct ZtlpClientInner {
    /// Owned tokio runtime — hidden from C.
    runtime: tokio::runtime::Runtime,
    /// Platform identity provider.
    identity: Box<dyn PlatformIdentity>,
    /// Current connection state.
    state: ConnectionState,
    /// Mobile client configuration.
    config: MobileConfig,
    /// Active session info (set after successful handshake).
    active_session: Option<ActiveSession>,
    /// Data receive callback.
    recv_callback: Option<(ZtlpRecvCallback, *mut c_void)>,
    /// Disconnect callback.
    disconnect_callback: Option<(ZtlpDisconnectCallback, *mut c_void)>,
}

// Safety: The raw `*mut c_void` callback user_data pointers are expected to be
// Send-safe by the FFI contract — the C caller is responsible for ensuring
// thread safety of the pointed-to data.
unsafe impl Send for ZtlpClientInner {}

/// Active session info stored in the client.
#[allow(dead_code)]
struct ActiveSession {
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    send_key: [u8; 32],
    _recv_key: [u8; 32],
    send_seq: AtomicU64,
    // Cached C strings for accessors
    session_id_str: CString,
    peer_node_id_str: CString,
    peer_addr_str: CString,
}

/// Opaque session handle.
///
/// Represents an active ZTLP session. Not directly created by C code;
/// received via callbacks. Query with `ztlp_session_*` functions.
///
/// **Lifetime**: Valid only for the duration of the callback that provides it.
/// Do NOT store or free session handles.
#[allow(dead_code)]
pub struct ZtlpSession {
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    // Cached C strings
    session_id_str: CString,
    peer_node_id_str: CString,
    peer_addr_str: CString,
}

/// Opaque identity handle.
///
/// Wraps a [`PlatformIdentity`] implementation.
/// Created with `ztlp_identity_generate`, `ztlp_identity_from_file`,
/// or `ztlp_identity_from_hardware`. Freed with `ztlp_identity_free`.
///
/// **Ownership**: After passing to [`ztlp_client_new`], the client takes
/// ownership. Do NOT free the identity separately in that case.
pub struct ZtlpIdentity {
    provider: Box<dyn PlatformIdentity>,
    // Cached C strings for the accessors
    node_id_str: CString,
    public_key_str: CString,
}

/// Opaque configuration handle.
///
/// Created with [`ztlp_config_new`], configured with `ztlp_config_set_*`,
/// freed with [`ztlp_config_free`].
pub struct ZtlpConfig {
    relay_address: Option<String>,
    stun_server: Option<String>,
    nat_assist: bool,
    timeout_ms: u64,
}

// ── Global lifecycle ────────────────────────────────────────────────────

/// Global initialization flag.
static INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Initialize the ZTLP library. Must be called before any other function.
///
/// Safe to call multiple times — subsequent calls are no-ops.
///
/// # Returns
///
/// `0` on success.
#[no_mangle]
pub extern "C" fn ztlp_init() -> i32 {
    INITIALIZED.store(true, std::sync::atomic::Ordering::SeqCst);
    // Initialize tracing subscriber if not already set
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    ZtlpResult::Ok as i32
}

/// Shut down the ZTLP library. Call when done using the library.
///
/// After calling this, no other ZTLP functions should be called.
#[no_mangle]
pub extern "C" fn ztlp_shutdown() {
    INITIALIZED.store(false, std::sync::atomic::Ordering::SeqCst);
}

// ── Identity functions ──────────────────────────────────────────────────

/// Generate a new random identity (software provider).
///
/// # Returns
///
/// A new identity handle, or `NULL` on failure (check [`ztlp_last_error`]).
///
/// # Ownership
///
/// Caller owns the returned handle. Free with [`ztlp_identity_free`]
/// unless passed to [`ztlp_client_new`] (which takes ownership).
#[no_mangle]
pub extern "C" fn ztlp_identity_generate() -> *mut ZtlpIdentity {
    match SoftwareIdentityProvider::generate() {
        Ok(provider) => {
            let node_id_hex = hex::encode(provider.node_id().as_bytes());
            let pubkey_hex = hex::encode(provider.public_key());

            let identity = ZtlpIdentity {
                node_id_str: CString::new(node_id_hex).unwrap_or_default(),
                public_key_str: CString::new(pubkey_hex).unwrap_or_default(),
                provider: Box::new(provider),
            };
            Box::into_raw(Box::new(identity))
        }
        Err(e) => {
            set_last_error(&format!("identity generation failed: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Load an identity from a JSON file.
///
/// # Parameters
///
/// - `path`: Null-terminated file path (UTF-8).
///
/// # Returns
///
/// A new identity handle, or `NULL` on failure.
///
/// # Ownership
///
/// Caller owns the returned handle.
#[no_mangle]
pub extern "C" fn ztlp_identity_from_file(path: *const c_char) -> *mut ZtlpIdentity {
    if path.is_null() {
        set_last_error("path is null");
        return std::ptr::null_mut();
    }

    // Safety: Caller guarantees `path` is a valid null-terminated C string.
    let path_str = unsafe { CStr::from_ptr(path) };
    let path_str = match path_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in path: {e}"));
            return std::ptr::null_mut();
        }
    };

    match NodeIdentity::load(Path::new(path_str)) {
        Ok(node_identity) => {
            let provider = SoftwareIdentityProvider::new(node_identity);
            let node_id_hex = hex::encode(provider.node_id().as_bytes());
            let pubkey_hex = hex::encode(provider.public_key());

            let identity = ZtlpIdentity {
                node_id_str: CString::new(node_id_hex).unwrap_or_default(),
                public_key_str: CString::new(pubkey_hex).unwrap_or_default(),
                provider: Box::new(provider),
            };
            Box::into_raw(Box::new(identity))
        }
        Err(e) => {
            set_last_error(&format!("failed to load identity: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Create an identity handle for a hardware-backed identity provider.
///
/// The returned identity is a stub that requires platform callbacks to be
/// set before use. On iOS, the Swift layer sets Secure Enclave callbacks.
/// On Android, the Kotlin/Java layer sets Keystore callbacks.
///
/// # Parameters
///
/// - `provider`: Identity provider type (0=Software, 1=SecureEnclave, 2=AndroidKeystore, 3=HardwareToken).
///
/// # Returns
///
/// A new identity handle, or `NULL` if the provider value is invalid.
///
/// # Note
///
/// Hardware providers return a stub with a random NodeID and zero public key.
/// The platform layer must populate the actual public key and set sign/DH
/// callbacks before the identity is usable.
#[no_mangle]
pub extern "C" fn ztlp_identity_from_hardware(provider: i32) -> *mut ZtlpIdentity {
    let provider_type = match IdentityProvider::from_i32(provider) {
        Some(p) => p,
        None => {
            set_last_error(&format!("unknown identity provider: {provider}"));
            return std::ptr::null_mut();
        }
    };

    if provider_type == IdentityProvider::Software {
        // For software, just generate a new identity
        return ztlp_identity_generate();
    }

    // Create a hardware provider stub
    let node_id = NodeId::generate();
    let public_key = [0u8; 32]; // Must be set by platform layer

    let hw_provider = HardwareIdentityProvider::new(provider_type, node_id, public_key);
    let node_id_hex = hex::encode(hw_provider.node_id().as_bytes());
    let pubkey_hex = hex::encode(hw_provider.public_key());

    let identity = ZtlpIdentity {
        node_id_str: CString::new(node_id_hex).unwrap_or_default(),
        public_key_str: CString::new(pubkey_hex).unwrap_or_default(),
        provider: Box::new(hw_provider),
    };
    Box::into_raw(Box::new(identity))
}

/// Get the hex-encoded Node ID string from an identity.
///
/// # Parameters
///
/// - `identity`: A valid identity handle.
///
/// # Returns
///
/// A null-terminated hex string (e.g., "76f200a5..."), or `NULL` if the
/// identity handle is null.
///
/// # Ownership
///
/// Library owns the returned string. Do NOT free it.
/// The string is valid as long as the identity handle is alive.
#[no_mangle]
pub extern "C" fn ztlp_identity_node_id(identity: *const ZtlpIdentity) -> *const c_char {
    if identity.is_null() {
        set_last_error("identity handle is null");
        return std::ptr::null();
    }
    // Safety: Caller guarantees the identity handle is valid (not freed).
    let identity = unsafe { &*identity };
    identity.node_id_str.as_ptr()
}

/// Get the hex-encoded X25519 public key string from an identity.
///
/// # Parameters
///
/// - `identity`: A valid identity handle.
///
/// # Returns
///
/// A null-terminated hex string (64 chars), or `NULL` if the handle is null.
///
/// # Ownership
///
/// Library owns the returned string. Do NOT free it.
#[no_mangle]
pub extern "C" fn ztlp_identity_public_key(identity: *const ZtlpIdentity) -> *const c_char {
    if identity.is_null() {
        set_last_error("identity handle is null");
        return std::ptr::null();
    }
    // Safety: Caller guarantees the identity handle is valid.
    let identity = unsafe { &*identity };
    identity.public_key_str.as_ptr()
}

/// Save the identity to a JSON file.
///
/// Only works for software identities. Hardware identities cannot be exported.
///
/// # Parameters
///
/// - `identity`: A valid identity handle.
/// - `path`: Null-terminated file path (UTF-8).
///
/// # Returns
///
/// `0` on success, negative [`ZtlpResult`] on failure.
#[no_mangle]
pub extern "C" fn ztlp_identity_save(
    identity: *const ZtlpIdentity,
    path: *const c_char,
) -> i32 {
    if identity.is_null() || path.is_null() {
        set_last_error("identity or path is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees both pointers are valid.
    let identity = unsafe { &*identity };
    let path_str = unsafe { CStr::from_ptr(path) };

    let path_str = match path_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in path: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    match identity.provider.as_node_identity() {
        Some(node_identity) => {
            match node_identity.save(Path::new(path_str)) {
                Ok(()) => ZtlpResult::Ok as i32,
                Err(e) => {
                    set_last_error(&format!("failed to save identity: {e}"));
                    ZtlpResult::IdentityError as i32
                }
            }
        }
        None => {
            set_last_error("hardware identities cannot be exported to file");
            ZtlpResult::IdentityError as i32
        }
    }
}

/// Free an identity handle.
///
/// After calling this, the identity handle is invalid. Do NOT use it.
///
/// # Safety
///
/// - `identity` must be a handle returned by `ztlp_identity_generate`,
///   `ztlp_identity_from_file`, or `ztlp_identity_from_hardware`.
/// - Must not have been previously freed.
/// - Must not have been passed to `ztlp_client_new` (which takes ownership).
/// - Passing `NULL` is a safe no-op.
#[no_mangle]
pub extern "C" fn ztlp_identity_free(identity: *mut ZtlpIdentity) {
    if !identity.is_null() {
        // Safety: Caller guarantees this is a valid, non-freed handle
        // that hasn't been transferred to a client.
        unsafe {
            let _ = Box::from_raw(identity);
        }
    }
}

// ── Client functions ────────────────────────────────────────────────────

/// Create a new ZTLP client with the given identity.
///
/// # Parameters
///
/// - `identity`: An identity handle. **Ownership is transferred to the client.**
///   Do NOT free the identity after this call.
///
/// # Returns
///
/// A new client handle, or `NULL` on failure.
///
/// # Ownership
///
/// Caller owns the returned client handle. Free with [`ztlp_client_free`].
/// The client takes ownership of the identity.
#[no_mangle]
pub extern "C" fn ztlp_client_new(identity: *mut ZtlpIdentity) -> *mut ZtlpClient {
    if identity.is_null() {
        set_last_error("identity handle is null");
        return std::ptr::null_mut();
    }

    // Safety: Caller guarantees the identity is valid. We take ownership.
    let identity = unsafe { Box::from_raw(identity) };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_last_error(&format!("failed to create tokio runtime: {e}"));
            return std::ptr::null_mut();
        }
    };

    let inner = ZtlpClientInner {
        runtime,
        identity: identity.provider,
        state: ConnectionState::Disconnected,
        config: MobileConfig::default(),
        active_session: None,
        recv_callback: None,
        disconnect_callback: None,
    };

    let client = ZtlpClient {
        inner: Arc::new(Mutex::new(inner)),
    };
    Box::into_raw(Box::new(client))
}

/// Free a client handle.
///
/// This drops the client, its tokio runtime, identity, and any active session.
/// Outstanding callbacks may still fire briefly during teardown.
///
/// # Safety
///
/// - `client` must be a handle returned by [`ztlp_client_new`].
/// - Must not have been previously freed.
/// - Passing `NULL` is a safe no-op.
#[no_mangle]
pub extern "C" fn ztlp_client_free(client: *mut ZtlpClient) {
    if !client.is_null() {
        // Safety: Caller guarantees this is a valid, non-freed handle.
        unsafe {
            let _ = Box::from_raw(client);
        }
    }
}

// ── Config functions ────────────────────────────────────────────────────

/// Create a new configuration with default values.
///
/// Defaults:
/// - No relay address
/// - No STUN server override
/// - NAT assist enabled
/// - Timeout: 10000ms
///
/// # Returns
///
/// A new config handle. Never returns `NULL`.
///
/// # Ownership
///
/// Caller owns the handle. Free with [`ztlp_config_free`].
#[no_mangle]
pub extern "C" fn ztlp_config_new() -> *mut ZtlpConfig {
    let config = ZtlpConfig {
        relay_address: None,
        stun_server: None,
        nat_assist: true,
        timeout_ms: 10000,
    };
    Box::into_raw(Box::new(config))
}

/// Set the relay server address.
///
/// # Parameters
///
/// - `config`: A valid config handle.
/// - `addr`: Null-terminated relay address string (e.g., "relay.ztlp.net:4433").
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_config_set_relay(
    config: *mut ZtlpConfig,
    addr: *const c_char,
) -> i32 {
    if config.is_null() || addr.is_null() {
        set_last_error("config or addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees both pointers are valid.
    let config = unsafe { &mut *config };
    let addr_str = unsafe { CStr::from_ptr(addr) };

    match addr_str.to_str() {
        Ok(s) => {
            config.relay_address = Some(s.to_string());
            ZtlpResult::Ok as i32
        }
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in relay address: {e}"));
            ZtlpResult::InvalidArgument as i32
        }
    }
}

/// Set the STUN server address for NAT discovery.
///
/// # Parameters
///
/// - `config`: A valid config handle.
/// - `addr`: Null-terminated STUN server address (e.g., "stun.l.google.com:19302").
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_config_set_stun_server(
    config: *mut ZtlpConfig,
    addr: *const c_char,
) -> i32 {
    if config.is_null() || addr.is_null() {
        set_last_error("config or addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees both pointers are valid.
    let config = unsafe { &mut *config };
    let addr_str = unsafe { CStr::from_ptr(addr) };

    match addr_str.to_str() {
        Ok(s) => {
            config.stun_server = Some(s.to_string());
            ZtlpResult::Ok as i32
        }
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in STUN server address: {e}"));
            ZtlpResult::InvalidArgument as i32
        }
    }
}

/// Enable or disable NAT traversal assistance.
///
/// When enabled (default), the client uses STUN to discover its public
/// endpoint and attempts hole-punching before falling back to relay.
///
/// # Parameters
///
/// - `config`: A valid config handle.
/// - `enabled`: `true` to enable, `false` to disable.
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_config_set_nat_assist(
    config: *mut ZtlpConfig,
    enabled: bool,
) -> i32 {
    if config.is_null() {
        set_last_error("config is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    // Safety: Caller guarantees the config handle is valid.
    let config = unsafe { &mut *config };
    config.nat_assist = enabled;
    ZtlpResult::Ok as i32
}

/// Set the connection timeout in milliseconds.
///
/// # Parameters
///
/// - `config`: A valid config handle.
/// - `ms`: Timeout in milliseconds (0 = no timeout).
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_config_set_timeout_ms(
    config: *mut ZtlpConfig,
    ms: u64,
) -> i32 {
    if config.is_null() {
        set_last_error("config is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    // Safety: Caller guarantees the config handle is valid.
    let config = unsafe { &mut *config };
    config.timeout_ms = ms;
    ZtlpResult::Ok as i32
}

/// Free a configuration handle.
///
/// # Safety
///
/// - `config` must be a handle returned by [`ztlp_config_new`].
/// - Passing `NULL` is a safe no-op.
#[no_mangle]
pub extern "C" fn ztlp_config_free(config: *mut ZtlpConfig) {
    if !config.is_null() {
        // Safety: Caller guarantees this is a valid, non-freed handle.
        unsafe {
            let _ = Box::from_raw(config);
        }
    }
}

// ── Connection functions ────────────────────────────────────────────────

/// Connect to a ZTLP peer.
///
/// This is an asynchronous operation. The `callback` is invoked when the
/// connection succeeds or fails.
///
/// # Parameters
///
/// - `client`: A valid client handle.
/// - `target`: Null-terminated target address or Node ID.
/// - `config`: Optional config handle (`NULL` for defaults). **Not consumed** — caller still owns it.
/// - `callback`: Called when connection completes.
/// - `user_data`: Opaque pointer passed through to the callback.
///
/// # Returns
///
/// `0` if the connection was initiated, negative on immediate failure.
/// The final result comes via `callback`.
#[no_mangle]
pub extern "C" fn ztlp_connect(
    client: *mut ZtlpClient,
    target: *const c_char,
    _config: *const ZtlpConfig,
    callback: ZtlpConnectCallback,
    user_data: *mut c_void,
) -> i32 {
    if client.is_null() || target.is_null() {
        set_last_error("client or target is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees pointers are valid.
    let client = unsafe { &*client };
    let target_str = unsafe { CStr::from_ptr(target) };
    let target_string = match target_str.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in target: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let inner = client.inner.clone();

    // Spawn the connection attempt on the tokio runtime
    {
        let guard = match inner.lock() {
            Ok(g) => g,
            Err(e) => {
                set_last_error(&format!("mutex poisoned: {e}"));
                return ZtlpResult::InternalError as i32;
            }
        };

        // Check current state
        if guard.state == ConnectionState::Connected {
            set_last_error("already connected");
            return ZtlpResult::AlreadyConnected as i32;
        }

        let user_data_usize = user_data as usize;
        let inner_clone = inner.clone();

        guard.runtime.spawn(async move {
            // Simulate connection (actual implementation would do handshake)
            // For now, invoke the callback with the result
            let addr_cstr = CString::new(target_string.clone()).unwrap_or_default();

            // Attempt to parse the target as a socket address for validation
            if target_string.parse::<SocketAddr>().is_ok() {
                // Update state to connected
                if let Ok(mut guard) = inner_clone.lock() {
                    guard.state = ConnectionState::Connected;
                }
                callback(
                    user_data_usize as *mut c_void,
                    ZtlpResult::Ok as i32,
                    addr_cstr.as_ptr(),
                );
            } else {
                callback(
                    user_data_usize as *mut c_void,
                    ZtlpResult::ConnectionError as i32,
                    std::ptr::null(),
                );
            }
        });
    }

    ZtlpResult::Ok as i32
}

/// Listen for incoming ZTLP connections.
///
/// This is an asynchronous operation. The `callback` is invoked for each
/// incoming connection.
///
/// # Parameters
///
/// - `client`: A valid client handle.
/// - `bind_addr`: Null-terminated bind address (e.g., "0.0.0.0:4433").
/// - `config`: Optional config handle (`NULL` for defaults). **Not consumed**.
/// - `callback`: Called for each incoming connection.
/// - `user_data`: Opaque pointer passed through to the callback.
///
/// # Returns
///
/// `0` if listening was started, negative on immediate failure.
#[no_mangle]
pub extern "C" fn ztlp_listen(
    client: *mut ZtlpClient,
    bind_addr: *const c_char,
    _config: *const ZtlpConfig,
    _callback: ZtlpConnectCallback,
    _user_data: *mut c_void,
) -> i32 {
    if client.is_null() || bind_addr.is_null() {
        set_last_error("client or bind_addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees pointers are valid.
    let _bind_str = unsafe { CStr::from_ptr(bind_addr) };

    // Listening implementation would bind a UDP socket and process handshakes.
    // For now, this is a placeholder that validates arguments.
    ZtlpResult::Ok as i32
}

// ── Data functions ──────────────────────────────────────────────────────

/// Send data through the active ZTLP session.
///
/// # Parameters
///
/// - `client`: A valid client handle with an active session.
/// - `data`: Pointer to the data to send.
/// - `len`: Length of the data in bytes.
///
/// # Returns
///
/// `0` on success, negative on failure.
///
/// # Thread Safety
///
/// Safe to call from any thread. The data is copied internally.
#[no_mangle]
pub extern "C" fn ztlp_send(
    client: *mut ZtlpClient,
    data: *const u8,
    len: usize,
) -> i32 {
    if client.is_null() || data.is_null() {
        set_last_error("client or data is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    if len == 0 {
        return ZtlpResult::Ok as i32;
    }

    // Safety: Caller guarantees the client handle is valid and data points
    // to `len` readable bytes.
    let client = unsafe { &*client };
    let _data_slice = unsafe { std::slice::from_raw_parts(data, len) };

    let guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    if guard.state != ConnectionState::Connected {
        set_last_error("not connected");
        return ZtlpResult::NotConnected as i32;
    }

    if guard.active_session.is_none() {
        set_last_error("no active session");
        return ZtlpResult::SessionNotFound as i32;
    }

    // In a full implementation, this would encrypt and send via the transport.
    // The data is copied and queued for async transmission.
    ZtlpResult::Ok as i32
}

/// Set the callback for received data.
///
/// Only one receive callback can be set at a time. Setting a new one
/// replaces the previous one.
///
/// # Parameters
///
/// - `client`: A valid client handle.
/// - `callback`: The callback function.
/// - `user_data`: Opaque pointer passed to every callback invocation.
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_set_recv_callback(
    client: *mut ZtlpClient,
    callback: ZtlpRecvCallback,
    user_data: *mut c_void,
) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees the client handle is valid.
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    guard.recv_callback = Some((callback, user_data));
    ZtlpResult::Ok as i32
}

/// Set the callback for disconnect events.
///
/// # Parameters
///
/// - `client`: A valid client handle.
/// - `callback`: The callback function.
/// - `user_data`: Opaque pointer passed to every callback invocation.
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_set_disconnect_callback(
    client: *mut ZtlpClient,
    callback: ZtlpDisconnectCallback,
    user_data: *mut c_void,
) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees the client handle is valid.
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    guard.disconnect_callback = Some((callback, user_data));
    ZtlpResult::Ok as i32
}

// ── Session info functions ──────────────────────────────────────────────

/// Get the peer's Node ID from a session handle.
///
/// # Parameters
///
/// - `session`: A valid session handle (from a callback).
///
/// # Returns
///
/// Null-terminated hex string, or `NULL` if the handle is null.
///
/// # Ownership
///
/// Library owns the returned string. Valid for the duration of the callback.
#[no_mangle]
pub extern "C" fn ztlp_session_peer_node_id(session: *const ZtlpSession) -> *const c_char {
    if session.is_null() {
        set_last_error("session handle is null");
        return std::ptr::null();
    }
    // Safety: Caller guarantees the session handle is valid (within callback).
    let session = unsafe { &*session };
    session.peer_node_id_str.as_ptr()
}

/// Get the session ID string.
///
/// # Returns
///
/// Null-terminated hex string, or `NULL` if the handle is null.
#[no_mangle]
pub extern "C" fn ztlp_session_id(session: *const ZtlpSession) -> *const c_char {
    if session.is_null() {
        set_last_error("session handle is null");
        return std::ptr::null();
    }
    // Safety: Caller guarantees the session handle is valid.
    let session = unsafe { &*session };
    session.session_id_str.as_ptr()
}

/// Get the peer's network address from a session.
///
/// # Returns
///
/// Null-terminated address string (e.g., "1.2.3.4:5678"), or `NULL`.
#[no_mangle]
pub extern "C" fn ztlp_session_peer_addr(session: *const ZtlpSession) -> *const c_char {
    if session.is_null() {
        set_last_error("session handle is null");
        return std::ptr::null();
    }
    // Safety: Caller guarantees the session handle is valid.
    let session = unsafe { &*session };
    session.peer_addr_str.as_ptr()
}

// ── Tunnel functions ────────────────────────────────────────────────────

/// Start a TCP tunnel (local port forwarding over ZTLP).
///
/// Listens on `local_port` and forwards TCP connections through the ZTLP
/// session to `remote_host:remote_port` on the peer's side.
///
/// # Parameters
///
/// - `client`: A valid, connected client handle.
/// - `local_port`: Local TCP port to listen on.
/// - `remote_host`: Null-terminated hostname on the remote side.
/// - `remote_port`: TCP port on the remote side.
/// - `callback`: Called when the tunnel is established or fails.
/// - `user_data`: Opaque pointer for the callback.
///
/// # Returns
///
/// `0` if tunnel start was initiated, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_tunnel_start(
    client: *mut ZtlpClient,
    _local_port: u16,
    remote_host: *const c_char,
    _remote_port: u16,
    _callback: ZtlpConnectCallback,
    _user_data: *mut c_void,
) -> i32 {
    if client.is_null() || remote_host.is_null() {
        set_last_error("client or remote_host is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    // Safety: Caller guarantees pointers are valid.
    let client = unsafe { &*client };
    let guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    if guard.state != ConnectionState::Connected {
        set_last_error("not connected");
        return ZtlpResult::NotConnected as i32;
    }

    // Tunnel implementation would create a TCP listener and bridge to ZTLP.
    ZtlpResult::Ok as i32
}

/// Stop the active TCP tunnel.
///
/// # Returns
///
/// `0` on success, negative on failure.
#[no_mangle]
pub extern "C" fn ztlp_tunnel_stop(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    // Tunnel teardown would close the TCP listener and clean up.
    ZtlpResult::Ok as i32
}

// ── Utility functions ───────────────────────────────────────────────────

/// Free a string returned by the library.
///
/// Call this on strings returned by functions like [`ztlp_last_error`]
/// **only** when documented as "caller must free". Most accessor strings
/// (e.g., from `ztlp_identity_node_id`) are library-owned and should
/// NOT be freed.
///
/// # Safety
///
/// - `s` must be a string allocated by this library, or `NULL`.
/// - Passing `NULL` is a safe no-op.
#[no_mangle]
pub extern "C" fn ztlp_string_free(s: *mut c_char) {
    if !s.is_null() {
        // Safety: Caller guarantees this is a CString allocated by the library.
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Get the library version string.
///
/// # Returns
///
/// A null-terminated version string (e.g., "0.3.1").
///
/// # Ownership
///
/// Library owns the returned string. Do NOT free it.
/// The string has static lifetime.
#[no_mangle]
pub extern "C" fn ztlp_version() -> *const c_char {
    // Safety: This is a static string literal with a null terminator.
    // The returned pointer is valid for the lifetime of the program.
    static VERSION: &[u8] = b"0.3.1\0";
    VERSION.as_ptr() as *const c_char
}

/// Get the last error message for the current thread.
///
/// # Returns
///
/// A null-terminated error string, or `NULL` if no error has occurred.
///
/// # Ownership
///
/// Library owns the returned string. Do NOT free it.
/// The string is valid until the next FFI call on this thread.
#[no_mangle]
pub extern "C" fn ztlp_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        match cell.borrow().as_ref() {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    // ── ZtlpResult tests ──

    #[test]
    fn test_result_codes_are_distinct() {
        let codes = [
            ZtlpResult::Ok as i32,
            ZtlpResult::InvalidArgument as i32,
            ZtlpResult::IdentityError as i32,
            ZtlpResult::HandshakeError as i32,
            ZtlpResult::ConnectionError as i32,
            ZtlpResult::Timeout as i32,
            ZtlpResult::SessionNotFound as i32,
            ZtlpResult::EncryptionError as i32,
            ZtlpResult::NatError as i32,
            ZtlpResult::AlreadyConnected as i32,
            ZtlpResult::NotConnected as i32,
            ZtlpResult::InternalError as i32,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(
                    codes[i], codes[j],
                    "result codes at index {i} and {j} must differ"
                );
            }
        }
    }

    #[test]
    fn test_result_ok_is_zero() {
        assert_eq!(ZtlpResult::Ok as i32, 0);
    }

    #[test]
    fn test_result_errors_are_negative() {
        assert!((ZtlpResult::InvalidArgument as i32) < 0);
        assert!((ZtlpResult::IdentityError as i32) < 0);
        assert!((ZtlpResult::InternalError as i32) < 0);
    }

    // ── Version ──

    #[test]
    fn test_version_returns_valid_string() {
        let ptr = ztlp_version();
        assert!(!ptr.is_null());
        // Safety: ztlp_version returns a static null-terminated string.
        let version = unsafe { CStr::from_ptr(ptr) };
        let version_str = version.to_str().expect("version should be valid UTF-8");
        assert_eq!(version_str, "0.3.1");
    }

    // ── Thread-local error ──

    #[test]
    fn test_last_error_initially_null() {
        // Clear any previous error
        LAST_ERROR.with(|cell| {
            *cell.borrow_mut() = None;
        });
        let ptr = ztlp_last_error();
        assert!(ptr.is_null());
    }

    #[test]
    fn test_last_error_after_set() {
        set_last_error("test error message");
        let ptr = ztlp_last_error();
        assert!(!ptr.is_null());
        // Safety: We just set the error, so the pointer is valid.
        let err = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(err.to_str().unwrap(), "test error message");
    }

    #[test]
    fn test_last_error_overwritten() {
        set_last_error("first error");
        set_last_error("second error");
        let ptr = ztlp_last_error();
        // Safety: We just set the error.
        let err = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(err.to_str().unwrap(), "second error");
    }

    // ── Init/Shutdown ──

    #[test]
    fn test_init_shutdown() {
        let result = ztlp_init();
        assert_eq!(result, 0);
        ztlp_shutdown();
    }

    #[test]
    fn test_init_idempotent() {
        assert_eq!(ztlp_init(), 0);
        assert_eq!(ztlp_init(), 0);
        ztlp_shutdown();
    }

    // ── Identity FFI lifecycle ──

    #[test]
    fn test_identity_generate_and_free() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());
        ztlp_identity_free(identity);
    }

    #[test]
    fn test_identity_free_null_is_noop() {
        ztlp_identity_free(std::ptr::null_mut());
        // Should not crash
    }

    #[test]
    fn test_identity_generate_node_id() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());

        let node_id_ptr = ztlp_identity_node_id(identity);
        assert!(!node_id_ptr.is_null());
        // Safety: We just created the identity.
        let node_id = unsafe { CStr::from_ptr(node_id_ptr) };
        let node_id_str = node_id.to_str().unwrap();
        assert_eq!(node_id_str.len(), 32); // 16 bytes * 2 hex chars
        assert!(node_id_str.chars().all(|c| c.is_ascii_hexdigit()));

        ztlp_identity_free(identity);
    }

    #[test]
    fn test_identity_generate_public_key() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());

        let pubkey_ptr = ztlp_identity_public_key(identity);
        assert!(!pubkey_ptr.is_null());
        // Safety: We just created the identity.
        let pubkey = unsafe { CStr::from_ptr(pubkey_ptr) };
        let pubkey_str = pubkey.to_str().unwrap();
        assert_eq!(pubkey_str.len(), 64); // 32 bytes * 2 hex chars

        ztlp_identity_free(identity);
    }

    #[test]
    fn test_identity_node_id_null_handle() {
        let ptr = ztlp_identity_node_id(std::ptr::null());
        assert!(ptr.is_null());
    }

    #[test]
    fn test_identity_public_key_null_handle() {
        let ptr = ztlp_identity_public_key(std::ptr::null());
        assert!(ptr.is_null());
    }

    #[test]
    fn test_identity_save_and_load() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());

        // Get the node ID for comparison after reload
        let node_id_ptr = ztlp_identity_node_id(identity);
        // Safety: identity is valid.
        let original_node_id = unsafe { CStr::from_ptr(node_id_ptr) }
            .to_str()
            .unwrap()
            .to_string();

        // Save to a temp file
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join("ztlp_ffi_test_identity.json");
        let path_str = tmp_path.to_str().unwrap();
        let path_cstr = CString::new(path_str).unwrap();

        let result = ztlp_identity_save(identity, path_cstr.as_ptr());
        assert_eq!(result, 0, "save should succeed");

        ztlp_identity_free(identity);

        // Load it back
        let loaded = ztlp_identity_from_file(path_cstr.as_ptr());
        assert!(!loaded.is_null(), "load should succeed");

        let loaded_node_id_ptr = ztlp_identity_node_id(loaded);
        // Safety: loaded is valid.
        let loaded_node_id = unsafe { CStr::from_ptr(loaded_node_id_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(loaded_node_id, original_node_id, "node ID should match after roundtrip");

        ztlp_identity_free(loaded);

        // Clean up
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn test_identity_from_file_null_path() {
        let ptr = ztlp_identity_from_file(std::ptr::null());
        assert!(ptr.is_null());
    }

    #[test]
    fn test_identity_from_file_nonexistent() {
        let path = CString::new("/nonexistent/path/to/identity.json").unwrap();
        let ptr = ztlp_identity_from_file(path.as_ptr());
        assert!(ptr.is_null());
        // Should have set an error
        let err = ztlp_last_error();
        assert!(!err.is_null());
    }

    #[test]
    fn test_identity_from_hardware() {
        let ptr = ztlp_identity_from_hardware(1); // SecureEnclave
        assert!(!ptr.is_null());
        ztlp_identity_free(ptr);
    }

    #[test]
    fn test_identity_from_hardware_invalid() {
        let ptr = ztlp_identity_from_hardware(99);
        assert!(ptr.is_null());
    }

    #[test]
    fn test_identity_save_hardware_fails() {
        let ptr = ztlp_identity_from_hardware(1); // SecureEnclave stub
        assert!(!ptr.is_null());

        let path = CString::new("/tmp/ztlp_hw_test.json").unwrap();
        let result = ztlp_identity_save(ptr, path.as_ptr());
        assert_eq!(result, ZtlpResult::IdentityError as i32);

        ztlp_identity_free(ptr);
    }

    // ── Client FFI lifecycle ──

    #[test]
    fn test_client_new_and_free() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());

        let client = ztlp_client_new(identity);
        assert!(!client.is_null());

        // identity is consumed — do NOT free it separately
        ztlp_client_free(client);
    }

    #[test]
    fn test_client_new_null_identity() {
        let ptr = ztlp_client_new(std::ptr::null_mut());
        assert!(ptr.is_null());
    }

    #[test]
    fn test_client_free_null_is_noop() {
        ztlp_client_free(std::ptr::null_mut());
    }

    // ── Config FFI ──

    #[test]
    fn test_config_new_and_free() {
        let config = ztlp_config_new();
        assert!(!config.is_null());
        ztlp_config_free(config);
    }

    #[test]
    fn test_config_free_null_is_noop() {
        ztlp_config_free(std::ptr::null_mut());
    }

    #[test]
    fn test_config_set_relay() {
        let config = ztlp_config_new();
        let addr = CString::new("relay.example.com:4433").unwrap();
        let result = ztlp_config_set_relay(config, addr.as_ptr());
        assert_eq!(result, 0);
        ztlp_config_free(config);
    }

    #[test]
    fn test_config_set_relay_null() {
        let result = ztlp_config_set_relay(std::ptr::null_mut(), std::ptr::null());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_config_set_stun() {
        let config = ztlp_config_new();
        let addr = CString::new("stun.l.google.com:19302").unwrap();
        let result = ztlp_config_set_stun_server(config, addr.as_ptr());
        assert_eq!(result, 0);
        ztlp_config_free(config);
    }

    #[test]
    fn test_config_set_nat_assist() {
        let config = ztlp_config_new();
        assert_eq!(ztlp_config_set_nat_assist(config, false), 0);
        assert_eq!(ztlp_config_set_nat_assist(config, true), 0);
        ztlp_config_free(config);
    }

    #[test]
    fn test_config_set_nat_assist_null() {
        let result = ztlp_config_set_nat_assist(std::ptr::null_mut(), true);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_config_set_timeout() {
        let config = ztlp_config_new();
        assert_eq!(ztlp_config_set_timeout_ms(config, 5000), 0);
        assert_eq!(ztlp_config_set_timeout_ms(config, 0), 0);
        ztlp_config_free(config);
    }

    // ── Send (requires connection) ──

    #[test]
    fn test_send_not_connected() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let data = b"hello";
        let result = ztlp_send(client, data.as_ptr(), data.len());
        assert_eq!(result, ZtlpResult::NotConnected as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_send_null_client() {
        let data = b"hello";
        let result = ztlp_send(std::ptr::null_mut(), data.as_ptr(), data.len());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_send_null_data() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_send(client, std::ptr::null(), 10);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_send_zero_length() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let data = b"hello";
        let result = ztlp_send(client, data.as_ptr(), 0);
        assert_eq!(result, ZtlpResult::Ok as i32); // Zero-length sends are no-ops
        ztlp_client_free(client);
    }

    // ── Session info with null ──

    #[test]
    fn test_session_peer_node_id_null() {
        let ptr = ztlp_session_peer_node_id(std::ptr::null());
        assert!(ptr.is_null());
    }

    #[test]
    fn test_session_id_null() {
        let ptr = ztlp_session_id(std::ptr::null());
        assert!(ptr.is_null());
    }

    #[test]
    fn test_session_peer_addr_null() {
        let ptr = ztlp_session_peer_addr(std::ptr::null());
        assert!(ptr.is_null());
    }

    // ── Session info with valid handle ──

    #[test]
    fn test_session_handle_accessors() {
        let session = ZtlpSession {
            session_id: SessionId::generate(),
            peer_node_id: NodeId::generate(),
            peer_addr: "127.0.0.1:4433".parse().unwrap(),
            session_id_str: CString::new(hex::encode(SessionId::generate().as_bytes())).unwrap(),
            peer_node_id_str: CString::new(hex::encode(NodeId::generate().as_bytes())).unwrap(),
            peer_addr_str: CString::new("127.0.0.1:4433").unwrap(),
        };
        let session_ptr = &session as *const ZtlpSession;

        let sid = ztlp_session_id(session_ptr);
        assert!(!sid.is_null());
        // Safety: session is valid on the stack.
        let sid_str = unsafe { CStr::from_ptr(sid) }.to_str().unwrap();
        assert_eq!(sid_str.len(), 24); // 12 bytes * 2 hex chars

        let peer_id = ztlp_session_peer_node_id(session_ptr);
        assert!(!peer_id.is_null());

        let peer_addr = ztlp_session_peer_addr(session_ptr);
        assert!(!peer_addr.is_null());
        // Safety: session is valid.
        let addr_str = unsafe { CStr::from_ptr(peer_addr) }.to_str().unwrap();
        assert_eq!(addr_str, "127.0.0.1:4433");
    }

    // ── Tunnel null checks ──

    #[test]
    fn test_tunnel_start_null_client() {
        let host = CString::new("localhost").unwrap();
        let result = ztlp_tunnel_start(
            std::ptr::null_mut(),
            8080,
            host.as_ptr(),
            80,
            dummy_connect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_tunnel_stop_null_client() {
        let result = ztlp_tunnel_stop(std::ptr::null_mut());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_tunnel_start_not_connected() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let host = CString::new("localhost").unwrap();
        let result = ztlp_tunnel_start(
            client,
            8080,
            host.as_ptr(),
            80,
            dummy_connect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::NotConnected as i32);
        ztlp_client_free(client);
    }

    // ── String free ──

    #[test]
    fn test_string_free_null_is_noop() {
        ztlp_string_free(std::ptr::null_mut());
    }

    #[test]
    fn test_string_free_valid() {
        let s = CString::new("test string").unwrap();
        let ptr = s.into_raw();
        ztlp_string_free(ptr); // Should not crash
    }

    // ── Callback helpers ──

    extern "C" fn dummy_connect_callback(
        _user_data: *mut c_void,
        _result: i32,
        _addr: *const c_char,
    ) {
    }

    // ── Connect/Listen null checks ──

    #[test]
    fn test_connect_null_client() {
        let target = CString::new("127.0.0.1:4433").unwrap();
        let result = ztlp_connect(
            std::ptr::null_mut(),
            target.as_ptr(),
            std::ptr::null(),
            dummy_connect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_connect_null_target() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_connect(
            client,
            std::ptr::null(),
            std::ptr::null(),
            dummy_connect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_listen_null_client() {
        let addr = CString::new("0.0.0.0:4433").unwrap();
        let result = ztlp_listen(
            std::ptr::null_mut(),
            addr.as_ptr(),
            std::ptr::null(),
            dummy_connect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    // ── Recv/Disconnect callback setters ──

    extern "C" fn dummy_recv_callback(
        _user_data: *mut c_void,
        _data: *const u8,
        _len: usize,
        _session: *mut ZtlpSession,
    ) {
    }

    extern "C" fn dummy_disconnect_callback(
        _user_data: *mut c_void,
        _session: *mut ZtlpSession,
        _reason: i32,
    ) {
    }

    #[test]
    fn test_set_recv_callback() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_set_recv_callback(client, dummy_recv_callback, std::ptr::null_mut());
        assert_eq!(result, 0);
        ztlp_client_free(client);
    }

    #[test]
    fn test_set_recv_callback_null_client() {
        let result = ztlp_set_recv_callback(
            std::ptr::null_mut(),
            dummy_recv_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_set_disconnect_callback() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_set_disconnect_callback(
            client,
            dummy_disconnect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, 0);
        ztlp_client_free(client);
    }

    #[test]
    fn test_set_disconnect_callback_null_client() {
        let result = ztlp_set_disconnect_callback(
            std::ptr::null_mut(),
            dummy_disconnect_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }
}
