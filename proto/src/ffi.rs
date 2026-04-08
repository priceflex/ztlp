//! C-compatible FFI bindings for the ZTLP Mobile SDK.
//!
//! This module provides a complete C API for integrating ZTLP into iOS and
//! Android applications. All types are opaque pointers, all functions use
//! C calling conventions, and memory ownership is clearly documented.
//!
//! **This is the REAL implementation** — ztlp_connect performs a genuine
//! Noise_XX handshake over UDP, ztlp_send encrypts with ChaCha20-Poly1305,
//! and a background recv loop delivers decrypted data to the recv_callback.

// FFI functions inherently work with raw pointers; callers are responsible for
// passing valid pointers per the documented ownership contracts.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── iOS console logging via NSLog ────────────────────────────────────────
// println!/eprintln! don't show in Xcode's device console on iOS.
// NSLog is always available from Foundation framework (linked by the app).
// We call it directly via extern "C" — no Swift bridge needed.
#[cfg(target_os = "ios")]
extern "C" {
    // Foundation's NSLog — format string is an NSString (CFStringRef).
    // We use CFStringCreateWithCString to create one from a C string.
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFRelease(cf: *const c_void);
    fn NSLog(format: *const c_void, ...);
}

#[cfg(target_os = "ios")]
fn ios_log(msg: &str) {
    if let Ok(c) = CString::new(msg) {
        unsafe {
            // kCFStringEncodingUTF8 = 0x08000100
            let cfstr = CFStringCreateWithCString(
                std::ptr::null(),
                c.as_ptr(),
                0x08000100,
            );
            if !cfstr.is_null() {
                // NSLog(@"%@", cfstr) — but simpler: NSLog(cfstr) since it's the format
                NSLog(cfstr);
                CFRelease(cfstr);
            }
        }
    }
}

#[cfg(not(target_os = "ios"))]
fn ios_log(msg: &str) {
    eprintln!("{}", msg);
}

/// Log to iOS console (NSLog) or stderr on other platforms
macro_rules! diag_log {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        ios_log(&msg);
    }};
}

// ── Security constants ──────────────────────────────────────────────────

/// Maximum allowed length for target address strings passed via FFI.
/// Prevents unbounded allocations from malicious or buggy callers.
const MAX_FFI_ADDRESS_LEN: usize = 256;

/// Maximum allowed decrypted packet size in the recv loop.
/// Packets larger than this are dropped to prevent memory exhaustion.
/// 65535 is the maximum UDP payload size.
const MAX_RECV_PACKET_SIZE: usize = 65535;

use tokio::sync::RwLock as TokioRwLock;

use crate::dns::{VipRegistry, ZtlpDns};
use crate::handshake::{
    HandshakeContext, INITIAL_HANDSHAKE_RETRY_MS, MAX_HANDSHAKE_RETRIES, MAX_HANDSHAKE_RETRY_MS,
};
use crate::identity::{NodeId, NodeIdentity};
use crate::mobile::{
    ConnectionState, HardwareIdentityProvider, IdentityProvider, MobileConfig, PlatformIdentity,
    SoftwareIdentityProvider,
};
use crate::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use crate::reject::RejectFrame;
// SessionState used for future session management features
#[allow(unused_imports)]
use crate::session::SessionState;
use crate::transport::TransportNode;
use crate::tunnel::encode_service_name;
use crate::vip::VipProxy;

// ── Thread-local error storage ──────────────────────────────────────────

std::thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = CString::new(msg).ok();
    });
}

// ── Error codes ─────────────────────────────────────────────────────────

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZtlpResult {
    Ok = 0,
    InvalidArgument = -1,
    IdentityError = -2,
    HandshakeError = -3,
    ConnectionError = -4,
    Timeout = -5,
    SessionNotFound = -6,
    EncryptionError = -7,
    NatError = -8,
    AlreadyConnected = -9,
    NotConnected = -10,
    Rejected = -11,
    InternalError = -99,
}

// ── Callback types ──────────────────────────────────────────────────────

pub type ZtlpConnectCallback = extern "C" fn(*mut c_void, i32, *const c_char);
pub type ZtlpRecvCallback = extern "C" fn(*mut c_void, *const u8, usize, *mut ZtlpSession);
pub type ZtlpDisconnectCallback = extern "C" fn(*mut c_void, *mut ZtlpSession, i32);

/// Callback for sending pre-encrypted ACK packets via Swift's NWConnection.
/// Rust encrypts the ACK into a full ZTLP wire packet, then calls this callback
/// with the raw bytes + destination address. Swift sends via a separate NWConnection
/// on its own dispatch queue, bypassing iOS kernel contention on the main socket.
pub type ZtlpAckSendCallback = extern "C" fn(*mut c_void, *const u8, usize, *const c_char);

/// Send-safe wrapper for raw pointers passed across thread boundaries.
/// Safety: The caller guarantees the pointer remains valid for the task's lifetime.
#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}

// ── Opaque handle types ─────────────────────────────────────────────────

pub struct ZtlpClient {
    inner: Arc<std::sync::Mutex<ZtlpClientInner>>,
}

#[allow(dead_code)]
struct ZtlpClientInner {
    runtime: tokio::runtime::Runtime,
    identity: Box<dyn PlatformIdentity>,
    state: ConnectionState,
    config: MobileConfig,
    active_session: Option<ActiveSession>,
    recv_callback: Option<(ZtlpRecvCallback, *mut c_void)>,
    disconnect_callback: Option<(ZtlpDisconnectCallback, *mut c_void)>,
    ack_send_callback: Option<(ZtlpAckSendCallback, *mut c_void)>,
    /// VIP proxy manager (local TCP → tunnel).
    vip_proxy: Option<VipProxy>,
    /// DNS resolver for *.ztlp domains.
    dns_server: Option<ZtlpDns>,
    /// Shared VIP registry (service name → IP) used by both VIP proxy and DNS.
    vip_registry: VipRegistry,
    /// Packet router for iOS utun interface (raw IPv4 → ZTLP mux streams).
    packet_router: Option<crate::packet_router::PacketRouter>,
}

unsafe impl Send for ZtlpClientInner {}

/// Active session with real transport state.
#[allow(dead_code)]
struct ActiveSession {
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    /// The real async transport (UDP socket + pipeline).
    transport: Arc<TransportNode>,
    /// Bytes sent counter.
    bytes_sent: Arc<AtomicU64>,
    /// Bytes received counter.
    bytes_received: Arc<AtomicU64>,
    /// Flag to stop the recv loop.
    stop_flag: Arc<AtomicBool>,
    /// Tunnel data sequence counter (for FRAME_DATA framing).
    data_seq: Arc<AtomicU64>,
    /// Channel to feed gateway upload ACKs to the SendController.
    /// Set when VIP proxy starts with congestion-controlled uploads.
    upload_ack_tx: Option<tokio::sync::mpsc::UnboundedSender<u64>>,
    /// Channel for the recv_loop to enqueue frames (e.g., download ACKs)
    /// into the SendController for sequenced, retransmittable sending.
    /// Without this, download ACKs sent directly via transport.send_data()
    /// consume transport seq numbers but aren't retransmitted if lost,
    /// creating permanent gaps in the gateway's recv_window.
    send_enqueue_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    /// Channel for packet router actions (OpenStream, SendData, CloseStream).
    /// The async router_action_task processes these and sends ZTLP mux frames.
    router_action_tx:
        Option<tokio::sync::mpsc::UnboundedSender<crate::packet_router::RouterAction>>,
    // Cached C strings for accessors
    session_id_str: CString,
    peer_node_id_str: CString,
    peer_addr_str: CString,
}

#[allow(dead_code)]
pub struct ZtlpSession {
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    session_id_str: CString,
    peer_node_id_str: CString,
    peer_addr_str: CString,
}

pub struct ZtlpIdentity {
    provider: Box<dyn PlatformIdentity>,
    node_id_str: CString,
    public_key_str: CString,
}

pub struct ZtlpConfig {
    relay_address: Option<String>,
    stun_server: Option<String>,
    nat_assist: bool,
    timeout_ms: u64,
    service_name: Option<String>,
}

// ── Global lifecycle ────────────────────────────────────────────────────

static INITIALIZED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "C" fn ztlp_init() -> i32 {
    INITIALIZED.store(true, Ordering::SeqCst);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    ZtlpResult::Ok as i32
}

#[no_mangle]
pub extern "C" fn ztlp_shutdown() {
    INITIALIZED.store(false, Ordering::SeqCst);
}

// ── Identity functions ──────────────────────────────────────────────────

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

#[no_mangle]
pub extern "C" fn ztlp_identity_from_file(path: *const c_char) -> *mut ZtlpIdentity {
    if path.is_null() {
        set_last_error("path is null");
        return std::ptr::null_mut();
    }
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
        return ztlp_identity_generate();
    }
    let node_id = NodeId::generate();
    let public_key = [0u8; 32];
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

#[no_mangle]
pub extern "C" fn ztlp_identity_node_id(identity: *const ZtlpIdentity) -> *const c_char {
    if identity.is_null() {
        set_last_error("identity handle is null");
        return std::ptr::null();
    }
    let identity = unsafe { &*identity };
    identity.node_id_str.as_ptr()
}

#[no_mangle]
pub extern "C" fn ztlp_identity_public_key(identity: *const ZtlpIdentity) -> *const c_char {
    if identity.is_null() {
        set_last_error("identity handle is null");
        return std::ptr::null();
    }
    let identity = unsafe { &*identity };
    identity.public_key_str.as_ptr()
}

#[no_mangle]
pub extern "C" fn ztlp_identity_save(identity: *const ZtlpIdentity, path: *const c_char) -> i32 {
    if identity.is_null() || path.is_null() {
        set_last_error("identity or path is null");
        return ZtlpResult::InvalidArgument as i32;
    }
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
        Some(node_identity) => match node_identity.save(Path::new(path_str)) {
            Ok(()) => ZtlpResult::Ok as i32,
            Err(e) => {
                set_last_error(&format!("failed to save identity: {e}"));
                ZtlpResult::IdentityError as i32
            }
        },
        None => {
            set_last_error("hardware identities cannot be exported to file");
            ZtlpResult::IdentityError as i32
        }
    }
}

#[no_mangle]
pub extern "C" fn ztlp_identity_free(identity: *mut ZtlpIdentity) {
    if !identity.is_null() {
        unsafe {
            let _ = Box::from_raw(identity);
        }
    }
}

// ── Client functions ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn ztlp_client_new(identity: *mut ZtlpIdentity) -> *mut ZtlpClient {
    // Diagnostic: confirm this library version is actually running
    ios_log("[ZTLP] ======= ztlp_client_new called =======");
    ios_log("[ZTLP] Library version: 0.24.1-diag (build b29f324+nslog)");
    ios_log("[ZTLP] NSLog bridge: CFStringCreateWithCString direct");
    if identity.is_null() {
        ios_log("[ZTLP] ERROR: identity handle is null");
        set_last_error("identity handle is null");
        return std::ptr::null_mut();
    }
    let identity = unsafe { Box::from_raw(identity) };
    // Limit tokio to 4 worker threads to reduce memory while avoiding task starvation.
    // Default spawns N=num_cpus (6 on iPhone) × 2MB stack = ~12MB.
    // 4 threads × 512KB stacks = ~2MB — recv_loop, VIP proxy writes, send, and listener
    // all need concurrent scheduling. 2 threads caused VIP proxy write starvation.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(256 * 1024)
        .enable_all()
        .build()
    {
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
        ack_send_callback: None,
        vip_proxy: None,
        dns_server: None,
        vip_registry: Arc::new(TokioRwLock::new(std::collections::HashMap::new())),
        packet_router: None,
    };
    let client = ZtlpClient {
        inner: Arc::new(std::sync::Mutex::new(inner)),
    };
    Box::into_raw(Box::new(client))
}

#[no_mangle]
pub extern "C" fn ztlp_client_free(client: *mut ZtlpClient) {
    if !client.is_null() {
        unsafe {
            let client = Box::from_raw(client);
            // Stop any active recv loop before dropping
            if let Ok(guard) = client.inner.lock() {
                if let Some(ref session) = guard.active_session {
                    session.stop_flag.store(true, Ordering::SeqCst);
                }
            }
            drop(client);
        }
    }
}

// ── Config functions ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn ztlp_config_new() -> *mut ZtlpConfig {
    let config = ZtlpConfig {
        relay_address: None,
        stun_server: None,
        nat_assist: true,
        timeout_ms: 15000,
        service_name: None,
    };
    Box::into_raw(Box::new(config))
}

#[no_mangle]
pub extern "C" fn ztlp_config_set_relay(config: *mut ZtlpConfig, addr: *const c_char) -> i32 {
    if config.is_null() || addr.is_null() {
        set_last_error("config or addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }
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

#[no_mangle]
pub extern "C" fn ztlp_config_set_stun_server(config: *mut ZtlpConfig, addr: *const c_char) -> i32 {
    if config.is_null() || addr.is_null() {
        set_last_error("config or addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }
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

#[no_mangle]
pub extern "C" fn ztlp_config_set_nat_assist(config: *mut ZtlpConfig, enabled: bool) -> i32 {
    if config.is_null() {
        set_last_error("config is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let config = unsafe { &mut *config };
    config.nat_assist = enabled;
    ZtlpResult::Ok as i32
}

#[no_mangle]
pub extern "C" fn ztlp_config_set_timeout_ms(config: *mut ZtlpConfig, ms: u64) -> i32 {
    if config.is_null() {
        set_last_error("config is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let config = unsafe { &mut *config };
    config.timeout_ms = ms;
    ZtlpResult::Ok as i32
}

/// Set the target service name for gateway routing.
///
/// The gateway uses this to determine which backend to forward traffic to.
/// For example, "beta" would route to the "beta" backend configured in
/// the gateway.
#[no_mangle]
pub extern "C" fn ztlp_config_set_service(config: *mut ZtlpConfig, service: *const c_char) -> i32 {
    if config.is_null() || service.is_null() {
        set_last_error("config or service is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let config = unsafe { &mut *config };
    let svc_str = unsafe { CStr::from_ptr(service) };
    match svc_str.to_str() {
        Ok(s) => {
            // Validate the service name length (max 16 bytes)
            if let Err(e) = encode_service_name(s) {
                set_last_error(&e);
                return ZtlpResult::InvalidArgument as i32;
            }
            config.service_name = Some(s.to_string());
            ZtlpResult::Ok as i32
        }
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in service name: {e}"));
            ZtlpResult::InvalidArgument as i32
        }
    }
}

#[no_mangle]
pub extern "C" fn ztlp_config_free(config: *mut ZtlpConfig) {
    if !config.is_null() {
        unsafe {
            let _ = Box::from_raw(config);
        }
    }
}

// ── Connection functions — REAL IMPLEMENTATION ──────────────────────────

/// Connect to a ZTLP peer or gateway.
///
/// Performs a real Noise_XX three-message handshake over UDP:
/// 1. Send HELLO (with retransmit on timeout)
/// 2. Receive HELLO_ACK
/// 3. Send final confirmation
///
/// After the handshake, starts a background receive loop.
/// The callback is invoked when the handshake completes or fails.
#[no_mangle]
pub extern "C" fn ztlp_connect(
    client: *mut ZtlpClient,
    target: *const c_char,
    config: *const ZtlpConfig,
    callback: ZtlpConnectCallback,
    user_data: *mut c_void,
) -> i32 {
    ios_log("[ZTLP] ztlp_connect called");
    if client.is_null() || target.is_null() {
        ios_log("[ZTLP] ERROR: client or target is null");
        set_last_error("client or target is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let client = unsafe { &*client };
    let target_str = unsafe { CStr::from_ptr(target) };
    let target_string = match target_str.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in target: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    // SECURITY: Reject oversized target addresses to prevent unbounded allocations
    // from malicious or buggy FFI callers. 256 bytes is generous for any valid
    // socket address (IPv6 + port is at most ~47 chars).
    if target_string.len() > MAX_FFI_ADDRESS_LEN {
        set_last_error(&format!(
            "target address too long ({} bytes, max {})",
            target_string.len(),
            MAX_FFI_ADDRESS_LEN
        ));
        return ZtlpResult::InvalidArgument as i32;
    }

    // Read config
    let (service_name, timeout_ms, relay_address) = if !config.is_null() {
        let cfg = unsafe { &*config };
        (
            cfg.service_name.clone(),
            cfg.timeout_ms,
            cfg.relay_address.clone(),
        )
    } else {
        (None, 15000, None)
    };

    let inner = client.inner.clone();

    {
        let guard = match inner.lock() {
            Ok(g) => g,
            Err(e) => {
                set_last_error(&format!("mutex poisoned: {e}"));
                return ZtlpResult::InternalError as i32;
            }
        };

        if guard.state == ConnectionState::Connected {
            set_last_error("already connected");
            return ZtlpResult::AlreadyConnected as i32;
        }

        // Extract the NodeIdentity for the handshake.
        // If the identity is hardware-backed (Secure Enclave), we generate
        // ephemeral X25519 keys for Noise_XX since hardware keys are Ed25519
        // and can't be used directly in Noise. The hardware node_id is preserved
        // for identification; the Noise static key is ephemeral-per-session.
        let node_identity = match guard.identity.as_node_identity() {
            Some(ni) => ni.clone(),
            None => {
                // Hardware identity — generate software X25519 keys for Noise,
                // keeping the hardware-assigned node_id
                let hw_node_id = *guard.identity.node_id();
                match SoftwareIdentityProvider::generate() {
                    Ok(sw) => {
                        let mut ni = sw
                            .as_node_identity()
                            .expect("freshly generated software identity must have node_identity")
                            .clone();
                        // Override with hardware node_id
                        ni.node_id = hw_node_id;
                        ni
                    }
                    Err(e) => {
                        set_last_error(&format!(
                            "failed to generate ephemeral keys for hardware identity: {e}"
                        ));
                        return ZtlpResult::IdentityError as i32;
                    }
                }
            }
        };

        let user_data_usize = user_data as usize;
        let inner_clone = inner.clone();

        guard.runtime.spawn(async move {
            match do_connect(
                &node_identity,
                &target_string,
                service_name.as_deref(),
                timeout_ms,
                relay_address.as_deref(),
            )
            .await
            {
                Ok(connected) => {
                    let addr_cstr =
                        CString::new(connected.peer_addr.to_string()).unwrap_or_default();

                    // Start the background recv loop
                    let transport = connected.transport.clone();
                    let bytes_received = connected.bytes_received.clone();
                    let stop_flag = connected.stop_flag.clone();
                    let session_id = connected.session_id;
                    let peer_node_id = connected.peer_node_id;
                    let peer_addr = connected.peer_addr;
                    let inner_for_recv = inner_clone.clone();

                    // Store the session
                    if let Ok(mut guard) = inner_clone.lock() {
                        guard.state = ConnectionState::Connected;
                        guard.active_session = Some(connected);
                    }

                    // Spawn recv loop
                    tokio::spawn(async move {
                        recv_loop(
                            transport,
                            bytes_received,
                            stop_flag,
                            session_id,
                            peer_node_id,
                            peer_addr,
                            inner_for_recv,
                        )
                        .await;
                    });

                    callback(
                        user_data_usize as *mut c_void,
                        ZtlpResult::Ok as i32,
                        addr_cstr.as_ptr(),
                    );
                }
                Err(e) => {
                    // Store the error
                    set_last_error(&e);
                    if let Ok(mut guard) = inner_clone.lock() {
                        guard.state = ConnectionState::Disconnected;
                    }
                    callback(
                        user_data_usize as *mut c_void,
                        ZtlpResult::ConnectionError as i32,
                        std::ptr::null(),
                    );
                }
            }
        });
    }

    ZtlpResult::Ok as i32
}

/// Perform the actual Noise_XX handshake over UDP.
async fn do_connect(
    identity: &NodeIdentity,
    target: &str,
    service_name: Option<&str>,
    timeout_ms: u64,
    relay_address: Option<&str>,
) -> Result<ActiveSession, String> {
    // Parse target address (gateway/peer)
    let target_addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("invalid target address '{}': {}", target, e))?;

    // If a relay is configured, send packets to the relay instead of directly to the target.
    // The relay will forward based on the session/service info in the HELLO header.
    let send_addr: SocketAddr = if let Some(relay) = relay_address {
        relay
            .parse()
            .map_err(|e| format!("invalid relay address '{}': {}", relay, e))?
    } else {
        target_addr
    };

    // Bind a UDP socket
    let node = TransportNode::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("failed to bind UDP socket: {}", e))?;

    // Create Noise_XX initiator context
    let mut ctx =
        HandshakeContext::new_initiator(identity).map_err(|e| format!("handshake init: {}", e))?;

    let session_id = SessionId::generate();

    // ── Message 1: HELLO ──
    let msg1 = ctx
        .write_message(&[])
        .map_err(|e| format!("handshake msg1: {}", e))?;

    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;

    // Set service name if specified (for gateway routing)
    if let Some(svc) = service_name {
        hello_hdr.dst_svc_id =
            encode_service_name(svc).map_err(|e| format!("bad service name: {}", e))?;
    }

    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);

    node.send_raw(&pkt1, send_addr)
        .await
        .map_err(|e| format!("send HELLO: {}", e))?;

    // ── Message 2: receive HELLO_ACK (with retransmit) ──
    let mut retry_delay = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
    let max_retry_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);
    let overall_timeout = Duration::from_millis(timeout_ms);
    let start = tokio::time::Instant::now();
    let mut retries: u8 = 0;

    let (recv2, recv2_header) = loop {
        if start.elapsed() > overall_timeout {
            return Err("handshake timed out waiting for HELLO_ACK".to_string());
        }

        match tokio::time::timeout(retry_delay, node.recv_raw()).await {
            Ok(Ok((data, _addr))) => {
                if data.len() >= HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                        if hdr.msg_type == MsgType::HelloAck && hdr.session_id == session_id {
                            break (data, hdr);
                        }
                    }
                }
                // Not our HELLO_ACK — keep waiting
                continue;
            }
            Ok(Err(e)) => return Err(format!("recv error: {}", e)),
            Err(_) => {
                // Timeout — retransmit HELLO
                retries += 1;
                if retries > MAX_HANDSHAKE_RETRIES {
                    return Err("handshake failed: no HELLO_ACK after retransmits".to_string());
                }
                node.send_raw(&pkt1, send_addr)
                    .await
                    .map_err(|e| format!("retransmit HELLO: {}", e))?;
                retry_delay = (retry_delay * 2).min(max_retry_delay);
            }
        }
    };

    // Process HELLO_ACK noise payload
    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)
        .map_err(|e| format!("handshake msg2: {}", e))?;

    // ── Message 3: final confirmation ──
    let msg3 = ctx
        .write_message(&[])
        .map_err(|e| format!("handshake msg3: {}", e))?;

    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;

    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);

    node.send_raw(&pkt3, send_addr)
        .await
        .map_err(|e| format!("send msg3: {}", e))?;

    // Verify handshake completed
    if !ctx.is_finished() {
        return Err("handshake did not complete after 3 messages".to_string());
    }

    let peer_node_id = NodeId::from_bytes(recv2_header.src_node_id);
    let (_transport_state, session) = ctx
        .finalize(peer_node_id, session_id)
        .map_err(|e| format!("handshake finalize: {}", e))?;

    // Register session in the pipeline
    {
        let mut pipeline = node.pipeline.lock().await;
        pipeline.register_session(session);
    }

    // Check for REJECT frame (server sends after handshake if policy denies)
    {
        let reject_deadline = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(reject_deadline);
        loop {
            tokio::select! {
                _ = &mut reject_deadline => break, // No reject — proceed
                result = node.recv_data() => {
                    match result {
                        Ok(Some((plaintext, _from))) => {
                            if RejectFrame::is_reject(&plaintext) {
                                if let Some(reject) = RejectFrame::decode(&plaintext) {
                                    return Err(format!(
                                        "access denied: {} ({})",
                                        reject.message, reject.reason
                                    ));
                                }
                            }
                            // Non-reject data — ignore during this window
                        }
                        Ok(None) => {} // Dropped by pipeline
                        Err(_) => break, // Socket error — proceed
                    }
                }
            }
        }
    }

    let transport = Arc::new(node);
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));

    Ok(ActiveSession {
        session_id,
        peer_node_id,
        peer_addr: send_addr,
        transport,
        bytes_sent,
        bytes_received,
        stop_flag,
        data_seq: Arc::new(AtomicU64::new(0)),
        upload_ack_tx: None,
        send_enqueue_tx: None,
        router_action_tx: None,
        session_id_str: CString::new(hex::encode(session_id.as_bytes())).unwrap_or_default(),
        peer_node_id_str: CString::new(hex::encode(peer_node_id.as_bytes())).unwrap_or_default(),
        peer_addr_str: CString::new(send_addr.to_string()).unwrap_or_default(),
    })
}

/// Background receive loop — decrypts incoming packets and invokes the recv callback.
/// Action to take after processing a received packet.
enum RecvAction {
    /// Continue the recv loop (e.g., keepalive frame processed).
    Continue,
    /// Break the recv loop (e.g., server rejected connection).
    Break,
    /// No special action — fall through normally.
    Noop,
}

/// Process a single received packet, extracting the logic from recv_loop
/// so it can be wrapped in `catch_unwind` for panic safety.
///
/// SECURITY: This function is called inside catch_unwind. A panic here
/// (e.g., from a malicious server response) will be caught and logged
/// rather than aborting the process.
fn process_recv_packet(
    plaintext: &[u8],
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    inner: &Arc<std::sync::Mutex<ZtlpClientInner>>,
) -> RecvAction {
    // Check if it's a disconnect/reject
    if RejectFrame::is_reject(plaintext) {
        if let Some(reject) = RejectFrame::decode(plaintext) {
            set_last_error(&format!("server rejected: {}", reject.message));
            // Invoke disconnect callback
            if let Ok(guard) = inner.lock() {
                if let Some((cb, ud)) = guard.disconnect_callback {
                    let mut session_handle = ZtlpSession {
                        session_id,
                        peer_node_id,
                        peer_addr,
                        session_id_str: CString::new(hex::encode(session_id.as_bytes()))
                            .unwrap_or_default(),
                        peer_node_id_str: CString::new(hex::encode(peer_node_id.as_bytes()))
                            .unwrap_or_default(),
                        peer_addr_str: CString::new(peer_addr.to_string()).unwrap_or_default(),
                    };
                    cb(
                        ud,
                        &mut session_handle as *mut ZtlpSession,
                        ZtlpResult::Rejected as i32,
                    );
                }
            }
            return RecvAction::Break;
        }
    }

    // Skip keepalive frames (frame_type 0x01) — they're just NAT pings
    if plaintext.len() == 1 && plaintext[0] == 0x01 {
        return RecvAction::Continue;
    }

    // Invoke recv callback
    if let Ok(guard) = inner.lock() {
        if let Some((cb, ud)) = guard.recv_callback {
            let mut session_handle = ZtlpSession {
                session_id,
                peer_node_id,
                peer_addr,
                session_id_str: CString::new(hex::encode(session_id.as_bytes()))
                    .unwrap_or_default(),
                peer_node_id_str: CString::new(hex::encode(peer_node_id.as_bytes()))
                    .unwrap_or_default(),
                peer_addr_str: CString::new(peer_addr.to_string()).unwrap_or_default(),
            };
            cb(
                ud,
                plaintext.as_ptr(),
                plaintext.len(),
                &mut session_handle as *mut ZtlpSession,
            );
        }

        // NOTE: VIP proxy forwarding is now handled in recv_loop (after ACK
        // tracking) so we can deliver data in data_seq order. The recv_loop
        // buffers out-of-order packets and flushes them in sequence.
    }

    RecvAction::Noop
}

async fn recv_loop(
    transport: Arc<TransportNode>,
    bytes_received: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    inner: Arc<std::sync::Mutex<ZtlpClientInner>>,
) {
    // Tunnel frame types (must match gateway session.ex constants)
    const FRAME_DATA: u8 = 0x00;
    const FRAME_ACK: u8 = 0x01;
    const FRAME_FIN: u8 = 0x02;
    const FRAME_NACK: u8 = 0x03;
    const FRAME_CLOSE: u8 = 0x05;

    // Keepalive watchdog: if no data arrives for this long, treat connection as dead
    let mut last_recv_time = std::time::Instant::now();
    const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(45);
    const DISCONNECT_KEEPALIVE_TIMEOUT: i32 = 100;

    // Track highest contiguous data_seq received for cumulative ACKs.
    // Uses a simple approach: track next_expected and a set of
    // out-of-order seqs received ahead.
    let mut next_expected_seq: u64 = 0;
    let mut received_ahead: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // Reassembly buffer: holds payloads for out-of-order data_seqs so we
    // can deliver to the VIP proxy in the correct order.
    // For multiplexed streams, we dispatch by stream_id immediately after
    // reassembly — the global data_seq ensures transport-level ordering
    // and ACK correctness, while per-stream dispatch to separate channels
    // allows independent delivery.
    let mut reassembly_buf: std::collections::BTreeMap<u64, (u32, Vec<u8>)> =
        std::collections::BTreeMap::new(); // data_seq → (stream_id, payload)
    let mut vip_next_deliver_seq: u64 = 0;
    let mut _last_data_seq: u64 = 0;
    // Delayed ACK flush: track the last ACK we sent and when we last received data.
    // If we have unacked data older than ACK_FLUSH_TIMEOUT, send an ACK immediately
    // instead of waiting for the coalesce threshold.
    let mut last_acked_data_seq: u64 = 0; // last data_seq we ACK'd (next_expected at ACK time)
    let mut last_data_recv_time: Option<std::time::Instant> = None;
    const ACK_FLUSH_TIMEOUT_MS: u128 = 10; // flush unacked data after 10ms

    // NACK (Negative ACK): when we detect a gap (received_ahead non-empty),
    // wait NACK_GAP_THRESHOLD_MS then send FRAME_NACK listing missing seqs.
    // This tells the gateway exactly which data_seqs to retransmit immediately
    // instead of waiting for exponential RTO backoff.
    let mut gap_detected_at: Option<std::time::Instant> = None;
    let mut last_nack_time: Option<std::time::Instant> = None;
    const NACK_GAP_THRESHOLD_MS: u128 = 50; // wait this long before sending NACK
    const NACK_MIN_INTERVAL_MS: u128 = 100; // rate-limit: one NACK per 100ms
    const MAX_NACK_SEQS: usize = 64; // max missing seqs per NACK frame

    // Rate-limit duplicate re-ACKs to prevent retransmit storms.
    // When gateway fast-retransmits N packets, client receives N duplicates.
    // Without rate limiting, N re-ACKs trigger another fast retransmit → loop.
    let mut last_reack_time: Option<std::time::Instant> = None;
    const REACK_MIN_INTERVAL_MS: u128 = 20; // re-ACK every 20ms during dup storms (was 100ms)

    // ── iOS diagnostic counters ──
    // Track packet flow metrics for diagnosing iOS performance issues.
    // Logged periodically (every 100 packets or 5 seconds) to TunnelLogger.
    let mut diag_packets_received: u64 = 0;
    let mut diag_packets_decrypted: u64 = 0;
    let mut diag_acks_sent: u64 = 0;
    let mut diag_reassembly_buf_peak: usize = 0;
    let mut diag_ooo_peak: usize = 0;
    let mut diag_last_report: std::time::Instant = std::time::Instant::now();
    let mut diag_lock_contention_us: u64 = 0;
    const DIAG_REPORT_INTERVAL_MS: u128 = 5000; // report every 5 seconds
    const DIAG_REPORT_PACKET_INTERVAL: u64 = 200; // or every 200 packets

    // Reassembly buffer cap — prevent unbounded memory growth in iOS
    // Network Extension (15MB process limit). 512 entries × ~1200 bytes
    // = ~600KB max reassembly memory.
    const REASSEMBLY_MAX_ENTRIES: usize = 256;

    // Cap for received_ahead BTreeSet (out-of-order tracking).
    // 1024 entries × ~56 bytes per BTreeSet node = ~56KB max.
    const RECEIVED_AHEAD_MAX: usize = 1024;

    // NAT keepalive: send an encrypted empty frame every 5s to keep
    // UDP NAT mappings alive. Nebula uses 5s which handles aggressive
    // cellular NATs (some have timeouts as low as 20-30s). The previous
    // 15s interval was too close to the timeout threshold, causing
    // NAT rebinding during active data transfers.
    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
    // Single-byte 0x01 — gateway sees <<@frame_ack, rest::binary>> with
    // empty rest, which it silently ignores (malformed ACK). This is fine
    // for keepalive purposes; it just needs to be an encrypted packet that
    // keeps the NAT mapping alive.
    const KEEPALIVE_FRAME: [u8; 1] = [0x01];

    let keepalive_transport = transport.clone();
    let keepalive_stop = stop_flag.clone();
    let keepalive_peer = peer_addr;
    let keepalive_session_id = session_id;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
        interval.tick().await; // skip first immediate tick
        loop {
            interval.tick().await;
            if keepalive_stop.load(Ordering::SeqCst) {
                break;
            }
            // Send a minimal encrypted keepalive frame
            if keepalive_transport
                .send_data(keepalive_session_id, &KEEPALIVE_FRAME, keepalive_peer)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // ── ACK sender via Swift NWConnection callback (separate socket) ──
    //
    // Architecture: recv_loop builds ACK/NACK frames → encrypt locally →
    // fire via FFI callback to Swift, which sends on a dedicated NWConnection.
    //
    // This solves the root cause: ACKs go out on a SEPARATE UDP socket from
    // the one receiving data. No kernel-level sendto/recv contention.
    //
    // Previous approaches (OS thread sendto on same fd, tokio pump, 5x redundant
    // sends) all suffered from single-socket contention under 55Mbps inbound.
    // See SPEED-FIX-PLAN.md for the full analysis.
    //
    // The relay accepts ACKs from any source port because it routes by
    // session_id (Nebula-style), not by (IP, port) tuple.
    let ack_cb: Option<(ZtlpAckSendCallback, SendPtr)> = {
        if let Ok(guard) = inner.lock() {
            guard.ack_send_callback.map(|(cb, ud)| (cb, SendPtr(ud)))
        } else {
            None
        }
    };
    let ack_transport = transport.clone();
    let ack_session_id = session_id;
    let ack_peer_addr = peer_addr;
    let ack_peer_str = std::ffi::CString::new(format!("{}", peer_addr)).unwrap_or_default();

    // Extract raw pointer from ack_cb so the macro doesn't hold a non-Send reference
    // across await points. The raw fn ptr + raw void ptr are both Send-safe in practice
    // (the Swift side guarantees the user_data pointer lives for the session's lifetime).
    let ack_cb_fn: Option<ZtlpAckSendCallback> = ack_cb.map(|(cb, _)| cb);
    let ack_cb_ud: SendPtr = ack_cb.map(|(_, ud)| ud).unwrap_or(SendPtr(std::ptr::null_mut()));

    // Pre-extract send_key and shared seq counter for LOCK-FREE ACK encryption.
    // This is critical: encrypt_data() takes the pipeline lock, which blocks recv_data().
    // By extracting the key and using a shared atomic seq counter, we encrypt ACKs
    // without any lock contention with the recv path.
    let (ack_send_key, ack_seq_counter) = {
        let pipeline = transport.pipeline.lock().await;
        match pipeline.get_session(&session_id) {
            Some(session) => (session.send_key, session.send_seq_counter()),
            None => {
                tracing::error!("ack setup: session not found");
                ([0u8; 32], Arc::new(std::sync::atomic::AtomicU64::new(0)))
            }
        }
    };

    // Helper: encrypt an ACK/NACK frame and send via the Swift NWConnection callback.
    // Falls back to tokio transport.send_data() if no callback is registered.
    //
    // LOCK-FREE: uses pre-extracted send_key + atomic seq counter.
    // Does NOT touch the pipeline lock — recv_data() runs unblocked.
    macro_rules! send_ack_frame {
        ($frame:expr) => {{
            let frame_ref: &[u8] = &$frame;

            // PRIORITY 1: Send via Swift NWConnection callback (non-blocking).
            // This is the primary ACK path on iOS — it uses a separate socket
            // that won't block the recv_loop if the main socket buffer is full.
            if let Some(cb) = ack_cb_fn {
                let seq = ack_seq_counter.fetch_add(1, Ordering::Relaxed);
                match crate::ack_socket::build_encrypted_packet(
                    ack_session_id, &ack_send_key, seq, frame_ref,
                ) {
                    Ok(wire_bytes) => {
                        cb(ack_cb_ud.0, wire_bytes.as_ptr(), wire_bytes.len(), ack_peer_str.as_ptr());
                    }
                    Err(e) => {
                        tracing::warn!("send_ack_frame: callback encrypt failed: {}", e);
                    }
                }
            }

            // PRIORITY 2: Also try the main transport with a short timeout.
            // If the socket send buffer is full, don't block the recv_loop —
            // the callback path above already sent the ACK on a separate socket.
            // A blocked send_data() here was the root cause of ACK starvation:
            // the .await would block indefinitely, freezing the entire recv_loop.
            let _transport_result = tokio::time::timeout(
                Duration::from_millis(5),
                ack_transport.send_data(ack_session_id, frame_ref, ack_peer_addr),
            ).await;
        }};
    }

    // ── Leveled file logging for diagnosing tunnel issues ──
    //
    // ZTLP_LOG_LEVEL env var controls verbosity:
    //   "off"   — no file logging at all
    //   "error" — errors only
    //   "warn"  — errors + warnings
    //   "info"  — session lifecycle + errors + warnings (DEFAULT)
    //   "debug" — info + frame summaries (periodic, not per-packet)
    //   "trace" — every single recv/frame (17MB/min — diagnostic only!)
    //
    // ZTLP_LOG_FILE env var overrides the log path (default: /tmp/ztlp-recv.log)
    // Log files are rotated at 2MB — previous log moved to .1 suffix.
    const LOG_ROTATE_BYTES: u64 = 2 * 1024 * 1024; // 2MB
    #[derive(Clone, Copy, PartialEq, PartialOrd)]
    enum LogLevel {
        Off = 0,
        Error = 1,
        Warn = 2,
        Info = 3,
        Debug = 4,
        Trace = 5,
    }
    let log_level = match std::env::var("ZTLP_LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .to_lowercase()
        .as_str()
    {
        "off" | "none" => LogLevel::Off,
        "error" => LogLevel::Error,
        "warn" | "warning" => LogLevel::Warn,
        "info" => LogLevel::Info,
        "debug" => LogLevel::Debug,
        "trace" | "all" => LogLevel::Trace,
        _ => LogLevel::Info,
    };
    let log_path =
        std::env::var("ZTLP_LOG_FILE").unwrap_or_else(|_| "/tmp/ztlp-recv.log".to_string());
    let open_log_file = |path: &str| -> Option<std::fs::File> {
        if log_level == LogLevel::Off {
            return None;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
    };
    let mut debug_log = open_log_file(&log_path);
    let mut log_bytes_written: u64 = debug_log
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .map(|m| m.len())
        .unwrap_or(0);
    let log_start = std::time::Instant::now();
    let log_write = |file: &mut Option<std::fs::File>,
                     bytes_written: &mut u64,
                     start: std::time::Instant,
                     level: LogLevel,
                     msg: &str,
                     cur_level: LogLevel,
                     log_path: &str| {
        if level > cur_level {
            return;
        }
        if let Some(ref mut f) = file {
            use std::io::Write;
            let lvl_str = match level {
                LogLevel::Off => return,
                LogLevel::Error => "ERROR",
                LogLevel::Warn => "WARN",
                LogLevel::Info => "INFO",
                LogLevel::Debug => "DEBUG",
                LogLevel::Trace => "TRACE",
            };
            let elapsed = start.elapsed().as_millis();
            let line = format!("[+{}ms] [{}] {}\n", elapsed, lvl_str, msg);
            let _ = f.write_all(line.as_bytes());
            *bytes_written += line.len() as u64;
            // Rotate if over limit
            if *bytes_written > LOG_ROTATE_BYTES {
                let _ = f.flush();
                drop(file.take());
                let rotated = format!("{}.1", log_path);
                let _ = std::fs::rename(log_path, &rotated);
                if let Ok(new_f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                {
                    *file = Some(new_f);
                }
                *bytes_written = 0;
            }
        }
    };
    // Frame stats for periodic debug-level summaries instead of per-packet logging
    let mut frame_count: u64 = 0;
    let mut frame_bytes: u64 = 0;
    let mut last_frame_summary = std::time::Instant::now();
    log_write(
        &mut debug_log,
        &mut log_bytes_written,
        log_start,
        LogLevel::Info,
        &format!(
            "recv_loop started, session={}, log_level={:?}",
            hex::encode(session_id.as_bytes()),
            match log_level {
                LogLevel::Off => "off",
                LogLevel::Error => "error",
                LogLevel::Warn => "warn",
                LogLevel::Info => "info",
                LogLevel::Debug => "debug",
                LogLevel::Trace => "trace",
            }
        ),
        log_level,
        &log_path,
    );

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            log_write(
                &mut debug_log,
                &mut log_bytes_written,
                log_start,
                LogLevel::Info,
                "recv_loop: stop_flag set, breaking",
                log_level,
                &log_path,
            );
            break;
        }

        match tokio::time::timeout(Duration::from_millis(50), transport.recv_data()).await {
            Ok(Ok(Some((plaintext, _from)))) => {
                last_recv_time = std::time::Instant::now();
                diag_log!("[ZTLP-RX] {} bytes, first_byte=0x{:02x}",
                    plaintext.len(),
                    plaintext.first().copied().unwrap_or(0));
                log_write(
                    &mut debug_log,
                    &mut log_bytes_written,
                    log_start,
                    LogLevel::Trace,
                    &format!(
                        "recv: {} bytes, first_byte=0x{:02x}",
                        plaintext.len(),
                        plaintext.first().copied().unwrap_or(0)
                    ),
                    log_level,
                    &log_path,
                );

                // SECURITY: Reject oversized packets to prevent memory exhaustion.
                // Maximum UDP payload is 65535 bytes; anything larger indicates a
                // bug or attack. Drop silently and continue.
                if plaintext.len() > MAX_RECV_PACKET_SIZE {
                    tracing::warn!(
                        "recv_loop: dropping oversized packet ({} bytes, max {})",
                        plaintext.len(),
                        MAX_RECV_PACKET_SIZE,
                    );
                    continue;
                }

                bytes_received.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

                // Log short packets for debugging
                if plaintext.len() <= 9 {
                    tracing::debug!(
                        "recv_loop: short packet len={} first_byte=0x{:02x}",
                        plaintext.len(),
                        plaintext.first().copied().unwrap_or(0)
                    );
                }

                // ── Upload ACK: gateway acknowledging our upload packets ──
                //
                // When the gateway receives our upload data, it sends back:
                //   [FRAME_ACK(0x01) | acked_packet_seq(8 BE)]
                // This is a cumulative ACK — all packets ≤ acked_packet_seq
                // are confirmed received. We feed this to the SendController
                // so it can open the congestion window and stop retransmitting.
                //
                // This check MUST come before the FRAME_DATA check because
                // FRAME_ACK (0x01) with 9 bytes should not fall through to
                // process_recv_packet (which would treat 1-byte 0x01 as keepalive).
                // Gateway ACK format: [FRAME_ACK(1) | cumulative_ack(8) | sack_count(1) | sack_blocks...]
                // Minimum 10 bytes (with sack_count=0), but also accept legacy 9-byte format.
                if plaintext.len() >= 9 && plaintext[0] == FRAME_ACK {
                    let acked_seq =
                        u64::from_be_bytes(plaintext[1..9].try_into().unwrap_or([0u8; 8]));
                    diag_log!("[ZTLP-RX] FRAME_ACK (upload) acked_seq={} len={}", acked_seq, plaintext.len());
                    tracing::debug!("recv_loop: FRAME_ACK (upload) acked_seq={}", acked_seq);
                    log_write(
                        &mut debug_log,
                        &mut log_bytes_written,
                        log_start,
                        LogLevel::Info,
                        &format!("FRAME_ACK (upload) acked_seq={}", acked_seq),
                        log_level,
                        &log_path,
                    );
                    // Forward to SendController via the upload ACK channel
                    if let Ok(guard) = inner.lock() {
                        if let Some(ref session) = guard.active_session {
                            if let Some(ref tx) = session.upload_ack_tx {
                                let _ = tx.send(acked_seq);
                            }
                        }
                    }
                    continue;
                }

                // ── ACK logic: track received data_seqs and send cumulative ACKs ──
                //
                // The gateway uses a windowed ARQ protocol: it sends up to
                // @send_window_size packets, then waits for ACKs before sending
                // more. Without ACKs, only the first window (~8 × 1200B = 9.6KB)
                // gets delivered, causing large responses to stall.
                //
                // ACK frame format: [FRAME_ACK(0x01) | data_seq(8 bytes BE)]
                // This tells the gateway: "I've received everything up to and
                // including data_seq N" — it can remove those from its send
                // buffer and advance the window.
                if plaintext.len() > 9 && plaintext[0] == FRAME_DATA {
                    // Parse FRAME_DATA — two formats:
                    // Multiplexed: [0x00 | stream_id(4 BE) | data_seq(8 BE) | payload] (13+ bytes)
                    // Legacy:      [0x00 | data_seq(8 BE) | payload] (9+ bytes)
                    // Detection: if stream_id > 0, it's multiplexed (stream IDs start at 1)
                    let (stream_id, data_seq, payload) = if plaintext.len() >= 13 {
                        let candidate_stream_id =
                            u32::from_be_bytes(plaintext[1..5].try_into().unwrap_or([0u8; 4]));
                        if candidate_stream_id > 0 {
                            // Multiplexed format
                            let ds =
                                u64::from_be_bytes(plaintext[5..13].try_into().unwrap_or([0u8; 8]));
                            (candidate_stream_id, ds, plaintext[13..].to_vec())
                        } else {
                            // Legacy format (stream_id bytes happen to look like 0)
                            let ds =
                                u64::from_be_bytes(plaintext[1..9].try_into().unwrap_or([0u8; 8]));
                            (0u32, ds, plaintext[9..].to_vec())
                        }
                    } else {
                        // Short packet — must be legacy format
                        let ds = u64::from_be_bytes(plaintext[1..9].try_into().unwrap_or([0u8; 8]));
                        (0u32, ds, plaintext[9..].to_vec())
                    };

                    diag_log!("[ZTLP-RX] FRAME_DATA stream={} data_seq={} payload={} expected={}",
                        stream_id, data_seq, payload.len(), next_expected_seq);
                    // Per-frame trace logging (very verbose)
                    log_write(
                        &mut debug_log,
                        &mut log_bytes_written,
                        log_start,
                        LogLevel::Trace,
                        &format!(
                            "FRAME_DATA stream={} data_seq={} payload_len={} expected={}",
                            stream_id,
                            data_seq,
                            payload.len(),
                            next_expected_seq
                        ),
                        log_level,
                        &log_path,
                    );
                    // Periodic debug-level summary (every 5 seconds)
                    frame_count += 1;
                    frame_bytes += payload.len() as u64;
                    if last_frame_summary.elapsed() >= Duration::from_secs(5) {
                        log_write(
                            &mut debug_log,
                            &mut log_bytes_written,
                            log_start,
                            LogLevel::Debug,
                            &format!(
                                "frame_summary: {} frames, {} bytes in last {:.1}s",
                                frame_count,
                                frame_bytes,
                                last_frame_summary.elapsed().as_secs_f64()
                            ),
                            log_level,
                            &log_path,
                        );
                        frame_count = 0;
                        frame_bytes = 0;
                        last_frame_summary = std::time::Instant::now();
                    }

                    // Update cumulative ACK tracking (global across all streams)
                    last_data_recv_time = Some(std::time::Instant::now());
                    let is_duplicate = data_seq < next_expected_seq;
                    if data_seq == next_expected_seq {
                        next_expected_seq = data_seq + 1;
                        while received_ahead.remove(&next_expected_seq) {
                            next_expected_seq += 1;
                        }
                        // Gap cleared if all out-of-order packets consumed
                        if received_ahead.is_empty() {
                            gap_detected_at = None;
                        }
                    } else if data_seq > next_expected_seq {
                        if received_ahead.len() < RECEIVED_AHEAD_MAX {
                            received_ahead.insert(data_seq);
                        }
                        // Start gap timer if this is first out-of-order packet
                        if gap_detected_at.is_none() {
                            gap_detected_at = Some(std::time::Instant::now());
                        }
                    }
                    _last_data_seq = data_seq;

                    // Re-ACK duplicates so gateway can clear its send_buffer,
                    // but rate-limit to prevent retransmit storms: gateway fast-retransmits
                    // N packets → N duplicates → N re-ACKs → another fast retransmit → loop.
                    if is_duplicate && next_expected_seq > 0 {
                        diag_log!("[ZTLP-RX] DUPLICATE data_seq={} (expected={})", data_seq, next_expected_seq);
                        let should_reack = last_reack_time
                            .map(|t| t.elapsed().as_millis() >= REACK_MIN_INTERVAL_MS)
                            .unwrap_or(true);
                        if should_reack {
                            let ack_seq = next_expected_seq.saturating_sub(1);
                            let mut ack_frame = Vec::with_capacity(9);
                            ack_frame.push(FRAME_ACK);
                            ack_frame.extend_from_slice(&ack_seq.to_be_bytes());
                            send_ack_frame!(ack_frame);
                            diag_log!("[ZTLP-TX] re-ACK ack_seq={} for dup data_seq={}", ack_seq, data_seq);
                            tracing::info!("recv_loop: re-ACK for duplicate data_seq={}, ack_seq={}", data_seq, ack_seq);
                            last_acked_data_seq = next_expected_seq;
                            last_data_recv_time = None;
                            last_reack_time = Some(std::time::Instant::now());
                        }
                        continue; // Don't re-deliver duplicate to VIP proxy
                    }

                    // ── Delivery to VIP proxy ──
                    // Buffer for ordered delivery, then flush contiguous.
                    // For mux: dispatch to per-stream channel.
                    // For legacy: dispatch to stream_id=0.
                    if stream_id == 0 && data_seq == 0 && vip_next_deliver_seq > 0 {
                        tracing::info!(
                            "recv_loop: detected stream reset (data_seq=0, expected={})",
                            vip_next_deliver_seq
                        );
                        reassembly_buf.clear();
                        vip_next_deliver_seq = 0;
                    }

                    if data_seq >= vip_next_deliver_seq {
                        // Cap reassembly buffer to prevent OOM in iOS NE
                        if reassembly_buf.len() >= REASSEMBLY_MAX_ENTRIES {
                            tracing::warn!(
                                "recv_loop: reassembly buffer full ({} entries), dropping data_seq={}",
                                reassembly_buf.len(), data_seq
                            );
                            diag_log!("[ZTLP-DIAG] reassembly_buf FULL len={} dropping seq={}", reassembly_buf.len(), data_seq);
                        } else {
                            reassembly_buf.insert(data_seq, (stream_id, payload));
                        }
                    }

                    // Track diagnostic peaks
                    if reassembly_buf.len() > diag_reassembly_buf_peak {
                        diag_reassembly_buf_peak = reassembly_buf.len();
                    }
                    if received_ahead.len() > diag_ooo_peak {
                        diag_ooo_peak = received_ahead.len();
                    }

                    // Flush contiguous packets to VIP proxy or packet router.
                    // CRITICAL: distinguish channel-full (backpressure → retry) from
                    // stream-not-found (closed → skip). Dropping data on channel-full
                    // causes permanent TCP gaps; blocking on stream-closed causes deadlock.
                    if let Ok(mut guard) = inner.lock() {
                        let has_vip = guard.vip_proxy.is_some();
                        let has_router = guard.packet_router.is_some();

                        while let Some((sid, data)) = reassembly_buf.remove(&vip_next_deliver_seq) {
                            let mut dispatched = false;
                            let mut backpressure = false;

                            if has_vip {
                                if let Some(ref proxy) = guard.vip_proxy {
                                    match proxy.dispatcher().dispatch(sid, data.clone()) {
                                        Ok(()) => dispatched = true,
                                        Err(crate::vip::DispatchError::ChannelFull) => backpressure = true,
                                        Err(crate::vip::DispatchError::NoStream) => {
                                            // Stream closed/unregistered — skip, don't block
                                        }
                                    }
                                }
                            }

                            if !dispatched && !backpressure && has_router {
                                if let Some(ref mut router) = guard.packet_router {
                                    router.process_gateway_data(sid, &data);
                                    
                                }
                            }

                            if backpressure {
                                // Channel full — put it back and stop flushing.
                                // Next recv iteration retries after consumer drains.
                                reassembly_buf.insert(vip_next_deliver_seq, (sid, data));
                                tracing::debug!(
                                    "recv_loop: dispatch backpressure at data_seq={}, will retry",
                                    vip_next_deliver_seq
                                );
                                break;
                            }

                            // Either dispatched or stream gone — advance either way
                            vip_next_deliver_seq += 1;
                        }
                    }

                    // Delayed ACK: only send every ACK_COALESCE_COUNT packets,
                    // or immediately when there's an out-of-order gap (to trigger
                    // fast retransmit on the gateway), or during startup (first
                    // 64 packets ACK every 2 to help BBR ramp up).
                    // This reduces ACK count from ~870 (for 1MB) to ~70.
                    const ACK_COALESCE_COUNT: u64 = 8; // ACK every 8 packets — less outbound pressure on iOS
                    const ACK_STARTUP_EVERY: u64 = 2;
                    const ACK_STARTUP_THRESHOLD: u64 = 64;
                    let has_gap = !received_ahead.is_empty();
                    let in_startup = next_expected_seq < ACK_STARTUP_THRESHOLD;
                    let is_coalesce_point = if in_startup {
                        next_expected_seq % ACK_STARTUP_EVERY == 0
                    } else {
                        next_expected_seq % ACK_COALESCE_COUNT == 0
                    };
                    let is_first = next_expected_seq <= 1;

                    if is_coalesce_point || has_gap || is_first {
                        let ack_seq = next_expected_seq.saturating_sub(1);
                        let mut ack_frame = Vec::with_capacity(9);
                        ack_frame.push(FRAME_ACK);
                        ack_frame.extend_from_slice(&ack_seq.to_be_bytes());

                        send_ack_frame!(ack_frame);
                        diag_log!("[ZTLP-TX] ACK ack_seq={} via callback", ack_seq);
                        tracing::info!("recv_loop: ACK data_seq={} direct (gap={}, coalesce={}, first={})",
                            ack_seq, has_gap, is_coalesce_point, is_first);
                        last_acked_data_seq = next_expected_seq;
                        last_data_recv_time = None; // ACK sent, reset timer
                        diag_acks_sent += 1;
                    }

                    // ── Periodic diagnostic report ──
                    diag_packets_received += 1;
                    diag_packets_decrypted += 1;
                    let now_diag = std::time::Instant::now();
                    if diag_packets_received % DIAG_REPORT_PACKET_INTERVAL == 0
                        || now_diag.duration_since(diag_last_report).as_millis() > DIAG_REPORT_INTERVAL_MS
                    {
                        let elapsed_ms = now_diag.duration_since(diag_last_report).as_millis();
                        let pps = if elapsed_ms > 0 { diag_packets_received as u128 * 1000 / elapsed_ms } else { 0 };
                        diag_log!(
                            "[ZTLP-DIAG] pkts={} decrypted={} acks_sent={} next_expected={} reassembly_buf={}/{} ooo_peak={} lock_us={} pps={}",
                            diag_packets_received, diag_packets_decrypted, diag_acks_sent,
                            next_expected_seq, reassembly_buf.len(), REASSEMBLY_MAX_ENTRIES,
                            diag_ooo_peak, diag_lock_contention_us, pps
                        );
                        tracing::info!(
                            "recv_diag: pkts={} acks={} next_seq={} reasm_buf={} ooo_peak={} pps={}",
                            diag_packets_received, diag_acks_sent, next_expected_seq,
                            reassembly_buf.len(), diag_ooo_peak, pps
                        );
                        // Reset periodic counters
                        diag_last_report = now_diag;
                        diag_lock_contention_us = 0;
                        diag_ooo_peak = 0;
                    }
                } else if plaintext.len() >= 5 && plaintext[0] == FRAME_FIN {
                    // Per-stream FIN or legacy FIN
                    let fin_stream_id = if plaintext.len() >= 5 {
                        u32::from_be_bytes(plaintext[1..5].try_into().unwrap_or([0u8; 4]))
                    } else {
                        0
                    };
                    if fin_stream_id > 0 {
                        // Multiplexed stream FIN — close the stream's dispatcher channel
                        log_write(
                            &mut debug_log,
                            &mut log_bytes_written,
                            log_start,
                            LogLevel::Info,
                            &format!("FRAME_FIN stream={}", fin_stream_id),
                            log_level,
                            &log_path,
                        );
                        if let Ok(mut guard) = inner.lock() {
                            if let Some(ref proxy) = guard.vip_proxy {
                                proxy.dispatcher().close_stream(fin_stream_id);
                            }
                            // Also notify packet router of stream close
                            if let Some(ref mut router) = guard.packet_router {
                                router.process_gateway_close(fin_stream_id);
                            }
                        }
                    } else {
                        // Legacy FIN (entire session)
                        log_write(
                            &mut debug_log,
                            &mut log_bytes_written,
                            log_start,
                            LogLevel::Info,
                            &format!("FRAME_FIN (legacy), next_expected={}", next_expected_seq),
                            log_level,
                            &log_path,
                        );
                        if next_expected_seq > 0 {
                            let ack_seq = next_expected_seq - 1;
                            let mut ack_frame = Vec::with_capacity(9);
                            ack_frame.push(FRAME_ACK);
                            ack_frame.extend_from_slice(&ack_seq.to_be_bytes());
                            send_ack_frame!(ack_frame);
                        }
                    }
                } else if !plaintext.is_empty() && plaintext[0] == FRAME_CLOSE {
                    // FRAME_CLOSE: remote closed a stream
                    if plaintext.len() >= 5 {
                        let close_stream_id =
                            u32::from_be_bytes(plaintext[1..5].try_into().unwrap_or([0u8; 4]));
                        log_write(
                            &mut debug_log,
                            &mut log_bytes_written,
                            log_start,
                            LogLevel::Info,
                            &format!("FRAME_CLOSE stream={}", close_stream_id),
                            log_level,
                            &log_path,
                        );
                        if let Ok(mut guard) = inner.lock() {
                            if let Some(ref proxy) = guard.vip_proxy {
                                proxy.dispatcher().close_stream(close_stream_id);
                            }
                            if let Some(ref mut router) = guard.packet_router {
                                router.process_gateway_close(close_stream_id);
                            }
                        }
                    }
                }

                // SECURITY: Wrap the decrypt+process path in catch_unwind to
                // prevent a panic from a malicious server response from aborting
                // the entire process. On panic, log the error and continue the
                // recv loop so the session can recover or be cleanly shut down.
                let process_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    process_recv_packet(&plaintext, session_id, peer_node_id, peer_addr, &inner)
                }));

                match process_result {
                    Ok(RecvAction::Continue) => continue,
                    Ok(RecvAction::Break) => break,
                    Ok(RecvAction::Noop) => {}
                    Err(panic_info) => {
                        // A panic occurred during packet processing — log and continue.
                        // This prevents a malicious server response from killing the client.
                        let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_info.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "unknown panic".to_string()
                        };
                        tracing::error!(
                            "recv_loop: panic during packet processing (recovered): {}",
                            msg,
                        );
                        continue;
                    }
                }
            }
            Ok(Ok(None)) => {
                // Packet dropped by pipeline or decrypt failure — continue
                diag_log!("[ZTLP-RX] packet dropped (pipeline/decrypt)");
                log_write(
                    &mut debug_log,
                    &mut log_bytes_written,
                    log_start,
                    LogLevel::Debug,
                    "recv: packet dropped by pipeline (None)",
                    log_level,
                    &log_path,
                );
            }
            Ok(Err(e)) => {
                // Socket error — clean up
                log_write(
                    &mut debug_log,
                    &mut log_bytes_written,
                    log_start,
                    LogLevel::Error,
                    &format!("recv: socket error: {}", e),
                    log_level,
                    &log_path,
                );
                break;
            }
            Err(_) => {
                // Timeout — flush delayed ACKs if needed
                if let Some(recv_time) = last_data_recv_time {
                    if recv_time.elapsed().as_millis() >= ACK_FLUSH_TIMEOUT_MS
                        && next_expected_seq > last_acked_data_seq
                    {
                        // Unacked data has been sitting for >50ms — flush ACK now
                        let ack_seq = next_expected_seq.saturating_sub(1);
                        let mut ack_frame = Vec::with_capacity(9);
                        ack_frame.push(FRAME_ACK);
                        ack_frame.extend_from_slice(&ack_seq.to_be_bytes());

                        send_ack_frame!(ack_frame);
                        tracing::info!("recv_loop: delayed ACK flush data_seq={} direct", ack_seq);
                        last_acked_data_seq = next_expected_seq;
                        last_data_recv_time = None;
                    }
                }

                // NACK: if we have a persistent gap (out-of-order packets received
                // but expected_seq hasn't arrived), tell the gateway exactly which
                // data_seqs are missing so it can retransmit immediately.
                if !received_ahead.is_empty() {
                    let gap_old_enough = gap_detected_at
                        .map(|t| t.elapsed().as_millis() >= NACK_GAP_THRESHOLD_MS)
                        .unwrap_or(false);
                    let nack_allowed = last_nack_time
                        .map(|t| t.elapsed().as_millis() >= NACK_MIN_INTERVAL_MS)
                        .unwrap_or(true);

                    if gap_old_enough && nack_allowed {
                        // Build list of missing data_seqs between next_expected and
                        // the highest buffered seq
                        let max_buffered = received_ahead.iter().next_back().copied().unwrap_or(next_expected_seq);
                        let mut missing: Vec<u64> = Vec::new();
                        let mut seq = next_expected_seq;
                        while seq <= max_buffered && missing.len() < MAX_NACK_SEQS {
                            if !received_ahead.contains(&seq) {
                                missing.push(seq);
                            }
                            seq += 1;
                        }

                        if !missing.is_empty() {
                            // Encode NACK: [FRAME_NACK(1) | count(2 BE) | seq1(8 BE) | seq2(8 BE) | ...]
                            let count = missing.len() as u16;
                            let mut nack_frame = Vec::with_capacity(1 + 2 + (count as usize) * 8);
                            nack_frame.push(FRAME_NACK);
                            nack_frame.extend_from_slice(&count.to_be_bytes());
                            for &ms in &missing {
                                nack_frame.extend_from_slice(&ms.to_be_bytes());
                            }

                            send_ack_frame!(nack_frame);

                            tracing::info!(
                                "recv_loop: NACK sent for {} missing seqs (expected={}, max_buffered={}, first_missing={})",
                                missing.len(), next_expected_seq, max_buffered, missing[0]
                            );
                            last_nack_time = Some(std::time::Instant::now());
                        }
                    }
                }

                // Check keepalive watchdog
                if last_recv_time.elapsed() > KEEPALIVE_TIMEOUT {
                    tracing::warn!(
                        "recv_loop: keepalive timeout ({}s without data)",
                        KEEPALIVE_TIMEOUT.as_secs()
                    );
                    // Invoke disconnect callback
                    if let Ok(guard) = inner.lock() {
                        if let Some((cb, ud)) = guard.disconnect_callback {
                            let mut session_handle = ZtlpSession {
                                session_id,
                                peer_node_id,
                                peer_addr,
                                session_id_str: CString::new(hex::encode(session_id.as_bytes()))
                                    .unwrap_or_default(),
                                peer_node_id_str: CString::new(hex::encode(
                                    peer_node_id.as_bytes(),
                                ))
                                .unwrap_or_default(),
                                peer_addr_str: CString::new(peer_addr.to_string())
                                    .unwrap_or_default(),
                            };
                            cb(ud, &mut session_handle, DISCONNECT_KEEPALIVE_TIMEOUT);
                        }
                    }
                    // Update state and stop VIP proxy (it holds refs to old transport)
                    if let Ok(mut guard) = inner.lock() {
                        if let Some(ref mut proxy) = guard.vip_proxy {
                            proxy.stop();
                        }
                        if let Some(ref mut dns) = guard.dns_server {
                            dns.stop();
                        }
                        guard.state = ConnectionState::Disconnected;
                        guard.active_session = None;
                    }
                    break;
                }
            }
        }
    }

    // Mark as disconnected
    if let Ok(mut guard) = inner.lock() {
        guard.state = ConnectionState::Disconnected;
    }
}

/// Disconnect from the current session.
#[no_mangle]
pub extern "C" fn ztlp_disconnect(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    // Stop VIP proxy first (before clearing session)
    if let Some(ref mut proxy) = guard.vip_proxy {
        proxy.stop();
    }

    if let Some(ref session) = guard.active_session {
        session.stop_flag.store(true, Ordering::SeqCst);
    }
    guard.active_session = None;
    guard.state = ConnectionState::Disconnected;
    ZtlpResult::Ok as i32
}

/// Disconnect the tunnel transport session only.
///
/// Unlike `ztlp_disconnect`, this keeps the VIP proxy listeners alive and
/// the runtime running. Used for reconnect flows — after calling this,
/// call `ztlp_connect` again and then `ztlp_vip_start` to hot-swap the
/// tunnel session in the existing proxy listeners.
///
/// This avoids the need to rebind TCP ports (which drops in-flight connections)
/// and prevents the admin password prompt that setupNetworking requires.
#[no_mangle]
pub extern "C" fn ztlp_disconnect_transport(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    // Stop the recv loop but keep VIP proxy listeners running
    if let Some(ref session) = guard.active_session {
        session.stop_flag.store(true, Ordering::SeqCst);
    }
    guard.active_session = None;
    // Set to reconnecting (not disconnected) — keeps VIP proxy ready
    guard.state = ConnectionState::Reconnecting;
    tracing::info!("transport disconnected (VIP proxy listeners preserved)");
    ZtlpResult::Ok as i32
}

/// Listen for incoming ZTLP connections (placeholder — used by responder/server).
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
    ZtlpResult::Ok as i32
}

// ── Data functions — REAL IMPLEMENTATION ────────────────────────────────

/// Send encrypted data through the active ZTLP session.
///
/// The data is encrypted with ChaCha20-Poly1305 using the session keys
/// derived from the Noise_XX handshake, wrapped in a ZTLP data packet,
/// and sent over UDP to the peer.
#[no_mangle]
pub extern "C" fn ztlp_send(client: *mut ZtlpClient, data: *const u8, len: usize) -> i32 {
    if client.is_null() || data.is_null() {
        set_last_error("client or data is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    if len == 0 {
        return ZtlpResult::Ok as i32;
    }

    let client = unsafe { &*client };
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };

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

    let session = match guard.active_session.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("no active session");
            return ZtlpResult::SessionNotFound as i32;
        }
    };

    let transport = session.transport.clone();
    let session_id = session.session_id;
    let peer_addr = session.peer_addr;
    let bytes_sent = session.bytes_sent.clone();
    let data_seq = session.data_seq.fetch_add(1, Ordering::Relaxed);
    let raw_payload = data_slice.to_vec();

    // Wrap in tunnel frame: [FRAME_DATA(1) | data_seq(8 BE) | payload]
    // The gateway expects this framing before decrypted TCP data.
    const FRAME_DATA: u8 = 0x00;
    let mut framed = Vec::with_capacity(1 + 8 + raw_payload.len());
    framed.push(FRAME_DATA);
    framed.extend_from_slice(&data_seq.to_be_bytes());
    framed.extend_from_slice(&raw_payload);

    // Send on the runtime — we can't block here
    guard.runtime.spawn(async move {
        if let Err(e) = transport.send_data(session_id, &framed, peer_addr).await {
            set_last_error(&format!("send failed: {}", e));
        } else {
            bytes_sent.fetch_add(raw_payload.len() as u64, Ordering::Relaxed);
        }
    });

    ZtlpResult::Ok as i32
}

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

#[no_mangle]
pub extern "C" fn ztlp_set_ack_send_callback(
    client: *mut ZtlpClient,
    callback: ZtlpAckSendCallback,
    user_data: *mut c_void,
) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };
    guard.ack_send_callback = Some((callback, user_data));
    ZtlpResult::Ok as i32
}

// ── Session info functions ──────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn ztlp_session_peer_node_id(session: *const ZtlpSession) -> *const c_char {
    if session.is_null() {
        set_last_error("session handle is null");
        return std::ptr::null();
    }
    let session = unsafe { &*session };
    session.peer_node_id_str.as_ptr()
}

#[no_mangle]
pub extern "C" fn ztlp_session_id(session: *const ZtlpSession) -> *const c_char {
    if session.is_null() {
        set_last_error("session handle is null");
        return std::ptr::null();
    }
    let session = unsafe { &*session };
    session.session_id_str.as_ptr()
}

#[no_mangle]
pub extern "C" fn ztlp_session_peer_addr(session: *const ZtlpSession) -> *const c_char {
    if session.is_null() {
        set_last_error("session handle is null");
        return std::ptr::null();
    }
    let session = unsafe { &*session };
    session.peer_addr_str.as_ptr()
}

// ── Stats functions ─────────────────────────────────────────────────────

/// Get the number of bytes sent through the active session.
#[no_mangle]
pub extern "C" fn ztlp_bytes_sent(client: *const ZtlpClient) -> u64 {
    if client.is_null() {
        return 0;
    }
    let client = unsafe { &*client };
    let guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    guard
        .active_session
        .as_ref()
        .map(|s| s.bytes_sent.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Get the number of bytes received through the active session.
#[no_mangle]
pub extern "C" fn ztlp_bytes_received(client: *const ZtlpClient) -> u64 {
    if client.is_null() {
        return 0;
    }
    let client = unsafe { &*client };
    let guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    guard
        .active_session
        .as_ref()
        .map(|s| s.bytes_received.load(Ordering::Relaxed))
        .unwrap_or(0)
}

// ── Tunnel functions ────────────────────────────────────────────────────

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
    ZtlpResult::Ok as i32
}

#[no_mangle]
pub extern "C" fn ztlp_tunnel_stop(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    ZtlpResult::Ok as i32
}

// ── Utility functions ───────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn ztlp_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn ztlp_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ztlp_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(cstr) => cstr.as_ptr(),
        None => std::ptr::null(),
    })
}

// ── VIP Proxy functions ─────────────────────────────────────────────────

/// Register a service with a VIP (Virtual IP) address and port.
///
/// The VIP proxy will listen on `vip:port` and forward TCP traffic
/// through the ZTLP tunnel.
///
/// # Example
/// ```c
/// ztlp_vip_add_service(client, "beta", "127.0.55.1", 80);
/// ztlp_vip_add_service(client, "beta", "127.0.55.1", 443);
/// ```
#[no_mangle]
pub extern "C" fn ztlp_vip_add_service(
    client: *mut ZtlpClient,
    name: *const c_char,
    vip: *const c_char,
    port: u16,
) -> i32 {
    if client.is_null() || name.is_null() || vip.is_null() {
        set_last_error("client, name, or vip is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let client = unsafe { &*client };
    let name_str = unsafe { CStr::from_ptr(name) };
    let name_string = match name_str.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in name: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let vip_str = unsafe { CStr::from_ptr(vip) };
    let vip_string = match vip_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in vip: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let vip_addr: std::net::Ipv4Addr = match vip_string.parse() {
        Ok(a) => a,
        Err(e) => {
            set_last_error(&format!("invalid VIP address '{}': {}", vip_string, e));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    // Initialize VIP proxy if needed
    if guard.vip_proxy.is_none() {
        guard.vip_proxy = Some(VipProxy::new());
    }

    if let Some(ref mut proxy) = guard.vip_proxy {
        if let Err(e) = proxy.add_service(name_string.clone(), vip_addr, port) {
            set_last_error(&e);
            return ZtlpResult::InvalidArgument as i32;
        }
    }

    // Also update the shared DNS registry
    let registry = guard.vip_registry.clone();
    guard.runtime.spawn(async move {
        let mut reg = registry.write().await;
        reg.insert(name_string, vip_addr);
    });

    ZtlpResult::Ok as i32
}

/// Start VIP proxy listeners for all registered services.
///
/// Requires an active ZTLP session. Each registered service will get
/// a TCP listener on its VIP:port that pipes data through the tunnel.
#[no_mangle]
pub extern "C" fn ztlp_vip_start(client: *mut ZtlpClient) -> i32 {
    ios_log("[ZTLP] ztlp_vip_start called");
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let client = unsafe { &*client };
    ios_log("[ZTLP] vip_start: acquiring lock...");
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };
    ios_log("[ZTLP] vip_start: lock acquired");

    if guard.state != ConnectionState::Connected {
        set_last_error("not connected — connect first, then start VIP proxy");
        ios_log("[ZTLP] vip_start: not connected");
        return ZtlpResult::NotConnected as i32;
    }

    let session = match guard.active_session.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("no active session");
            ios_log("[ZTLP] vip_start: no active session");
            return ZtlpResult::SessionNotFound as i32;
        }
    };

    let transport = session.transport.clone();
    let session_id = session.session_id;
    let peer_addr = session.peer_addr;
    let data_seq = session.data_seq.clone();
    let bytes_sent = session.bytes_sent.clone();
    let runtime_handle = guard.runtime.handle().clone();

    let mut proxy = match guard.vip_proxy.take() {
        Some(p) => p,
        None => {
            set_last_error("no services registered — call ztlp_vip_add_service first");
            ios_log("[ZTLP] vip_start: no services registered");
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    // Drop the lock BEFORE block_on to avoid deadlock with recv_loop.
    // recv_loop constantly locks inner to process packets — holding the lock
    // during block_on can deadlock if recv_loop is waiting for the lock.
    ios_log("[ZTLP] vip_start: dropping lock before proxy.start()");
    drop(guard);

    // Start proxy listeners on the runtime (lock is NOT held)
    ios_log("[ZTLP] vip_start: calling proxy.start()...");
    let result = runtime_handle.block_on(async {
        proxy
            .start(transport, session_id, peer_addr, data_seq, bytes_sent)
            .await
    });
    ios_log("[ZTLP] vip_start: proxy.start() returned");

    // Re-acquire lock to store results
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned after vip_start: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    guard.vip_proxy = Some(proxy);

    match result {
        Ok((ack_tx, send_enqueue_tx)) => {
            // Store the ACK channel sender so the recv_loop can feed
            // gateway upload ACKs to the SendController.
            // Store the send_enqueue_tx so the recv_loop can route download
            // ACKs through the SendController (for reliable delivery).
            if let Some(ref mut session) = guard.active_session {
                session.upload_ack_tx = Some(ack_tx);
                session.send_enqueue_tx = Some(send_enqueue_tx);
            }
            ios_log("[ZTLP] vip_start: OK, channels stored");
            ZtlpResult::Ok as i32
        }
        Err(e) => {
            ios_log(&format!("[ZTLP] vip_start: FAILED: {}", e));
            set_last_error(&format!("VIP proxy start failed: {e}"));
            ZtlpResult::ConnectionError as i32
        }
    }
}

/// Stop all VIP proxy listeners.
#[no_mangle]
pub extern "C" fn ztlp_vip_stop(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    if let Some(ref mut proxy) = guard.vip_proxy {
        proxy.stop();
    }

    ZtlpResult::Ok as i32
}

// ── DNS Resolver functions ──────────────────────────────────────────────

/// Start the ZTLP DNS resolver on the given listen address.
///
/// Resolves `*.ztlp` domain queries to VIP addresses based on registered
/// services. Typically bound to `127.0.55.53:53`.
///
/// # macOS Setup
/// Create `/etc/resolver/ztlp` with:
/// ```text
/// nameserver 127.0.55.53
/// ```
/// This tells macOS to route all `*.ztlp` queries to our DNS server.
#[no_mangle]
pub extern "C" fn ztlp_dns_start(client: *mut ZtlpClient, listen_addr: *const c_char) -> i32 {
    if client.is_null() || listen_addr.is_null() {
        set_last_error("client or listen_addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let client = unsafe { &*client };
    let addr_str = unsafe { CStr::from_ptr(listen_addr) };
    let addr_string = match addr_str.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in listen_addr: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let bind_addr: SocketAddr = match addr_string.parse() {
        Ok(a) => a,
        Err(e) => {
            set_last_error(&format!("invalid address '{}': {}", addr_string, e));
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    // Stop existing DNS server if any
    if let Some(ref mut dns) = guard.dns_server {
        dns.stop();
    }

    let registry = guard.vip_registry.clone();
    let mut dns = ZtlpDns::new(registry);

    let result = guard.runtime.block_on(async { dns.start(bind_addr).await });

    match result {
        Ok(()) => {
            guard.dns_server = Some(dns);
            ZtlpResult::Ok as i32
        }
        Err(e) => {
            set_last_error(&format!("DNS start failed: {e}"));
            ZtlpResult::ConnectionError as i32
        }
    }
}

/// Stop the ZTLP DNS resolver.
#[no_mangle]
pub extern "C" fn ztlp_dns_stop(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(e) => {
            set_last_error(&format!("mutex poisoned: {e}"));
            return ZtlpResult::InternalError as i32;
        }
    };

    if let Some(ref mut dns) = guard.dns_server {
        dns.stop();
    }
    guard.dns_server = None;

    ZtlpResult::Ok as i32
}

// ── NS Resolution ───────────────────────────────────────────────────────

/// Resolve a ZTLP service name via NS, returning the gateway endpoint address.
///
/// Queries the NS server for a SVC record matching `service_name` (e.g.,
/// "beta.techrockstars.ztlp"). On success, returns a heap-allocated C string
/// containing the resolved address (e.g., "10.42.42.112:23098"). The caller
/// must free the string with `ztlp_string_free`.
///
/// Returns NULL on failure (check `ztlp_last_error` for details).
///
/// # Parameters
/// - `service_name`: The ZTLP-NS name to resolve (e.g., "beta.techrockstars.ztlp")
/// - `ns_server`: The NS server address (e.g., "52.39.59.34:23096")
/// - `timeout_ms`: Query timeout in milliseconds (0 = default 5000ms)
#[no_mangle]
pub extern "C" fn ztlp_ns_resolve(
    service_name: *const c_char,
    ns_server: *const c_char,
    timeout_ms: u32,
) -> *mut c_char {
    if service_name.is_null() || ns_server.is_null() {
        set_last_error("service_name or ns_server is null");
        return std::ptr::null_mut();
    }

    let name = match unsafe { CStr::from_ptr(service_name) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("invalid UTF-8 in service_name");
            return std::ptr::null_mut();
        }
    };

    let server = match unsafe { CStr::from_ptr(ns_server) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("invalid UTF-8 in ns_server");
            return std::ptr::null_mut();
        }
    };

    let timeout = if timeout_ms == 0 {
        5000
    } else {
        timeout_ms as u64
    };

    // Run NS resolution on a dedicated thread to avoid nesting tokio runtimes.
    // The FFI may be called from Swift's async context which already has a runtime.
    let (tx, rx) = std::sync::mpsc::channel();
    let name_for_err = name.clone();
    let server_for_err = server.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(Err(format!("failed to create runtime: {e}")));
                return;
            }
        };

        let result = rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(timeout),
                crate::agent::proxy::ns_resolve(&name, &server),
            )
            .await
        });

        let _ = match result {
            Ok(Ok(resolution)) => tx.send(Ok(resolution.addr.to_string())),
            Ok(Err(e)) => tx.send(Err(format!("NS resolution failed: {e}"))),
            Err(_) => tx.send(Err(format!(
                "NS resolution timed out after {}ms (server: {}, name: {})",
                timeout, server, name
            ))),
        };

        // Explicitly shut down the runtime to avoid "Cannot drop a runtime
        // in a context where blocking is not allowed" panics.
        rt.shutdown_background();
    });

    // Wait for the thread to complete (with extra margin for thread startup)
    let wait_time = std::time::Duration::from_millis(timeout + 2000);
    match rx.recv_timeout(wait_time) {
        Ok(Ok(addr_str)) => match CString::new(addr_str) {
            Ok(cs) => cs.into_raw(),
            Err(_) => {
                set_last_error("resolved address contains null byte");
                std::ptr::null_mut()
            }
        },
        Ok(Err(e)) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error(&format!(
                "NS resolution thread timed out (server: {}, name: {})",
                server_for_err, name_for_err
            ));
            std::ptr::null_mut()
        }
    }
}

// ── NS Certificate Authority FFI ────────────────────────────────────────

/// Fetch the CA root certificate (DER-encoded) from the ZTLP-NS server.
///
/// Sends a `0x14 0x01` query to the NS and returns the raw DER bytes.
/// The caller receives a pointer and length via `out_data` and `out_len`.
/// The returned buffer must be freed with `ztlp_bytes_free()`.
///
/// Returns 0 on success, negative on error.
///
/// # Parameters
/// - `ns_server`: NS server address as "host:port" C string
/// - `timeout_ms`: Query timeout in milliseconds (0 = default 5000ms)
/// - `out_data`: Pointer to receive the DER data pointer
/// - `out_len`: Pointer to receive the data length
#[no_mangle]
pub extern "C" fn ztlp_ns_fetch_ca_root(
    ns_server: *const c_char,
    timeout_ms: u32,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    if ns_server.is_null() || out_data.is_null() || out_len.is_null() {
        set_last_error("ns_server, out_data, or out_len is null");
        return ZtlpResult::InvalidArgument as i32;
    }

    let server = match unsafe { CStr::from_ptr(ns_server) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("invalid UTF-8 in ns_server");
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    let timeout = if timeout_ms == 0 {
        5000
    } else {
        timeout_ms as u64
    };

    // Use a dedicated thread to avoid nesting tokio runtimes
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::net::UdpSocket;

        let result = (|| -> Result<Vec<u8>, String> {
            let addr: SocketAddr = server
                .parse()
                .map_err(|e| format!("invalid ns_server address: {e}"))?;

            let socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| format!("failed to bind UDP socket: {e}"))?;
            socket
                .set_read_timeout(Some(Duration::from_millis(timeout)))
                .map_err(|e| format!("failed to set timeout: {e}"))?;

            // Send query: 0x14 0x01 (get CA root DER)
            let query = [0x14u8, 0x01];
            socket
                .send_to(&query, addr)
                .map_err(|e| format!("failed to send query: {e}"))?;

            // Receive response
            let mut buf = vec![0u8; 8192];
            let len = socket
                .recv(&mut buf)
                .map_err(|e| format!("failed to receive response: {e}"))?;
            buf.truncate(len);

            // Parse: <<0x14, 0x01, 0x00, cert_len(4 BE), cert_der>>
            if buf.len() < 3 {
                return Err("response too short".to_string());
            }
            if buf[0] != 0x14 || buf[1] != 0x01 {
                return Err(format!(
                    "unexpected response type: 0x{:02x}{:02x}",
                    buf[0], buf[1]
                ));
            }
            if buf[2] == 0x01 {
                return Err("CA not initialized on NS server".to_string());
            }
            if buf[2] != 0x00 || buf.len() < 7 {
                return Err(format!("unexpected status byte: 0x{:02x}", buf[2]));
            }

            let cert_len = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
            if buf.len() < 7 + cert_len {
                return Err(format!(
                    "truncated response: expected {} cert bytes, got {}",
                    cert_len,
                    buf.len() - 7
                ));
            }

            Ok(buf[7..7 + cert_len].to_vec())
        })();

        let _ = tx.send(result);
    });

    let wait_time = Duration::from_millis(timeout + 2000);
    match rx.recv_timeout(wait_time) {
        Ok(Ok(der_bytes)) => {
            let len = der_bytes.len();
            let ptr = unsafe {
                let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
                let p = std::alloc::alloc(layout);
                if p.is_null() {
                    set_last_error("allocation failed");
                    return ZtlpResult::InternalError as i32;
                }
                std::ptr::copy_nonoverlapping(der_bytes.as_ptr(), p, len);
                p
            };
            unsafe {
                *out_data = ptr;
                *out_len = len as u32;
            }
            0
        }
        Ok(Err(e)) => {
            set_last_error(&e);
            ZtlpResult::ConnectionError as i32
        }
        Err(_) => {
            set_last_error("NS CA root query timed out");
            ZtlpResult::ConnectionError as i32
        }
    }
}

/// Free a byte buffer returned by `ztlp_ns_fetch_ca_root()`.
///
/// # Safety
/// `data` must have been returned by a `ztlp_ns_fetch_ca_*` function,
/// and `len` must match the returned length.
#[no_mangle]
pub extern "C" fn ztlp_bytes_free(data: *mut u8, len: u32) {
    if data.is_null() || len == 0 {
        return;
    }
    unsafe {
        let layout = std::alloc::Layout::from_size_align(len as usize, 1).unwrap();
        std::alloc::dealloc(data, layout);
    }
}

/// Fetch the CA chain (PEM-encoded intermediate + root) from the ZTLP-NS server.
///
/// Returns a C string (null-terminated PEM). Caller must free with `ztlp_string_free()`.
/// Returns null on error (check `ztlp_last_error()`).
#[no_mangle]
pub extern "C" fn ztlp_ns_fetch_ca_chain_pem(
    ns_server: *const c_char,
    timeout_ms: u32,
) -> *mut c_char {
    if ns_server.is_null() {
        set_last_error("ns_server is null");
        return std::ptr::null_mut();
    }

    let server = match unsafe { CStr::from_ptr(ns_server) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("invalid UTF-8 in ns_server");
            return std::ptr::null_mut();
        }
    };

    let timeout = if timeout_ms == 0 {
        5000
    } else {
        timeout_ms as u64
    };

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::net::UdpSocket;

        let result = (|| -> Result<String, String> {
            let addr: SocketAddr = server
                .parse()
                .map_err(|e| format!("invalid ns_server address: {e}"))?;

            let socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| format!("failed to bind UDP socket: {e}"))?;
            socket
                .set_read_timeout(Some(Duration::from_millis(timeout)))
                .map_err(|e| format!("failed to set timeout: {e}"))?;

            // Send query: 0x14 0x02 (get CA chain PEM)
            let query = [0x14u8, 0x02];
            socket
                .send_to(&query, addr)
                .map_err(|e| format!("failed to send query: {e}"))?;

            let mut buf = vec![0u8; 16384]; // chain PEM can be larger
            let len = socket
                .recv(&mut buf)
                .map_err(|e| format!("failed to receive response: {e}"))?;
            buf.truncate(len);

            // Parse: <<0x14, 0x02, 0x00, chain_len(4 BE), chain_pem>>
            if buf.len() < 3 {
                return Err("response too short".to_string());
            }
            if buf[0] != 0x14 || buf[1] != 0x02 {
                return Err(format!(
                    "unexpected response type: 0x{:02x}{:02x}",
                    buf[0], buf[1]
                ));
            }
            if buf[2] == 0x01 {
                return Err("CA not initialized on NS server".to_string());
            }
            if buf[2] != 0x00 || buf.len() < 7 {
                return Err(format!("unexpected status byte: 0x{:02x}", buf[2]));
            }

            let chain_len = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
            if buf.len() < 7 + chain_len {
                return Err(format!(
                    "truncated response: expected {} chain bytes, got {}",
                    chain_len,
                    buf.len() - 7
                ));
            }

            String::from_utf8(buf[7..7 + chain_len].to_vec())
                .map_err(|e| format!("invalid UTF-8 in chain PEM: {e}"))
        })();

        let _ = tx.send(result);
    });

    let wait_time = Duration::from_millis(timeout + 2000);
    match rx.recv_timeout(wait_time) {
        Ok(Ok(pem)) => match CString::new(pem) {
            Ok(cs) => cs.into_raw(),
            Err(_) => {
                set_last_error("chain PEM contains null byte");
                std::ptr::null_mut()
            }
        },
        Ok(Err(e)) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("NS CA chain query timed out");
            std::ptr::null_mut()
        }
    }
}

// ── Packet Router FFI (iOS utun) ────────────────────────────────────────

/// Create a new packet router for the iOS utun interface.
///
/// The `tunnel_addr` is the IP address assigned to the utun interface
/// (e.g., "10.122.0.100"). This should match the address configured in
/// `NEPacketTunnelProvider`.
///
/// Returns 0 on success, or a negative error code.
#[no_mangle]
pub extern "C" fn ztlp_router_new(client: *mut ZtlpClient, tunnel_addr: *const c_char) -> i32 {
    if client.is_null() || tunnel_addr.is_null() {
        set_last_error("client or tunnel_addr is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let addr_cstr = unsafe { CStr::from_ptr(tunnel_addr) };
    let addr_str = match addr_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in tunnel_addr: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };
    if addr_str.len() > MAX_FFI_ADDRESS_LEN {
        set_last_error("tunnel_addr too long");
        return ZtlpResult::InvalidArgument as i32;
    }
    let addr: std::net::Ipv4Addr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            set_last_error(&format!("invalid tunnel_addr '{}': {}", addr_str, e));
            return ZtlpResult::InvalidArgument as i32;
        }
    };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("lock poisoned");
            return ZtlpResult::InternalError as i32;
        }
    };
    guard.packet_router = Some(crate::packet_router::PacketRouter::new(addr));

    // Set up the router action channel and processing task
    // (requires an active session with transport access)
    if let Some(ref mut session) = guard.active_session {
        let (action_tx, mut action_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::packet_router::RouterAction>();
        session.router_action_tx = Some(action_tx);

        let transport = session.transport.clone();
        let session_id = session.session_id;
        let peer_addr = session.peer_addr;
        let stop = session.stop_flag.clone();

        // Spawn async task that reads router actions and sends ZTLP mux frames
        guard.runtime.spawn(async move {
            use crate::packet_router::RouterAction;
            const FRAME_OPEN: u8 = 0x06;
            const FRAME_DATA: u8 = 0x00;
            const FRAME_CLOSE: u8 = 0x05;

            while let Some(action) = action_rx.recv().await {
                if stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match action {
                    RouterAction::OpenStream {
                        stream_id,
                        service_name,
                    } => {
                        // FRAME_OPEN with service name:
                        // [0x06 | stream_id(4 BE) | service_name_len(1) | service_name]
                        let name_bytes = service_name.as_bytes();
                        let mut frame = Vec::with_capacity(5 + 1 + name_bytes.len());
                        frame.push(FRAME_OPEN);
                        frame.extend_from_slice(&stream_id.to_be_bytes());
                        frame.push(name_bytes.len() as u8);
                        frame.extend_from_slice(name_bytes);
                        if let Err(e) = transport.send_data(session_id, &frame, peer_addr).await {
                            tracing::warn!(
                                "router: failed to send OPEN for stream {}: {}",
                                stream_id,
                                e
                            );
                        } else {
                            tracing::info!(
                                "router: sent OPEN for stream {} (service={})",
                                stream_id,
                                service_name
                            );
                        }
                    }
                    RouterAction::SendData { stream_id, data } => {
                        // Chunk data into MAX_MUX_PAYLOAD-sized frames
                        // max_payload(1140) - mux_header(5) = 1135
                        const MAX_MUX_PAYLOAD: usize = 1135;
                        for chunk in data.chunks(MAX_MUX_PAYLOAD) {
                            let mut frame = Vec::with_capacity(5 + chunk.len());
                            frame.push(FRAME_DATA);
                            frame.extend_from_slice(&stream_id.to_be_bytes());
                            frame.extend_from_slice(chunk);
                            if let Err(e) = transport.send_data(session_id, &frame, peer_addr).await
                            {
                                tracing::warn!(
                                    "router: failed to send DATA for stream {}: {}",
                                    stream_id,
                                    e
                                );
                                break;
                            }
                        }
                    }
                    RouterAction::CloseStream { stream_id } => {
                        let mut frame = Vec::with_capacity(5);
                        frame.push(FRAME_CLOSE);
                        frame.extend_from_slice(&stream_id.to_be_bytes());
                        let _ = transport.send_data(session_id, &frame, peer_addr).await;
                        tracing::info!("router: sent CLOSE for stream {}", stream_id);
                    }
                }
            }
            tracing::info!("router: action processing task exiting");
        });

        tracing::info!(
            "router: initialized with tunnel_addr={}, action task spawned",
            addr
        );
    } else {
        tracing::warn!(
            "router: initialized but no active session — actions won't be sent until connect"
        );
    }

    ZtlpResult::Ok as i32
}

/// Register a VIP service with the packet router.
///
/// Maps a VIP address (e.g., "10.122.0.1") to a ZTLP service name
/// (e.g., "vault"). Traffic destined for the VIP will be routed through
/// a ZTLP mux stream to the named service on the gateway.
///
/// Returns 0 on success, or a negative error code.
#[no_mangle]
pub extern "C" fn ztlp_router_add_service(
    client: *mut ZtlpClient,
    vip: *const c_char,
    service_name: *const c_char,
) -> i32 {
    if client.is_null() || vip.is_null() || service_name.is_null() {
        set_last_error("client, vip, or service_name is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let vip_str = match unsafe { CStr::from_ptr(vip) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in vip: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };
    let name_str = match unsafe { CStr::from_ptr(service_name) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in service_name: {e}"));
            return ZtlpResult::InvalidArgument as i32;
        }
    };
    if vip_str.len() > MAX_FFI_ADDRESS_LEN {
        set_last_error("vip address too long");
        return ZtlpResult::InvalidArgument as i32;
    }
    let addr: std::net::Ipv4Addr = match vip_str.parse() {
        Ok(a) => a,
        Err(e) => {
            set_last_error(&format!("invalid vip '{}': {}", vip_str, e));
            return ZtlpResult::InvalidArgument as i32;
        }
    };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("lock poisoned");
            return ZtlpResult::InternalError as i32;
        }
    };
    match guard.packet_router.as_mut() {
        Some(router) => {
            router.add_service(addr, name_str.to_string());
            ZtlpResult::Ok as i32
        }
        None => {
            set_last_error("packet router not initialized (call ztlp_router_new first)");
            ZtlpResult::NotConnected as i32
        }
    }
}

/// Write a raw IPv4 packet into the packet router (from utun → ZTLP).
///
/// Called by Swift when `NEPacketTunnelProvider.readPackets()` delivers a
/// packet from the utun interface. The router parses the IP/TCP headers,
/// manages TCP state, and queues ZTLP actions.
///
/// **Note:** In the current implementation, ZTLP mux actions (OpenStream,
/// SendData, CloseStream) are processed internally. The caller should call
/// `ztlp_router_read_packet()` after this to retrieve outbound response
/// packets (SYN-ACK, ACK, data responses).
///
/// Returns 0 on success, or a negative error code.
#[no_mangle]
pub extern "C" fn ztlp_router_write_packet(
    client: *mut ZtlpClient,
    data: *const u8,
    len: usize,
) -> i32 {
    if client.is_null() || data.is_null() {
        set_last_error("client or data is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let packet = unsafe { std::slice::from_raw_parts(data, len) };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("lock poisoned");
            return ZtlpResult::InternalError as i32;
        }
    };
    match guard.packet_router.as_mut() {
        Some(router) => {
            let actions = router.process_inbound(packet);
            // Forward router actions to the async transport via channel
            if !actions.is_empty() {
                if let Some(ref session) = guard.active_session {
                    if let Some(ref tx) = session.router_action_tx {
                        for action in actions {
                            let _ = tx.send(action);
                        }
                    } else {
                        tracing::warn!("router: actions generated but no router_action_tx channel");
                    }
                } else {
                    tracing::warn!("router: actions generated but no active session");
                }
            }
            ZtlpResult::Ok as i32
        }
        None => {
            set_last_error("packet router not initialized");
            ZtlpResult::NotConnected as i32
        }
    }
}

/// Read the next outbound IPv4 packet from the router (ZTLP → utun).
///
/// Called by Swift to get response packets to inject back into the utun
/// interface via `writePackets()`. The packet router generates these in
/// response to:
/// - TCP handshakes (SYN-ACK)
/// - Data acknowledgments (ACK)
/// - Gateway response data (TCP data packets)
/// - Connection teardown (FIN, RST)
///
/// Returns:
/// - Positive value: number of bytes written to `buf` (one complete IPv4 packet)
/// - 0: no packets available
/// - Negative: error
#[no_mangle]
pub extern "C" fn ztlp_router_read_packet(
    client: *mut ZtlpClient,
    buf: *mut u8,
    buf_len: usize,
) -> i32 {
    if client.is_null() || buf.is_null() {
        set_last_error("client or buf is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("lock poisoned");
            return ZtlpResult::InternalError as i32;
        }
    };
    match guard.packet_router.as_mut() {
        Some(router) => {
            // Pop one packet at a time (caller loops until 0 is returned)
            if let Some(pkt) = router.pop_outbound() {
                if pkt.len() > buf_len {
                    set_last_error(&format!(
                        "packet too large for buffer ({} > {})",
                        pkt.len(),
                        buf_len
                    ));
                    return -1;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(pkt.as_ptr(), buf, pkt.len());
                }
                pkt.len() as i32
            } else {
                0
            }
        }
        None => {
            set_last_error("packet router not initialized");
            -1
        }
    }
}

/// Stop and destroy the packet router.
///
/// Cleans up all TCP flows and releases resources. Call this when the
/// VPN tunnel is being torn down.
///
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn ztlp_router_stop(client: *mut ZtlpClient) -> i32 {
    if client.is_null() {
        set_last_error("client is null");
        return ZtlpResult::InvalidArgument as i32;
    }
    let client = unsafe { &*client };
    let mut guard = match client.inner.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("lock poisoned");
            return ZtlpResult::InternalError as i32;
        }
    };
    guard.packet_router = None;
    ZtlpResult::Ok as i32
}

// ── Gateway Key Pinning ─────────────────────────────────────────────────

/// Pin a gateway's static Noise public key for certificate pinning.
///
/// The key is stored in the default config file (`~/.ztlp/config.toml`).
/// After pinning, subsequent connections will reject gateways whose
/// static key doesn't match any pinned key.
///
/// # Parameters
/// - `key_hex`: Hex-encoded 32-byte X25519 public key (64 hex chars).
///
/// # Returns
/// - `ZTLP_OK` on success
/// - `ZTLP_INVALID_ARGUMENT` if `key_hex` is null, not valid hex, or wrong length
/// - `ZTLP_INTERNAL_ERROR` on file I/O failure
#[no_mangle]
pub extern "C" fn ztlp_pin_gateway_key(key_hex: *const c_char) -> i32 {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if key_hex.is_null() {
            set_last_error("key_hex is null");
            return ZtlpResult::InvalidArgument as i32;
        }

        let key_str = match unsafe { CStr::from_ptr(key_hex) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("key_hex is not valid UTF-8");
                return ZtlpResult::InvalidArgument as i32;
            }
        };

        if key_str.len() > MAX_FFI_ADDRESS_LEN {
            set_last_error("key_hex too long");
            return ZtlpResult::InvalidArgument as i32;
        }

        let key_bytes = match hex::decode(key_str) {
            Ok(b) => b,
            Err(e) => {
                set_last_error(&format!("invalid hex: {}", e));
                return ZtlpResult::InvalidArgument as i32;
            }
        };

        if key_bytes.len() != 32 {
            set_last_error(&format!(
                "key must be 32 bytes, got {} bytes",
                key_bytes.len()
            ));
            return ZtlpResult::InvalidArgument as i32;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let config_path = match dirs::home_dir() {
            Some(h) => h.join(".ztlp").join("config.toml"),
            None => {
                set_last_error("could not determine home directory");
                return ZtlpResult::InternalError as i32;
            }
        };

        match crate::enrollment::pin_gateway_key(&config_path, &key) {
            Ok(()) => ZtlpResult::Ok as i32,
            Err(e) => {
                set_last_error(&format!("failed to pin key: {}", e));
                ZtlpResult::InternalError as i32
            }
        }
    }));

    result.unwrap_or_else(|_| {
        set_last_error("panic in ztlp_pin_gateway_key");
        ZtlpResult::InternalError as i32
    })
}

/// Verify a gateway's static key against pinned keys.
///
/// Checks if the given hex-encoded key matches any key in the config file's
/// `pinned_gateway_keys` list.
///
/// # Parameters
/// - `key_hex`: Hex-encoded 32-byte X25519 public key (64 hex chars).
///
/// # Returns
/// - `1` if the key matches a pinned key (or no keys are pinned)
/// - `0` if the key does NOT match any pinned key
/// - Negative error code on invalid input
#[no_mangle]
pub extern "C" fn ztlp_verify_gateway_pin(key_hex: *const c_char) -> i32 {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if key_hex.is_null() {
            set_last_error("key_hex is null");
            return ZtlpResult::InvalidArgument as i32;
        }

        let key_str = match unsafe { CStr::from_ptr(key_hex) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("key_hex is not valid UTF-8");
                return ZtlpResult::InvalidArgument as i32;
            }
        };

        if key_str.len() > MAX_FFI_ADDRESS_LEN {
            set_last_error("key_hex too long");
            return ZtlpResult::InvalidArgument as i32;
        }

        let key_bytes = match hex::decode(key_str) {
            Ok(b) => b,
            Err(e) => {
                set_last_error(&format!("invalid hex: {}", e));
                return ZtlpResult::InvalidArgument as i32;
            }
        };

        if key_bytes.len() != 32 {
            set_last_error(&format!(
                "key must be 32 bytes, got {} bytes",
                key_bytes.len()
            ));
            return ZtlpResult::InvalidArgument as i32;
        }

        // Load pinned keys from agent config
        let agent_config = crate::agent::config::AgentConfig::load();
        let pinned_keys = &agent_config.gateway.pinned_keys;

        if pinned_keys.is_empty() {
            // No pins configured — accept all
            return 1;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        if pinned_keys.contains(&key) {
            1 // Match found
        } else {
            0 // No match
        }
    }));

    result.unwrap_or_else(|_| {
        set_last_error("panic in ztlp_verify_gateway_pin");
        ZtlpResult::InternalError as i32
    })
}

// ── Sync Crypto Context & FFI (Phase 1: Strip Tokio) ───────────────────

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crate::pipeline::compute_header_auth_tag;
use crate::session::ReplayWindow;

/// Holds extracted session keys for sync encrypt/decrypt without tokio.
/// Created after handshake completes (or post-connect). No tokio dependency.
pub struct ZtlpCryptoContext {
    /// Key for encrypting outbound packets.
    pub send_key: [u8; 32],
    /// Key for decrypting inbound packets.
    pub recv_key: [u8; 32],
    /// Monotonic outbound sequence counter (shared with ACK sender).
    pub send_seq: Arc<AtomicU64>,
    /// Anti-replay window for inbound packets.
    pub recv_window: ReplayWindow,
    pub session_id: SessionId,
    pub peer_addr: SocketAddr,
    // Cached CStrings for FFI accessors
    session_id_str: CString,
    peer_addr_str: CString,
}

// ── Sync crypto context lifecycle ──────────────────────────────────────────

/// Extract a crypto context from a connected client (call after ztlp_connect succeeds).
/// Returns NULL if no active session exists.
///
/// Ownership: caller must free with ztlp_crypto_context_free().
#[no_mangle]
pub extern "C" fn ztlp_crypto_context_extract(
    client: *mut ZtlpClient,
) -> *mut ZtlpCryptoContext {
    if client.is_null() {
        set_last_error("client is null");
        return std::ptr::null_mut();
    }
    let client_ref = unsafe { &*client };
    let guard = match client_ref.inner.lock() {
        Ok(g) => g,
        Err(_) => {
            set_last_error("client lock poisoned");
            return std::ptr::null_mut();
        }
    };

    let active_session = match &guard.active_session {
        Some(s) => s,
        None => {
            set_last_error("no active session");
            return std::ptr::null_mut();
        }
    };

    // Read keys from the pipeline under a block_on (pipeline is tokio::sync::Mutex).
    let transport = Arc::clone(&active_session.transport);
    let session_id = active_session.session_id;
    let session_keys = guard.runtime.block_on(async {
        let pipeline = transport.pipeline.lock().await;
        pipeline.get_session(&session_id).map(|s| (s.send_key, s.recv_key))
    });

    let (send_key, recv_key) = match session_keys {
        Some((sk, rk)) => (sk, rk),
        None => {
            set_last_error("no session keys in pipeline");
            return std::ptr::null_mut();
        }
    };

    let session_id = active_session.session_id;
    let peer_addr = active_session.peer_addr;
    let send_seq = Arc::clone(&active_session.data_seq);
    let replay_window = ReplayWindow::new(crate::session::DEFAULT_REPLAY_WINDOW);

    let session_id_str = CString::new(session_id.to_string()).unwrap_or_default();
    let peer_addr_str = CString::new(peer_addr.to_string()).unwrap_or_default();

    let ctx = ZtlpCryptoContext {
        send_key,
        recv_key,
        send_seq,
        recv_window: replay_window,
        session_id,
        peer_addr,
        session_id_str,
        peer_addr_str,
    };
    Box::into_raw(Box::new(ctx))
}

#[no_mangle]
pub extern "C" fn ztlp_crypto_context_free(ctx: *mut ZtlpCryptoContext) {
    if !ctx.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx);
        }
    }
}

#[no_mangle]
pub extern "C" fn ztlp_crypto_context_session_id(
    ctx: *const ZtlpCryptoContext,
) -> *const c_char {
    if ctx.is_null() {
        return std::ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.session_id_str.as_ptr()
}

#[no_mangle]
pub extern "C" fn ztlp_crypto_context_peer_addr(
    ctx: *const ZtlpCryptoContext,
) -> *const c_char {
    if ctx.is_null() {
        return std::ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.peer_addr_str.as_ptr()
}

// ── Sync encrypt/decrypt FFI ──────────────────────────────────────────────

/// Encrypt plaintext into a full ZTLP wire packet.
///
/// Args:
///   ctx           — crypto context (from ztlp_crypto_context_extract)
///   plaintext     — raw payload to encrypt (e.g., framed data)
///   plaintext_len — length of plaintext
///   out_buf       — output buffer (caller-allocated, must be large enough)
///   out_buf_len   — size of out_buf
///   out_written   — receives the number of bytes written
///
/// Returns 0 on success, negative error code on failure.
#[no_mangle]
pub extern "C" fn ztlp_encrypt_packet(
    ctx: *mut ZtlpCryptoContext,
    plaintext: *const u8,
    plaintext_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    if ctx.is_null() || plaintext.is_null() || out_buf.is_null() || out_written.is_null() {
        set_last_error("null argument");
        return ZtlpResult::InvalidArgument as i32;
    }
    let ctx = unsafe { &mut *ctx };
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let out_buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };

    // Allocate seq from atomic counter (same counter shared with ACK sender)
    let seq = ctx.send_seq.fetch_add(1, Ordering::Relaxed);

    // Encrypt
    let cipher = ChaCha20Poly1305::new((&ctx.send_key).into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = match cipher.encrypt(nonce, plaintext) {
        Ok(ct) => ct,
        Err(e) => {
            set_last_error(&format!("encryption failed: {}", e));
            return ZtlpResult::EncryptionError as i32;
        }
    };

    // Build data header with auth tag
    let mut header = crate::packet::DataHeader::new(ctx.session_id, seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&ctx.send_key, &aad);

    // Serialize
    let packet = crate::packet::ZtlpPacket::Data {
        header,
        payload: encrypted,
    };
    let serialized = packet.serialize();

    if serialized.len() > out_buf_len {
        set_last_error(&format!(
            "output buffer too small: need {} got {}",
            serialized.len(),
            out_buf_len
        ));
        return ZtlpResult::InvalidArgument as i32;
    }

    out_buf[..serialized.len()].copy_from_slice(&serialized);
    unsafe { *out_written = serialized.len() };
    0
}

/// Decrypt a raw ZTLP wire packet into plaintext.
///
/// Args:
///   ctx        — crypto context
///   packet     — raw UDP payload (complete ZTLP packet)
///   packet_len — length of packet
///   out_buf    — output buffer for decrypted payload
///   out_buf_len — size of out_buf
///   out_written — receives number of bytes written
///
/// Returns 0 on success, negative error code on failure.
/// On success, out_payload_data and out_payload_len are set to point
/// into out_buf.
#[no_mangle]
pub extern "C" fn ztlp_decrypt_packet(
    ctx: *mut ZtlpCryptoContext,
    packet: *const u8,
    packet_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    if ctx.is_null() || packet.is_null() || out_buf.is_null() || out_written.is_null() {
        set_last_error("null argument");
        return ZtlpResult::InvalidArgument as i32;
    }
    let ctx = unsafe { &mut *ctx };
    let packet = unsafe { std::slice::from_raw_parts(packet, packet_len) };
    let out_buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };

    // Parse the packet header
    let header = match crate::packet::DataHeader::deserialize(packet) {
        Ok(h) => h,
        Err(e) => {
            set_last_error(&format!("header parse failed: {}", e));
            return ZtlpResult::InternalError as i32;
        }
    };

    // Anti-replay check
    if !ctx.recv_window.check_and_record(header.packet_seq) {
        set_last_error("replay detected");
        return ZtlpResult::InternalError as i32;
    }

    // Extract encrypted payload (after the data header)
    let payload_start = crate::packet::DATA_HEADER_SIZE;
    if packet.len() < payload_start {
        set_last_error("packet too short for header");
        return ZtlpResult::InternalError as i32;
    }
    let encrypted = &packet[payload_start..];

    // Decrypt
    let cipher = ChaCha20Poly1305::new((&ctx.recv_key).into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = match cipher.decrypt(nonce, encrypted) {
        Ok(pt) => pt,
        Err(e) => {
            set_last_error(&format!("decryption failed: {}", e));
            return ZtlpResult::EncryptionError as i32;
        }
    };

    if plaintext.len() > out_buf_len {
        set_last_error(&format!(
            "output buffer too small: need {} got {}",
            plaintext.len(),
            out_buf_len
        ));
        return ZtlpResult::InvalidArgument as i32;
    }

    out_buf[..plaintext.len()].copy_from_slice(&plaintext);
    unsafe { *out_written = plaintext.len() };
    0
}

// Frame type constants (matching recv_loop in ffi.rs)
const FRAME_DATA: u8 = 0x00;
#[allow(dead_code)]
const FRAME_ACK: u8 = 0x01;
#[allow(dead_code)]
const FRAME_FIN: u8 = 0x02;
#[allow(dead_code)]
const FRAME_NACK: u8 = 0x03;
#[allow(dead_code)]
const FRAME_CLOSE: u8 = 0x05;

/// Build a FRAME_DATA envelope: [0x00 | data_seq(8 bytes BE) | payload].
///
/// This wraps raw data for sending through the tunnel.
/// Bumps and uses the context's internal data_seq counter.
///
/// Returns 0 on success, error code on failure.
#[no_mangle]
pub extern "C" fn ztlp_frame_data(
    payload: *const u8,
    payload_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
    data_seq_in: u64,
) -> i32 {
    // This function takes an explicit data_seq so the caller controls it
    // (since it may be tracked separately from the transport pkt_seq).
    if payload.is_null() || out_buf.is_null() || out_written.is_null() {
        set_last_error("null argument");
        return ZtlpResult::InvalidArgument as i32;
    }
    let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let out_buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };

    // Frame: [FRAME_DATA(1) | data_seq(8 BE) | payload]
    let frame_len = 1 + 8 + payload_len;
    if frame_len > out_buf_len {
        set_last_error(&format!(
            "output buffer too small: need {} got {}",
            frame_len, out_buf_len
        ));
        return ZtlpResult::InvalidArgument as i32;
    }

    out_buf[0] = FRAME_DATA;
    out_buf[1..9].copy_from_slice(&data_seq_in.to_be_bytes());
    out_buf[9..9 + payload_len].copy_from_slice(payload);

    unsafe { *out_written = frame_len };
    0
}

/// Parse a decrypted frame — returns frame type and payload.
///
/// Args:
///   decrypted      — decrypted packet payload
///   decrypted_len  — length of decrypted data
///   out_frame_type — receives the frame type byte (0x00=data, 0x01=ack, etc.)
///   out_seq        — receives the data sequence number (8 bytes BE after frame type)
///   out_payload    — receives pointer to payload start (within decrypted buffer)
///   out_payload_len — receives payload length
///
/// Returns 0 on success, negative error code on failure.
#[no_mangle]
pub extern "C" fn ztlp_parse_frame(
    decrypted: *const u8,
    decrypted_len: usize,
    out_frame_type: *mut u8,
    out_seq: *mut u64,
    out_payload: *mut *const u8,
    out_payload_len: *mut usize,
) -> i32 {
    if decrypted.is_null()
        || out_frame_type.is_null()
        || out_seq.is_null()
        || out_payload.is_null()
        || out_payload_len.is_null()
    {
        set_last_error("null argument");
        return ZtlpResult::InvalidArgument as i32;
    }
    let decrypted = unsafe { std::slice::from_raw_parts(decrypted, decrypted_len) };

    if decrypted.is_empty() {
        set_last_error("empty frame");
        return ZtlpResult::InternalError as i32;
    }

    let frame_type = decrypted[0];
    unsafe { *out_frame_type = frame_type };

    if decrypted_len < 9 {
        // Frame is shorter than type + 8-byte seq — treat as special (keepalive etc.)
        unsafe {
            *out_seq = 0;
            *out_payload = decrypted.as_ptr();
            *out_payload_len = decrypted_len;
        }
        return 0;
    }

    let seq = u64::from_be_bytes(decrypted[1..9].try_into().unwrap_or([0u8; 8]));
    unsafe { *out_seq = seq };

    let payload_offset = 9;
    let payload_len = decrypted_len - payload_offset;
    unsafe {
        *out_payload = decrypted[payload_offset..].as_ptr();
        *out_payload_len = payload_len;
    }
    0
}

// ── Sync connect (Phase 2: Sync Handshake) ──────────────────────────────
//
// Blocking connect using std::net::UdpSocket — no tokio runtime needed.
// The Noise_XX state machine (snow) is already fully sync.

use std::net::UdpSocket;

/// Blocking synchronous connect using std::net::UdpSocket.
///
/// Performs the full Noise_XX 3-message handshake over plain UDP,
/// extracts session keys, and returns a ZtlpCryptoContext ready for
/// sync encrypt/decrypt. Does NOT create a tokio runtime or spawn any
/// background threads. The caller (Swift) handles recv via NWConnection.
///
/// Args:
///   identity    — ZTLP identity (software or hardware).
///   config      — Connection config (relay, timeout, service_name).
///   target      — Gateway/peer address as "host:port".
///   timeout_ms  — Overall handshake timeout in milliseconds.
///
/// Returns a ZtlpCryptoContext* on success (caller must free),
/// or NULL on failure (check ztlp_last_error()).
#[no_mangle]
pub extern "C" fn ztlp_connect_sync(
    identity: *mut ZtlpIdentity,
    config: *mut ZtlpConfig,
    target: *const c_char,
    timeout_ms: u32,
) -> *mut ZtlpCryptoContext {
    if identity.is_null() || target.is_null() {
        set_last_error("identity or target is null");
        return std::ptr::null_mut();
    }

    let identity = unsafe { &*identity };
    let target_str = unsafe { CStr::from_ptr(target) };
    let target_str = match target_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in target: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Extract config options
    let timeout_ms = if timeout_ms == 0 {
        15000 // default
    } else {
        timeout_ms as u64
    };
    let service_name: Option<&str> = if let Some(cfg) = unsafe { config.as_ref() } {
        cfg.service_name.as_deref()
    } else {
        None
    };
    let relay_address: Option<&str> = if let Some(cfg) = unsafe { config.as_ref() } {
        cfg.relay_address.as_deref()
    } else {
        None
    };

    let node_identity = match identity.provider.as_node_identity() {
        Some(id) => id,
        None => {
            set_last_error("identity provider has no node identity");
            return std::ptr::null_mut();
        }
    };

    match do_connect_sync(node_identity, target_str, service_name, timeout_ms, relay_address) {
        Ok(ctx) => Box::into_raw(Box::new(ctx)),
        Err(e) => {
            set_last_error(&e);
            std::ptr::null_mut()
        }
    }
}

/// Sync version of do_connect — performs the full Noise_XX handshake
/// using std::net::UdpSocket.
fn do_connect_sync(
    identity: &NodeIdentity,
    target: &str,
    service_name: Option<&str>,
    timeout_ms: u64,
    relay_address: Option<&str>,
) -> Result<ZtlpCryptoContext, String> {
    // Parse target address
    let target_addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("invalid target address '{}': {}", target, e))?;

    let send_addr: SocketAddr = if let Some(relay) = relay_address {
        relay
            .parse()
            .map_err(|e| format!("invalid relay address '{}': {}", relay, e))?
    } else {
        target_addr
    };

    // Bind a standard UDP socket (non-blocking for timeout control)
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("failed to bind UDP socket: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("local_addr: {}", e))?;
    diag_log!(
        "[ZTLP] sync: bound to {} for handshake to {}",
        local_addr,
        send_addr
    );

    // Create Noise_XX initiator
    let mut ctx = HandshakeContext::new_initiator(identity)
        .map_err(|e| format!("handshake init: {}", e))?;
    let session_id = SessionId::generate();

    // ── Message 1: HELLO ──
    let msg1 = ctx
        .write_message(&[])
        .map_err(|e| format!("handshake msg1: {}", e))?;

    let mut hello_hdr = crate::packet::HandshakeHeader::new(crate::packet::MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;

    if let Some(svc) = service_name {
        hello_hdr.dst_svc_id =
            encode_service_name(svc).map_err(|e| format!("bad service name: {}", e))?;
    }

    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);

    // Send using sync socket
    socket
        .send_to(&pkt1, send_addr)
        .map_err(|e| format!("send HELLO: {}", e))?;
    diag_log!("[ZTLP] sync: sent HELLO to {}", send_addr);

    // ── Message 2: HELLO_ACK (with retransmit) ──
    let mut retry_delay = Duration::from_millis(INITIAL_HANDSHAKE_RETRY_MS);
    let max_retry_delay = Duration::from_millis(MAX_HANDSHAKE_RETRY_MS);
    let overall_timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();
    let mut retries: u8 = 0;

    let (recv2, recv2_header) = loop {
        if start.elapsed() > overall_timeout {
            return Err("handshake timed out waiting for HELLO_ACK".to_string());
        }

        // Try to receive (socket has 100ms read timeout)
        let mut buf = [0u8; 8192];
        match socket.recv_from(&mut buf) {
            Ok((len, _addr)) => {
                let data = &buf[..len];
                if data.len() >= crate::packet::HANDSHAKE_HEADER_SIZE {
                    if let Ok(hdr) = crate::packet::HandshakeHeader::deserialize(data) {
                        if hdr.msg_type == crate::packet::MsgType::HelloAck
                            && hdr.session_id == session_id
                        {
                            break (data.to_vec(), hdr);
                        }
                    }
                }
                // Not our HELLO_ACK — keep waiting
                continue;
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    // Timeout — retransmit HELLO
                    retries += 1;
                    if retries > MAX_HANDSHAKE_RETRIES {
                        return Err(
                            "handshake failed: no HELLO_ACK after retransmits".to_string()
                        );
                    }
                    socket
                        .send_to(&pkt1, send_addr)
                        .map_err(|e| format!("retransmit HELLO: {}", e))?;
                    diag_log!("[ZTLP] sync: HELLO retransmit #{}", retries);
                    std::thread::sleep(retry_delay);
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                } else {
                    return Err(format!("recv error: {}", e));
                }
            }
        }
    };

    // Process HELLO_ACK noise payload
    let noise_payload2 = &recv2[crate::packet::HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)
        .map_err(|e| format!("handshake msg2: {}", e))?;

    // ── Message 3: final confirmation ──
    let msg3 = ctx
        .write_message(&[])
        .map_err(|e| format!("handshake msg3: {}", e))?;

    let mut final_hdr =
        crate::packet::HandshakeHeader::new(crate::packet::MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;

    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);

    socket
        .send_to(&pkt3, send_addr)
        .map_err(|e| format!("send msg3: {}", e))?;
    diag_log!("[ZTLP] sync: sent msg3 (final confirmation)");

    if !ctx.is_finished() {
        return Err("handshake did not complete after 3 messages".to_string());
    }

    let peer_node_id =
        crate::identity::NodeId::from_bytes(recv2_header.src_node_id);
    let (_transport_state, session_state) = ctx
        .finalize(peer_node_id, session_id)
        .map_err(|e| format!("handshake finalize: {}", e))?;

    // Check for REJECT frame (server sends after handshake if policy denies)
    // Non-blocking check with a short deadline
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() > deadline {
            break;
        }
        socket.set_read_timeout(Some(Duration::from_millis(50))).ok();
        let mut buf = [0u8; 8192];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                if crate::reject::RejectFrame::is_reject(&buf[..len]) {
                    if let Some(reject) =
                        crate::reject::RejectFrame::decode(&buf[..len])
                    {
                        return Err(format!(
                            "access denied: {} ({})",
                            reject.message, reject.reason
                        ));
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::TimedOut
                {
                    // Real socket error — proceed anyway
                    break;
                }
                // Timeout, keep waiting
            }
        }
    }

    diag_log!(
        "[ZTLP] sync: handshake complete session={} peer={} addr={}",
        session_id,
        peer_node_id,
        send_addr
    );

    // Build the crypto context
    let send_seq = Arc::new(AtomicU64::new(0));
    let recv_window = crate::session::ReplayWindow::new(
        crate::session::DEFAULT_REPLAY_WINDOW,
    );
    let session_id_str = CString::new(session_id.to_string()).unwrap_or_default();
    let peer_addr_str = CString::new(send_addr.to_string()).unwrap_or_default();

    Ok(ZtlpCryptoContext {
        send_key: session_state.send_key,
        recv_key: session_state.recv_key,
        send_seq,
        recv_window,
        session_id,
        peer_addr: send_addr,
        session_id_str,
        peer_addr_str,
    })
}

/// Build an ACK frame: [FRAME_ACK(0x01) | ack_seq(8 bytes BE)].
///
/// Returns 0 on success, error code on failure.
/// Written bytes: 9 total.
#[no_mangle]
pub extern "C" fn ztlp_build_ack(
    ack_seq: u64,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    if out_buf.is_null() || out_written.is_null() {
        set_last_error("null argument");
        return ZtlpResult::InvalidArgument as i32;
    }
    if out_buf_len < 9 {
        set_last_error(&format!("output buffer too small: need 9 got {}", out_buf_len));
        return ZtlpResult::InvalidArgument as i32;
    }

    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };
    buf[0] = FRAME_ACK;
    buf[1..9].copy_from_slice(&ack_seq.to_be_bytes());
    unsafe { *out_written = 9 };
    0
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

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
            ZtlpResult::Rejected as i32,
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
        assert!((ZtlpResult::Rejected as i32) < 0);
    }

    #[test]
    fn test_version_returns_valid_string() {
        let ptr = ztlp_version();
        assert!(!ptr.is_null());
        let version = unsafe { CStr::from_ptr(ptr) };
        let version_str = version.to_str().expect("version should be valid UTF-8");
        assert_eq!(version_str, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_last_error_initially_null() {
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
        let err = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(err.to_str().unwrap(), "test error message");
    }

    #[test]
    fn test_last_error_overwritten() {
        set_last_error("first error");
        set_last_error("second error");
        let ptr = ztlp_last_error();
        let err = unsafe { CStr::from_ptr(ptr) };
        assert_eq!(err.to_str().unwrap(), "second error");
    }

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

    #[test]
    fn test_identity_generate_and_free() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());
        ztlp_identity_free(identity);
    }

    #[test]
    fn test_identity_free_null_is_noop() {
        ztlp_identity_free(std::ptr::null_mut());
    }

    #[test]
    fn test_identity_generate_node_id() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());
        let node_id_ptr = ztlp_identity_node_id(identity);
        assert!(!node_id_ptr.is_null());
        let node_id = unsafe { CStr::from_ptr(node_id_ptr) };
        let node_id_str = node_id.to_str().unwrap();
        assert_eq!(node_id_str.len(), 32);
        assert!(node_id_str.chars().all(|c| c.is_ascii_hexdigit()));
        ztlp_identity_free(identity);
    }

    #[test]
    fn test_identity_generate_public_key() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());
        let pubkey_ptr = ztlp_identity_public_key(identity);
        assert!(!pubkey_ptr.is_null());
        let pubkey = unsafe { CStr::from_ptr(pubkey_ptr) };
        let pubkey_str = pubkey.to_str().unwrap();
        assert_eq!(pubkey_str.len(), 64);
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
        let node_id_ptr = ztlp_identity_node_id(identity);
        let original_node_id = unsafe { CStr::from_ptr(node_id_ptr) }
            .to_str()
            .unwrap()
            .to_string();

        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join("ztlp_ffi_test_identity.json");
        let path_str = tmp_path.to_str().unwrap();
        let path_cstr = CString::new(path_str).unwrap();

        let result = ztlp_identity_save(identity, path_cstr.as_ptr());
        assert_eq!(result, 0, "save should succeed");
        ztlp_identity_free(identity);

        let loaded = ztlp_identity_from_file(path_cstr.as_ptr());
        assert!(!loaded.is_null(), "load should succeed");
        let loaded_node_id_ptr = ztlp_identity_node_id(loaded);
        let loaded_node_id = unsafe { CStr::from_ptr(loaded_node_id_ptr) }
            .to_str()
            .unwrap();
        assert_eq!(loaded_node_id, original_node_id);
        ztlp_identity_free(loaded);
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
        let err = ztlp_last_error();
        assert!(!err.is_null());
    }

    #[test]
    fn test_identity_from_hardware() {
        let ptr = ztlp_identity_from_hardware(1);
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
        let ptr = ztlp_identity_from_hardware(1);
        assert!(!ptr.is_null());
        let path = CString::new("/tmp/ztlp_hw_test.json").unwrap();
        let result = ztlp_identity_save(ptr, path.as_ptr());
        assert_eq!(result, ZtlpResult::IdentityError as i32);
        ztlp_identity_free(ptr);
    }

    #[test]
    fn test_client_new_and_free() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());
        let client = ztlp_client_new(identity);
        assert!(!client.is_null());
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

    #[test]
    fn test_config_set_service() {
        let config = ztlp_config_new();
        let svc = CString::new("beta").unwrap();
        let result = ztlp_config_set_service(config, svc.as_ptr());
        assert_eq!(result, 0);
        ztlp_config_free(config);
    }

    #[test]
    fn test_config_set_service_too_long() {
        let config = ztlp_config_new();
        let svc = CString::new("this_is_way_too_long_for_service").unwrap();
        let result = ztlp_config_set_service(config, svc.as_ptr());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_config_free(config);
    }

    #[test]
    fn test_config_set_service_null() {
        let result = ztlp_config_set_service(std::ptr::null_mut(), std::ptr::null());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

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
        assert_eq!(result, ZtlpResult::Ok as i32);
        ztlp_client_free(client);
    }

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
        let sid_str = unsafe { CStr::from_ptr(sid) }.to_str().unwrap();
        assert_eq!(sid_str.len(), 24);

        let peer_id = ztlp_session_peer_node_id(session_ptr);
        assert!(!peer_id.is_null());

        let peer_addr = ztlp_session_peer_addr(session_ptr);
        assert!(!peer_addr.is_null());
        let addr_str = unsafe { CStr::from_ptr(peer_addr) }.to_str().unwrap();
        assert_eq!(addr_str, "127.0.0.1:4433");
    }

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

    #[test]
    fn test_string_free_null_is_noop() {
        ztlp_string_free(std::ptr::null_mut());
    }

    #[test]
    fn test_string_free_valid() {
        let s = CString::new("test string").unwrap();
        let ptr = s.into_raw();
        ztlp_string_free(ptr);
    }

    #[test]
    fn test_disconnect_not_connected() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_disconnect(client);
        assert_eq!(result, 0); // Disconnect when not connected is a no-op
        ztlp_client_free(client);
    }

    #[test]
    fn test_disconnect_null_client() {
        let result = ztlp_disconnect(std::ptr::null_mut());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_bytes_sent_no_session() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        assert_eq!(ztlp_bytes_sent(client), 0);
        ztlp_client_free(client);
    }

    #[test]
    fn test_bytes_received_no_session() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        assert_eq!(ztlp_bytes_received(client), 0);
        ztlp_client_free(client);
    }

    #[test]
    fn test_bytes_sent_null() {
        assert_eq!(ztlp_bytes_sent(std::ptr::null()), 0);
    }

    #[test]
    fn test_bytes_received_null() {
        assert_eq!(ztlp_bytes_received(std::ptr::null()), 0);
    }

    extern "C" fn dummy_connect_callback(
        _user_data: *mut c_void,
        _result: i32,
        _addr: *const c_char,
    ) {
    }

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
        let result =
            ztlp_set_disconnect_callback(client, dummy_disconnect_callback, std::ptr::null_mut());
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

    // ── VIP Proxy tests ────────────────────────────────────────────────

    #[test]
    fn test_vip_add_service_null_client() {
        let name = CString::new("beta").unwrap();
        let vip = CString::new("127.0.55.1").unwrap();
        let result = ztlp_vip_add_service(std::ptr::null_mut(), name.as_ptr(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_vip_add_service_null_name() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let vip = CString::new("127.0.55.1").unwrap();
        let result = ztlp_vip_add_service(client, std::ptr::null(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_add_service_null_vip() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("beta").unwrap();
        let result = ztlp_vip_add_service(client, name.as_ptr(), std::ptr::null(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_add_service_invalid_ip() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("beta").unwrap();
        let vip = CString::new("not_an_ip").unwrap();
        let result = ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_add_service_success() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("beta").unwrap();
        let vip = CString::new("127.0.55.1").unwrap();
        let result = ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::Ok as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_add_service_multiple() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("beta").unwrap();
        let vip = CString::new("127.0.55.1").unwrap();
        assert_eq!(
            ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80),
            ZtlpResult::Ok as i32
        );
        assert_eq!(
            ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 443),
            ZtlpResult::Ok as i32
        );

        let name2 = CString::new("backstage").unwrap();
        let vip2 = CString::new("127.0.55.2").unwrap();
        assert_eq!(
            ztlp_vip_add_service(client, name2.as_ptr(), vip2.as_ptr(), 80),
            ZtlpResult::Ok as i32
        );
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_start_null_client() {
        let result = ztlp_vip_start(std::ptr::null_mut());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_vip_start_not_connected() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("beta").unwrap();
        let vip = CString::new("127.0.55.1").unwrap();
        ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80);
        let result = ztlp_vip_start(client);
        assert_eq!(result, ZtlpResult::NotConnected as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_start_no_services() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        // Don't add any services — should fail
        let result = ztlp_vip_start(client);
        // Not connected, so we'll get NotConnected before checking services
        assert_eq!(result, ZtlpResult::NotConnected as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_vip_stop_null_client() {
        let result = ztlp_vip_stop(std::ptr::null_mut());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_vip_stop_no_proxy() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_vip_stop(client);
        assert_eq!(result, ZtlpResult::Ok as i32); // No-op is fine
        ztlp_client_free(client);
    }

    // ── DNS Resolver tests ─────────────────────────────────────────────

    #[test]
    fn test_dns_start_null_client() {
        let addr = CString::new("127.0.55.53:15353").unwrap();
        let result = ztlp_dns_start(std::ptr::null_mut(), addr.as_ptr());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_dns_start_null_addr() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_dns_start(client, std::ptr::null());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_dns_start_invalid_addr() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let addr = CString::new("not_a_valid_addr").unwrap();
        let result = ztlp_dns_start(client, addr.as_ptr());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_dns_start_and_stop() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);

        // Use a high port to avoid permission issues in tests
        let addr = CString::new("127.0.0.1:15353").unwrap();
        let result = ztlp_dns_start(client, addr.as_ptr());
        assert_eq!(result, ZtlpResult::Ok as i32);

        let result = ztlp_dns_stop(client);
        assert_eq!(result, ZtlpResult::Ok as i32);
        ztlp_client_free(client);
    }

    #[test]
    fn test_dns_stop_null_client() {
        let result = ztlp_dns_stop(std::ptr::null_mut());
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
    }

    #[test]
    fn test_dns_stop_no_server() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let result = ztlp_dns_stop(client);
        assert_eq!(result, ZtlpResult::Ok as i32); // No-op is fine
        ztlp_client_free(client);
    }

    #[test]
    fn test_dns_start_twice_replaces() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);

        let addr1 = CString::new("127.0.0.1:15354").unwrap();
        let result = ztlp_dns_start(client, addr1.as_ptr());
        assert_eq!(result, ZtlpResult::Ok as i32);

        // Start again on different port — should stop first and start new
        let addr2 = CString::new("127.0.0.1:15355").unwrap();
        let result = ztlp_dns_start(client, addr2.as_ptr());
        assert_eq!(result, ZtlpResult::Ok as i32);

        ztlp_dns_stop(client);
        ztlp_client_free(client);
    }

    #[test]
    fn test_dns_resolves_registered_service() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);

        // Register a service
        let name = CString::new("beta").unwrap();
        let vip = CString::new("127.0.55.1").unwrap();
        assert_eq!(
            ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80),
            ZtlpResult::Ok as i32
        );

        // Start DNS on a high port
        let addr = CString::new("127.0.0.1:15356").unwrap();
        assert_eq!(ztlp_dns_start(client, addr.as_ptr()), ZtlpResult::Ok as i32);

        // Give the DNS server a moment to start
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Send a DNS query and check the response
        let query = build_dns_test_query(0xABCD, "beta.techrockstars.ztlp");
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        sock.send_to(&query, "127.0.0.1:15356").expect("send query");

        let mut resp_buf = [0u8; 512];
        let (resp_len, _) = sock.recv_from(&mut resp_buf).expect("recv response");
        let response = &resp_buf[..resp_len];

        // Check: QR flag set, ANCOUNT = 1
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_ne!(flags & 0x8000, 0, "QR flag should be set");
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1, "should have 1 answer");

        // Extract the IP from the answer (last 4 bytes of response)
        let ip_bytes = &response[resp_len - 4..resp_len];
        assert_eq!(ip_bytes, &[127, 0, 55, 1], "should resolve to 127.0.55.1");

        ztlp_dns_stop(client);
        ztlp_client_free(client);
    }

    #[test]
    fn test_dns_nxdomain_for_unknown() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);

        let addr = CString::new("127.0.0.1:15357").unwrap();
        assert_eq!(ztlp_dns_start(client, addr.as_ptr()), ZtlpResult::Ok as i32);

        std::thread::sleep(std::time::Duration::from_millis(50));

        let query = build_dns_test_query(0x1234, "unknown.ztlp");
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        sock.send_to(&query, "127.0.0.1:15357").expect("send");

        let mut resp_buf = [0u8; 512];
        let (resp_len, _) = sock.recv_from(&mut resp_buf).expect("recv");
        let response = &resp_buf[..resp_len];

        // Check NXDOMAIN
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, 3, "should be NXDOMAIN");

        ztlp_dns_stop(client);
        ztlp_client_free(client);
    }

    /// Build a minimal DNS query for testing.
    fn build_dns_test_query(id: u16, name: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // Standard query
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question: encode name
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label

        // Type A, Class IN
        packet.extend_from_slice(&1u16.to_be_bytes()); // TYPE_A
        packet.extend_from_slice(&1u16.to_be_bytes()); // CLASS_IN

        packet
    }

    #[test]
    fn test_ns_resolve_null_args() {
        let server = CString::new("127.0.0.1:23096").unwrap();
        let result = ztlp_ns_resolve(std::ptr::null(), server.as_ptr(), 0);
        assert!(result.is_null());

        let name = CString::new("beta.test.ztlp").unwrap();
        let result = ztlp_ns_resolve(name.as_ptr(), std::ptr::null(), 0);
        assert!(result.is_null());
    }

    #[test]
    fn test_ns_resolve_timeout_on_bad_server() {
        let name = CString::new("beta.test.ztlp").unwrap();
        // Use a non-routable address that will timeout
        let server = CString::new("192.0.2.1:23096").unwrap();
        let result = ztlp_ns_resolve(name.as_ptr(), server.as_ptr(), 500);
        assert!(result.is_null());
        // Should have a timeout error
        let err = ztlp_last_error();
        assert!(!err.is_null());
    }

    // ── Security audit tests ────────────────────────────────────────────

    /// SECURITY: Verify that oversized target addresses are rejected.
    /// Without this check, a malicious FFI caller could pass an extremely
    /// long string causing unbounded allocation.
    #[test]
    fn test_connect_rejects_oversized_address() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);

        // Create an address longer than MAX_FFI_ADDRESS_LEN (256 bytes)
        let long_addr = "A".repeat(300);
        let target = CString::new(long_addr).unwrap();

        extern "C" fn noop_callback(_ud: *mut c_void, _result: i32, _addr: *const c_char) {}

        let result = ztlp_connect(
            client,
            target.as_ptr(),
            std::ptr::null(),
            noop_callback,
            std::ptr::null_mut(),
        );
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);

        // Verify the error message mentions the length
        let err = ztlp_last_error();
        assert!(!err.is_null());
        let err_str = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(
            err_str.contains("too long"),
            "error should mention address is too long, got: {}",
            err_str
        );

        ztlp_client_free(client);
    }

    /// SECURITY: Verify that valid-length addresses are NOT rejected.
    /// Ensures the length check doesn't break normal operation.
    #[test]
    fn test_connect_accepts_normal_address() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);

        // A normal IPv6 address with port — well under 256 bytes
        let target = CString::new("[::1]:12345").unwrap();

        extern "C" fn noop_callback(_ud: *mut c_void, _result: i32, _addr: *const c_char) {}

        // This will fail to connect (no server), but it should NOT fail
        // with InvalidArgument — it should attempt the connection.
        let result = ztlp_connect(
            client,
            target.as_ptr(),
            std::ptr::null(),
            noop_callback,
            std::ptr::null_mut(),
        );
        // Should be Ok (async connection attempt started) or a connection error,
        // but NOT InvalidArgument
        assert_ne!(result, ZtlpResult::InvalidArgument as i32);

        ztlp_client_free(client);
    }

    /// SECURITY: Verify that non-loopback VIP addresses are rejected.
    /// This prevents the VIP proxy from being used for SSRF/port scanning.
    #[test]
    fn test_vip_add_service_rejects_non_loopback() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("evil").unwrap();

        // Try to bind to a non-loopback address
        let vip = CString::new("10.0.0.1").unwrap();
        let result = ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);

        // Verify the error message mentions loopback
        let err = ztlp_last_error();
        assert!(!err.is_null());
        let err_str = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(
            err_str.contains("loopback"),
            "error should mention loopback requirement, got: {}",
            err_str
        );

        ztlp_client_free(client);
    }

    /// SECURITY: Verify that 0.0.0.0 is rejected as a VIP address.
    #[test]
    fn test_vip_add_service_rejects_wildcard() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("evil").unwrap();
        let vip = CString::new("0.0.0.0").unwrap();
        let result = ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);
        ztlp_client_free(client);
    }

    /// SECURITY: Verify that private network addresses are rejected as VIPs.
    #[test]
    fn test_vip_add_service_rejects_private_network() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        let name = CString::new("evil").unwrap();

        // 192.168.x.x is private but NOT loopback
        let vip = CString::new("192.168.1.1").unwrap();
        let result = ztlp_vip_add_service(client, name.as_ptr(), vip.as_ptr(), 80);
        assert_eq!(result, ZtlpResult::InvalidArgument as i32);

        ztlp_client_free(client);
    }

    /// SECURITY: Verify that process_recv_packet handles all frame types.
    #[test]
    fn test_process_recv_packet_keepalive() {
        // Keepalive frame (single byte 0x01) should result in Continue
        let keepalive = vec![0x01u8];
        let inner = Arc::new(std::sync::Mutex::new(create_test_inner()));
        let session_id = crate::packet::SessionId::generate();
        let peer_node_id = crate::identity::NodeId::from_bytes([0u8; 16]);
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let action = process_recv_packet(&keepalive, session_id, peer_node_id, peer_addr, &inner);
        assert!(matches!(action, RecvAction::Continue));
    }

    // ── Sync FFI tests (Phase 1+2: Strip Tokio) ─────────────────────────

    /// Create a test crypto context with known keys for encrypt/decrypt testing.
    fn make_test_crypto_context() -> ZtlpCryptoContext {
        let send_key = [0x42u8; 32];
        let recv_key = [0x99u8; 32];
        let send_seq = Arc::new(AtomicU64::new(0));
        let recv_window = crate::session::ReplayWindow::new(crate::session::DEFAULT_REPLAY_WINDOW);
        let session_id = SessionId::generate();
        let peer_addr: SocketAddr = "127.0.0.1:23095".parse().unwrap();
        let session_id_str = CString::new(session_id.to_string()).unwrap_or_default();
        let peer_addr_str = CString::new(peer_addr.to_string()).unwrap_or_default();

        ZtlpCryptoContext {
            send_key,
            recv_key,
            send_seq,
            recv_window,
            session_id,
            peer_addr,
            session_id_str,
            peer_addr_str,
        }
    }

    /// TEST: ztlp_frame_data builds correct envelope, ztlp_parse_frame extracts it.
    #[test]
    fn test_sync_frame_data_roundtrip() {
        let payload = b"Hello, ZTLP tunnel!";
        let data_seq: u64 = 42;

        let mut frame_buf = [0u8; 9 + 64];
        let mut written: usize = 0;
        let rc = ztlp_frame_data(
            payload.as_ptr(), payload.len(),
            frame_buf.as_mut_ptr(), frame_buf.len(),
            &mut written, data_seq,
        );
        assert_eq!(rc, 0, "frame_data should succeed");
        assert_eq!(written, 1 + 8 + payload.len(), "frame length should be 1+8+payload");

        // Verify structure: [0x00 | data_seq(8 BE) | payload]
        assert_eq!(frame_buf[0], 0x00, "first byte should be FRAME_DATA");
        let parsed_seq = u64::from_be_bytes(frame_buf[1..9].try_into().unwrap());
        assert_eq!(parsed_seq, data_seq, "data_seq should match");
        assert_eq!(&frame_buf[9..9 + payload.len()], payload, "payload should match");

        // Now parse it back
        let mut frame_type: u8 = 0;
        let mut seq: u64 = 0;
        let mut payload_ptr: *const u8 = std::ptr::null();
        let mut payload_len: usize = 0;
        let rc = ztlp_parse_frame(
            frame_buf.as_ptr(), written,
            &mut frame_type, &mut seq,
            &mut payload_ptr, &mut payload_len,
        );
        assert_eq!(rc, 0, "parse_frame should succeed");
        assert_eq!(frame_type, 0x00, "frame type should be FRAME_DATA");
        assert_eq!(seq, data_seq, "parsed seq should match");
        assert_eq!(payload_len, payload.len(), "payload length should match");

        let parsed_payload = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };
        assert_eq!(parsed_payload, payload, "parsed payload should match original");
    }

    /// TEST: ztlp_build_ack creates correct 9-byte ACK frame.
    #[test]
    fn test_sync_build_ack() {
        let mut buf = [0u8; 9];
        let mut written: usize = 0;
        let rc = ztlp_build_ack(
            12345u64,
            buf.as_mut_ptr(), buf.len(),
            &mut written,
        );
        assert_eq!(rc, 0);
        assert_eq!(written, 9);
        assert_eq!(buf[0], 0x01, "first byte should be FRAME_ACK");
        let acked_seq = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        assert_eq!(acked_seq, 12345u64);

        // Verify it parses correctly
        let mut frame_type: u8 = 0;
        let mut seq: u64 = 0;
        let mut payload_ptr: *const u8 = std::ptr::null();
        let mut payload_len: usize = 0;
        let rc = ztlp_parse_frame(
            buf.as_ptr(), 9,
            &mut frame_type, &mut seq,
            &mut payload_ptr, &mut payload_len,
        );
        assert_eq!(rc, 0);
        assert_eq!(frame_type, 0x01, "should be FRAME_ACK");
        assert_eq!(seq, 12345u64);
    }

    /// TEST: ztlp_build_ack rejects buffer too small.
    #[test]
    fn test_sync_build_ack_buffer_too_small() {
        let mut buf = [0u8; 8]; // needs 9
        let mut written: usize = 0;
        let rc = ztlp_build_ack(1, buf.as_mut_ptr(), buf.len(), &mut written);
        assert_ne!(rc, 0, "should fail with small buffer");
    }

    /// TEST: ztlp_encrypt_packet produces valid output, ztlp_decrypt_packet recovers original.
    #[test]
    fn test_sync_encrypt_decrypt_roundtrip() {
        // Create two contexts: client (for encryption) and server (for decryption)
        // In real usage: client encrypts with send_key (server's recv_key),
        // server decrypts with recv_key (client's send_key).
        let shared_key = [0xABu8; 32];

        let mut client_ctx = make_test_crypto_context();
        client_ctx.send_key = shared_key; // client encrypts with this
        let mut server_ctx = make_test_crypto_context();
        server_ctx.recv_key = shared_key; // server decrypts with this

        // Also set server's send_key and client's recv_key for the reverse direction
        let shared_key2 = [0xCDu8; 32];
        client_ctx.recv_key = shared_key2;
        server_ctx.send_key = shared_key2;

        let plaintext = b"Test payload for ZTLP sync encrypt/decrypt!";

        // Encrypt
        let mut pkt_buf = [0u8; 65536];
        let mut pkt_written: usize = 0;
        let rc_enc = ztlp_encrypt_packet(
            &mut client_ctx,
            plaintext.as_ptr(), plaintext.len(),
            pkt_buf.as_mut_ptr(), pkt_buf.len(),
            &mut pkt_written,
        );
        assert_eq!(rc_enc, 0, "encrypt should succeed");
        assert!(pkt_written > plaintext.len(), "encrypted packet should be larger than plaintext (header + auth tag)");

        // Decrypt
        let mut out_buf = [0u8; 65536];
        let mut out_written: usize = 0;
        let rc_dec = ztlp_decrypt_packet(
            &mut server_ctx,
            pkt_buf.as_ptr(), pkt_written,
            out_buf.as_mut_ptr(), out_buf.len(),
            &mut out_written,
        );
        assert_eq!(rc_dec, 0, "decrypt should succeed");
        assert_eq!(out_written, plaintext.len(), "decrypted length should match original");

        let decrypted = &out_buf[..out_written];
        assert_eq!(decrypted, plaintext, "decrypted text should match original");
    }

    /// TEST: Seq counter increments on each encrypt.
    #[test]
    fn test_sync_encrypt_increments_seq() {
        let mut ctx = make_test_crypto_context();
        let payload = [0x55u8; 10];

        let mut pkt1 = [0u8; 65536];
        let mut w1: usize = 0;
        assert_eq!(ztlp_encrypt_packet(&mut ctx, payload.as_ptr(), payload.len(), pkt1.as_mut_ptr(), pkt1.len(), &mut w1), 0);

        let mut pkt2 = [0u8; 65536];
        let mut w2: usize = 0;
        assert_eq!(ztlp_encrypt_packet(&mut ctx, payload.as_ptr(), payload.len(), pkt2.as_mut_ptr(), pkt2.len(), &mut w2), 0);

        // Both packets should have different seq numbers in the header
        // Parse the packet sequence from the data header
        let parse_header1 = crate::packet::DataHeader::deserialize(&pkt1[..w1]);
        let parse_header2 = crate::packet::DataHeader::deserialize(&pkt2[..w2]);
        assert!(parse_header1.is_ok());
        assert!(parse_header2.is_ok());
        let seq1 = parse_header1.unwrap().packet_seq;
        let seq2 = parse_header2.unwrap().packet_seq;
        assert_eq!(seq1, 0, "first encrypt should use seq 0");
        assert_eq!(seq2, 1, "second encrypt should use seq 1");
    }

    /// TEST: Decrypt rejects replayed packets (same seq twice).
    #[test]
    fn test_sync_decrypt_rejects_replay() {
        let mut client_ctx = make_test_crypto_context();
        let mut server_ctx = make_test_crypto_context();
        client_ctx.send_key = [0xFFu8; 32];
        server_ctx.recv_key = [0xFFu8; 32];

        let payload = b"Replay test message";

        let mut pkt = [0u8; 65536];
        let mut pkt_written: usize = 0;
        let rc = ztlp_encrypt_packet(
            &mut client_ctx,
            payload.as_ptr(), payload.len(),
            pkt.as_mut_ptr(), pkt.len(),
            &mut pkt_written,
        );
        assert_eq!(rc, 0);

        // First decrypt succeeds
        let mut out1 = [0u8; 65536];
        let mut w1: usize = 0;
        let rc1 = ztlp_decrypt_packet(
            &mut server_ctx,
            pkt.as_ptr(), pkt_written,
            out1.as_mut_ptr(), out1.len(),
            &mut w1,
        );
        assert_eq!(rc1, 0, "first decrypt should succeed");
        assert_eq!(&out1[..w1], payload);

        // Second decrypt with same packet should fail (replay)
        let mut out2 = [0u8; 65536];
        let mut w2: usize = 0;
        let rc2 = ztlp_decrypt_packet(
            &mut server_ctx,
            pkt.as_ptr(), pkt_written,
            out2.as_mut_ptr(), out2.len(),
            &mut w2,
        );
        assert_ne!(rc2, 0, "second decrypt should fail (replay detected)");
    }

    /// TEST: Out-of-order decrypt works within replay window.
    #[test]
    fn test_sync_decrypt_out_of_order_within_window() {
        let mut client_ctx = make_test_crypto_context();
        let key = [0xEEu8; 32];
        client_ctx.send_key = key;

        let mut server_ctx = make_test_crypto_context();
        server_ctx.recv_key = key;

        // Encrypt packets 0, 1, 2
        let mut packets: Vec<(Vec<u8>, usize)> = Vec::new();
        for i in 0..3 {
            let payload = format!("packet {}", i);
            let mut pkt = [0u8; 65536];
            let mut w: usize = 0;
            let rc = ztlp_encrypt_packet(
                &mut client_ctx,
                payload.as_ptr(), payload.len(),
                pkt.as_mut_ptr(), pkt.len(),
                &mut w,
            );
            assert_eq!(rc, 0);
            packets.push((pkt.to_vec(), w));
        }

        // Decrypt in order 2, 0, 1 (all should succeed within window of 64)
        let order = [2, 0, 1];
        for &idx in &order {
            let (pkt, pkt_len) = &packets[idx];
            let mut out = [0u8; 65536];
            let mut w: usize = 0;
            let rc = ztlp_decrypt_packet(
                &mut server_ctx,
                pkt.as_ptr(), *pkt_len,
                out.as_mut_ptr(), out.len(),
                &mut w,
            );
            assert_eq!(rc, 0, "decrypt of packet {} should succeed", idx);
            let expected = format!("packet {}", idx);
            assert_eq!(&out[..w], expected.as_bytes(), "packet {} content should match", idx);
        }
    }

    /// TEST: Null argument handling for sync functions.
    #[test]
    fn test_sync_null_args() {
        // ztlp_frame_data — null payload
        assert_ne!(ztlp_frame_data(
            std::ptr::null(), 10,
            std::ptr::null_mut(), 100,
            &mut 0, 0
        ), 0);

        // ztlp_frame_data — null out_written
        let payload = [0u8; 5];
        let mut out = [0u8; 20];
        assert_ne!(ztlp_frame_data(
            payload.as_ptr(), payload.len(),
            out.as_mut_ptr(), out.len(),
            std::ptr::null_mut(), 0
        ), 0);

        // ztlp_frame_data — valid call should succeed
        let mut w: usize = 0;
        assert_eq!(ztlp_frame_data(
            payload.as_ptr(), payload.len(),
            out.as_mut_ptr(), out.len(),
            &mut w, 42
        ), 0);
        assert_eq!(w, 1 + 8 + payload.len(), "frame should have correct length");

        // ztlp_build_ack — null out_buf
        assert_ne!(ztlp_build_ack(1, std::ptr::null_mut(), 9, &mut 0), 0);

        // ztlp_build_ack — null out_written
        let mut buf = [0u8; 9];
        assert_ne!(ztlp_build_ack(1, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut()), 0);
    }

    /// TEST: ztlp_encrypt_packet rejects output buffer too small.
    #[test]
    fn test_sync_encrypt_buffer_too_small() {
        let mut ctx = make_test_crypto_context();
        let payload = [0x11u8; 100];
        let mut tiny_buf = [0u8; 10]; // way too small for header + encrypted payload
        let mut written: usize = 0;
        let rc = ztlp_encrypt_packet(
            &mut ctx,
            payload.as_ptr(), payload.len(),
            tiny_buf.as_mut_ptr(), tiny_buf.len(),
            &mut written,
        );
        assert_ne!(rc, 0, "encrypt should fail with tiny buffer");
    }

    /// TEST: ztlp_decrypt_packet rejects malformed packet (too short).
    #[test]
    fn test_sync_decrypt_malformed_packet() {
        let mut ctx = make_test_crypto_context();
        let mut out = [0u8; 65536];
        let mut written: usize = 0;

        // 5 bytes is way too short for a 46-byte data header
        let short_pkt = [0x37u8, 0x5A, 0x01, 0x00, 0x00];
        let rc = ztlp_decrypt_packet(
            &mut ctx,
            short_pkt.as_ptr(), short_pkt.len(),
            out.as_mut_ptr(), out.len(),
            &mut written,
        );
        assert_ne!(rc, 0, "decrypt should fail with too-short packet");
    }

    /// TEST: ztlp_encrypt_packet + ztlp_decrypt_packet with full frame data envelope.
    #[test]
    fn test_sync_full_data_frame_roundtrip() {
        // Simulates the full Swift path: frame_data → encrypt → decrypt → parse_frame
        let mut client_ctx = make_test_crypto_context();
        let mut server_ctx = make_test_crypto_context();
        let key = [0xDDu8; 32];
        client_ctx.send_key = key;
        server_ctx.recv_key = key;

        // Build FRAME_DATA envelope
        let payload = b"Some IP packet data would go here";
        let data_seq: u64 = 7;
        let mut frame_buf = [0u8; 2048];
        let mut frame_len: usize = 0;
        let rc = ztlp_frame_data(
            payload.as_ptr(), payload.len(),
            frame_buf.as_mut_ptr(), frame_buf.len(),
            &mut frame_len, data_seq,
        );
        assert_eq!(rc, 0);
        assert_eq!(frame_len, 1 + 8 + payload.len());

        // Encrypt the frame
        let mut pkt_buf = [0u8; 65536];
        let mut pkt_len: usize = 0;
        let rc = ztlp_encrypt_packet(
            &mut client_ctx,
            frame_buf.as_ptr(), frame_len,
            pkt_buf.as_mut_ptr(), pkt_buf.len(),
            &mut pkt_len,
        );
        assert_eq!(rc, 0);
        assert!(pkt_len > payload.len());

        // Decrypt
        let mut out_buf = [0u8; 65536];
        let mut out_len: usize = 0;
        let rc = ztlp_decrypt_packet(
            &mut server_ctx,
            pkt_buf.as_ptr(), pkt_len,
            out_buf.as_mut_ptr(), out_buf.len(),
            &mut out_len,
        );
        assert_eq!(rc, 0);
        assert_eq!(out_len, frame_len);

        // Parse frame
        let mut frame_type: u8 = 0;
        let mut seq: u64 = 0;
        let mut payload_ptr: *const u8 = std::ptr::null();
        let mut payload_len: usize = 0;
        let rc = ztlp_parse_frame(
            out_buf.as_ptr(), out_len,
            &mut frame_type, &mut seq,
            &mut payload_ptr, &mut payload_len,
        );
        assert_eq!(rc, 0);
        assert_eq!(frame_type, 0x00, "should be FRAME_DATA");
        assert_eq!(seq, data_seq, "seq should match");
        assert_eq!(payload_len, payload.len());

        let parsed = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };
        assert_eq!(parsed, payload, "final payload should match original");
    }

    /// TEST: ztlp_connect_sync fails gracefully with invalid target.
    #[test]
    fn test_sync_connect_invalid_target() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());

        let config = ztlp_config_new();
        let target = CString::new("not-an-address").unwrap();
        let ctx = ztlp_connect_sync(
            identity,
            config,
            target.as_ptr(),
            500, // 500ms timeout
        );

        // Should return NULL (not a valid address format)
        assert!(ctx.is_null(), "connect with invalid target should return NULL");
        let err = ztlp_last_error();
        assert!(!err.is_null(), "should have error message");

        // Clean up
        ztlp_config_free(config);
        ztlp_identity_free(identity);
    }

    /// TEST: ztlp_connect_sync fails with timeout on unreachable target.
    #[test]
    fn test_sync_connect_timeout_unreachable() {
        let identity = ztlp_identity_generate();
        assert!(!identity.is_null());

        let config = ztlp_config_new();
        // Use a non-routable address that will timeout
        let target = CString::new("192.0.2.1:23095").unwrap();

        let start = std::time::Instant::now();
        let ctx = ztlp_connect_sync(
            identity,
            config,
            target.as_ptr(),
            500, // 500ms timeout
        );
        let elapsed = start.elapsed();

        assert!(ctx.is_null(), "connect to unreachable target should return NULL");
        assert!(
            elapsed.as_millis() < 5000,
            "should timeout quickly, took {}ms",
            elapsed.as_millis()
        );

        ztlp_config_free(config);
        ztlp_identity_free(identity);
    }

    /// TEST: ztlp_crypto_context_extract returns NULL when no active session.
    #[test]
    fn test_crypto_context_extract_no_session() {
        let identity = ztlp_identity_generate();
        let client = ztlp_client_new(identity);
        // identity ownership transferred to client — do NOT free it separately

        let ctx = ztlp_crypto_context_extract(client);
        assert!(ctx.is_null(), "extract should return NULL with no active session");

        ztlp_client_free(client);
    }

    /// TEST: ztlp_crypto_context_accessors return null for null context.
    #[test]
    fn test_crypto_context_null_accessors() {
        assert!(ztlp_crypto_context_session_id(std::ptr::null()).is_null());
        assert!(ztlp_crypto_context_peer_addr(std::ptr::null()).is_null());
    }

    /// TEST: ztlp_encrypt_packet detects null context.
    #[test]
    fn test_encrypt_null_context() {
        let payload = [0u8; 10];
        let mut out = [0u8; 65536];
        let mut w: usize = 0;
        let rc = ztlp_encrypt_packet(
            std::ptr::null_mut(),
            payload.as_ptr(), payload.len(),
            out.as_mut_ptr(), out.len(),
            &mut w,
        );
        assert_ne!(rc, 0);
    }

    /// TEST: ztlp_decrypt_packet detects null context.
    #[test]
    fn test_decrypt_null_context() {
        let pkt = [0u8; 100];
        let mut out = [0u8; 65536];
        let mut w: usize = 0;
        let rc = ztlp_decrypt_packet(
            std::ptr::null_mut(),
            pkt.as_ptr(), pkt.len(),
            out.as_mut_ptr(), out.len(),
            &mut w,
        );
        assert_ne!(rc, 0);
    }

    /// Helper to create a minimal ZtlpClientInner for testing.
    fn create_test_inner() -> ZtlpClientInner {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let identity = crate::mobile::SoftwareIdentityProvider::generate().unwrap();
        ZtlpClientInner {
            runtime,
            identity: Box::new(identity),
            state: ConnectionState::Disconnected,
            config: crate::mobile::MobileConfig::default(),
            active_session: None,
            recv_callback: None,
            disconnect_callback: None,
            ack_send_callback: None,
            vip_proxy: None,
            dns_server: None,
            vip_registry: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            packet_router: None,
        }
    }
}
