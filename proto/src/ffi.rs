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
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

// ── Opaque handle types ─────────────────────────────────────────────────

pub struct ZtlpClient {
    inner: Arc<std::sync::Mutex<ZtlpClientInner>>,
}

struct ZtlpClientInner {
    runtime: tokio::runtime::Runtime,
    identity: Box<dyn PlatformIdentity>,
    state: ConnectionState,
    config: MobileConfig,
    active_session: Option<ActiveSession>,
    recv_callback: Option<(ZtlpRecvCallback, *mut c_void)>,
    disconnect_callback: Option<(ZtlpDisconnectCallback, *mut c_void)>,
    /// VIP proxy manager (local TCP → tunnel).
    vip_proxy: Option<VipProxy>,
    /// DNS resolver for *.ztlp domains.
    dns_server: Option<ZtlpDns>,
    /// Shared VIP registry (service name → IP) used by both VIP proxy and DNS.
    vip_registry: VipRegistry,
}

unsafe impl Send for ZtlpClientInner {}

/// Active session with real transport state.
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
    // Cached C strings for accessors
    session_id_str: CString,
    peer_node_id_str: CString,
    peer_addr_str: CString,
}

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
    if identity.is_null() {
        set_last_error("identity handle is null");
        return std::ptr::null_mut();
    }
    let identity = unsafe { Box::from_raw(identity) };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
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
        vip_proxy: None,
        dns_server: None,
        vip_registry: Arc::new(TokioRwLock::new(std::collections::HashMap::new())),
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
pub extern "C" fn ztlp_config_set_stun_server(
    config: *mut ZtlpConfig,
    addr: *const c_char,
) -> i32 {
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
pub extern "C" fn ztlp_config_set_service(
    config: *mut ZtlpConfig,
    service: *const c_char,
) -> i32 {
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
    if client.is_null() || target.is_null() {
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

    // Read config
    let (service_name, timeout_ms) = if !config.is_null() {
        let cfg = unsafe { &*config };
        (cfg.service_name.clone(), cfg.timeout_ms)
    } else {
        (None, 15000)
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
                        let mut ni = sw.as_node_identity()
                            .expect("freshly generated software identity must have node_identity")
                            .clone();
                        // Override with hardware node_id
                        ni.node_id = hw_node_id;
                        ni
                    }
                    Err(e) => {
                        set_last_error(&format!("failed to generate ephemeral keys for hardware identity: {e}"));
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
) -> Result<ActiveSession, String> {
    // Parse target address
    let send_addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("invalid target address '{}': {}", target, e))?;

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
        session_id_str: CString::new(hex::encode(session_id.as_bytes())).unwrap_or_default(),
        peer_node_id_str: CString::new(hex::encode(peer_node_id.as_bytes())).unwrap_or_default(),
        peer_addr_str: CString::new(send_addr.to_string()).unwrap_or_default(),
    })
}

/// Background receive loop — decrypts incoming packets and invokes the recv callback.
async fn recv_loop(
    transport: Arc<TransportNode>,
    bytes_received: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
    session_id: SessionId,
    peer_node_id: NodeId,
    peer_addr: SocketAddr,
    inner: Arc<std::sync::Mutex<ZtlpClientInner>>,
) {
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        match tokio::time::timeout(Duration::from_secs(1), transport.recv_data()).await {
            Ok(Ok(Some((plaintext, _from)))) => {
                bytes_received.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

                // Check if it's a disconnect/reject
                if RejectFrame::is_reject(&plaintext) {
                    if let Some(reject) = RejectFrame::decode(&plaintext) {
                        set_last_error(&format!("server rejected: {}", reject.message));
                        // Invoke disconnect callback
                        if let Ok(guard) = inner.lock() {
                            if let Some((cb, ud)) = guard.disconnect_callback {
                                let mut session_handle = ZtlpSession {
                                    session_id,
                                    peer_node_id,
                                    peer_addr,
                                    session_id_str: CString::new(hex::encode(
                                        session_id.as_bytes(),
                                    ))
                                    .unwrap_or_default(),
                                    peer_node_id_str: CString::new(hex::encode(
                                        peer_node_id.as_bytes(),
                                    ))
                                    .unwrap_or_default(),
                                    peer_addr_str: CString::new(peer_addr.to_string())
                                        .unwrap_or_default(),
                                };
                                cb(
                                    ud,
                                    &mut session_handle as *mut ZtlpSession,
                                    ZtlpResult::Rejected as i32,
                                );
                            }
                        }
                        break;
                    }
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
                            peer_addr_str: CString::new(peer_addr.to_string())
                                .unwrap_or_default(),
                        };
                        cb(
                            ud,
                            plaintext.as_ptr(),
                            plaintext.len(),
                            &mut session_handle as *mut ZtlpSession,
                        );
                    }

                    // Forward to VIP proxy if running.
                    // Strip tunnel frame header: [frame_type(1) | data_seq(8) | payload]
                    if plaintext.len() > 9 && plaintext[0] == 0x00 {
                        let payload = plaintext[9..].to_vec();
                        if let Some(ref proxy) = guard.vip_proxy {
                            let tx = proxy.tunnel_sender();
                            // Non-blocking send — drop data if channel is full
                            let _ = tx.try_send(crate::vip::TunnelData { payload });
                        }
                    }
                }
            }
            Ok(Ok(None)) => {
                // Packet dropped by pipeline — continue
            }
            Ok(Err(_)) => {
                // Socket error — clean up
                break;
            }
            Err(_) => {
                // Timeout — just loop again (allows checking stop_flag)
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

    if let Some(ref session) = guard.active_session {
        session.stop_flag.store(true, Ordering::SeqCst);
    }
    guard.active_session = None;
    guard.state = ConnectionState::Disconnected;
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
    static VERSION: &[u8] = b"0.10.0\0";
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
        proxy.add_service(name_string.clone(), vip_addr, port);
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

    if guard.state != ConnectionState::Connected {
        set_last_error("not connected — connect first, then start VIP proxy");
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
    let data_seq = session.data_seq.clone();
    let bytes_sent = session.bytes_sent.clone();

    let mut proxy = match guard.vip_proxy.take() {
        Some(p) => p,
        None => {
            set_last_error("no services registered — call ztlp_vip_add_service first");
            return ZtlpResult::InvalidArgument as i32;
        }
    };

    // Start proxy listeners on the runtime
    let result = guard.runtime.block_on(async {
        proxy
            .start(transport, session_id, peer_addr, data_seq, bytes_sent)
            .await
    });

    guard.vip_proxy = Some(proxy);

    match result {
        Ok(()) => ZtlpResult::Ok as i32,
        Err(e) => {
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
pub extern "C" fn ztlp_dns_start(
    client: *mut ZtlpClient,
    listen_addr: *const c_char,
) -> i32 {
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
        assert_eq!(version_str, "0.10.0");
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
        sock.send_to(&query, "127.0.0.1:15356")
            .expect("send query");

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
}
