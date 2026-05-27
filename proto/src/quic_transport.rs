//! Experimental QUIC transport scaffold (Phase 0).
//!
//! This module is **intentionally empty of working logic**. It exists so
//! the new transport layer has a stable home in the crate while the
//! existing hand-rolled UDP stack (`mux.rs`, `send_controller.rs`,
//! `congestion.rs`, ...) keeps the tree running.
//!
//! See `docs/architecture/quic-noise-handshake.md` for the full design.
//!
//! # Why feature-gated
//!
//! `quinn`, `quinn-proto`, and `rustls` together pull in ~200k LOC of
//! transitive dependencies. We do not want default builds — especially
//! the iOS Network Extension build — paying that cost until the
//! implementation is real. Build with:
//!
//!   cargo build --features quic-transport
//!
//! to opt in. The iOS NE build will use `--features
//! ios-sync,quic-transport` once Phase 4 lands; until then `ios-sync`
//! continues to compile without this module.
//!
//! # Two backends, one feature flag
//!
//! - `quinn::Endpoint` (tokio-backed) — used on Gateway/Relay/macOS.
//!   Only compiled when both `quic-transport` AND `tokio-runtime` are on.
//! - `quinn-proto` sans-io state machine — used by iOS NE.
//!   Compiled whenever `quic-transport` is on.
//!
//! # ALPN
//!
//! Reserved: `ztlp/1`. Stored as a const so all call sites agree.

#![cfg(feature = "quic-transport")]

/// ALPN identifier advertised in QUIC `Initial` packets.
///
/// Distinct ALPN values let us run multiple QUIC-based protocols on
/// the same UDP port without collision and give middleboxes a clean
/// signal that this is ZTLP traffic, not generic HTTP/3.
pub const ZTLP_ALPN: &[u8] = b"ztlp/1";

/// Magic byte prefix on stream-0 control frames.
///
/// `0xZ1` (= `0x5A`, ASCII 'Z') marks a handshake-version-1 frame.
/// Range `0xZ2..=0xZF` is reserved for future stream-0 control
/// messages (rekey, keepalive, graceful close, etc.). Keeping this
/// const centralises the wire-format authority — never hard-code
/// the byte elsewhere.
pub const STREAM0_MAGIC_V1: u8 = b'Z';

/// Errors produced by the QUIC transport scaffold.
///
/// Every variant is a *placeholder* in Phase 0. Real error taxonomy
/// will be defined in Phase 1 once the endpoint is wired.
#[derive(Debug, thiserror::Error)]
pub enum QuicTransportError {
    /// The caller invoked a code path that has not been implemented yet.
    #[error("QUIC transport phase {phase} not yet implemented: {what}")]
    NotImplemented { phase: u8, what: &'static str },

    #[error("endpoint error: {0}")]
    Endpoint(#[from] std::io::Error),

    #[error("connect error: {0}")]
    Connect(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("read error: {0}")]
    Read(String),

    #[error("read exact error: {0}")]
    ReadExact(String),

    #[error("write error: {0}")]
    Write(String),

    #[error("bad magic: expected {expected:#04x}, got {got:#04x}")]
    BadMagic { expected: u8, got: u8 },

    #[error("frame too large: {sz}")]
    FrameTooLarge { sz: usize },

    #[error("handshake error: {0}")]
    Handshake(String),
}

impl From<quinn::ConnectError> for QuicTransportError {
    fn from(e: quinn::ConnectError) -> Self {
        QuicTransportError::Connect(e.to_string())
    }
}
impl From<quinn::ConnectionError> for QuicTransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        QuicTransportError::Connection(e.to_string())
    }
}
impl From<quinn::ReadError> for QuicTransportError {
    fn from(e: quinn::ReadError) -> Self {
        QuicTransportError::Read(e.to_string())
    }
}
impl From<quinn::ReadExactError> for QuicTransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        QuicTransportError::ReadExact(e.to_string())
    }
}
impl From<quinn::WriteError> for QuicTransportError {
    fn from(e: quinn::WriteError) -> Self {
        QuicTransportError::Write(e.to_string())
    }
}
impl From<crate::error::HandshakeError> for QuicTransportError {
    fn from(e: crate::error::HandshakeError) -> Self {
        QuicTransportError::Handshake(e.to_string())
    }
}

/// Sans-io QUIC endpoint configuration shared by both backends.
///
/// Phase 0: the struct exists so callers can be wired up against a
/// stable type. Fields will grow in Phase 1 (peer auth keys, ALPN
/// list, transport params) and Phase 4 (iOS-specific tuning).
#[derive(Debug, Clone)]
pub struct QuicEndpointConfig {
    /// Bind address for the underlying UDP socket.
    ///
    /// `None` means "let the OS choose" (used by client-mode
    /// connections that don't accept inbound). Servers must set this.
    pub bind: Option<std::net::SocketAddr>,
    /// ALPN values to advertise. Defaults to `[ZTLP_ALPN]`.
    pub alpn: Vec<Vec<u8>>,
    /// Optional override for Quinn's `max_idle_timeout`. v0.29.3 sets a
    /// 60s default on both client and server so a brief packet-loss window
    /// or a relay-side ETS GC tick doesn't immediately tear down a tunnel.
    /// Quinn's own default is 30s; the ZTLP relay's α-path adds an extra
    /// RTT + UDP loss surface, so we want headroom.
    pub max_idle_timeout_ms: Option<u32>,
    /// Optional override for Quinn's `keep_alive_interval`. v0.29.3 sets a
    /// 15s default so an idle tunnel still emits keepalive packets through
    /// the relay (which both refreshes the relay's `{:client_map, ...}`
    /// inserted_at and prevents the gateway from dropping the connection
    /// on idle).
    pub keep_alive_interval_ms: Option<u32>,
}

impl Default for QuicEndpointConfig {
    fn default() -> Self {
        Self {
            bind: None,
            alpn: vec![ZTLP_ALPN.to_vec()],
            // 60s idle timeout — long enough to survive a relay sweeper tick
            // (60s) plus jitter, short enough that a truly-dead client doesn't
            // hold a gateway slot forever.
            max_idle_timeout_ms: Some(60_000),
            // 15s keepalive — well under the 60s idle timeout. Picks up after
            // any natural traffic gap (e.g. user-initiated curl through the
            // local-forward) without flooding the relay.
            keep_alive_interval_ms: Some(15_000),
        }
    }
}

// ─── Tokio-backed endpoint (server/desktop) ───────────────────────────────
//
// Only compiled when both `quic-transport` and `tokio-runtime` are on.
// iOS NE builds (`ios-sync`) skip this entire block.

#[cfg(feature = "tokio-runtime")]
pub mod tokio_endpoint {
    //! `quinn::Endpoint`-backed server/client. Phase 1 deliverable.

    use super::{QuicEndpointConfig, QuicTransportError};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn ensure_crypto() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[derive(Debug)]
    struct NoCertVerifier;
    impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (
            vec![cert.cert.into()],
            PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
    }

    #[derive(Debug, Clone)]
    pub struct QuicConnection {
        pub inner: quinn::Connection,
    }

    impl QuicConnection {
        pub async fn open_bi(
            &self,
        ) -> Result<(quinn::SendStream, quinn::RecvStream), QuicTransportError> {
            Ok(self.inner.open_bi().await?)
        }

        pub async fn accept_bi(
            &self,
        ) -> Result<(quinn::SendStream, quinn::RecvStream), QuicTransportError> {
            Ok(self.inner.accept_bi().await?)
        }

        pub fn close(&self) {
            self.inner.close(0u32.into(), b"closed");
        }
    }

    #[derive(Debug)]
    pub struct QuicEndpoint {
        pub _cfg: QuicEndpointConfig,
        pub inner: quinn::Endpoint,
    }

    impl QuicEndpoint {
        pub async fn bind(cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
            let bind_addr = cfg.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let std_socket = std::net::UdpSocket::bind(bind_addr)?;
            Self::bind_with_socket(cfg, std_socket)
        }

        /// Bind a QUIC server using a caller-supplied `std::net::UdpSocket`.
        ///
        /// This lets the caller pre-bind the socket so it can do things on
        /// the underlying datagram socket (e.g. send a non-QUIC
        /// GATEWAY_REGISTER packet to a ZTLP relay) *before* handing
        /// ownership to Quinn. Pair with `try_clone()` on the original
        /// `std::net::UdpSocket` if you need to keep using the socket
        /// afterwards (the kernel socket is shared between both fds, so
        /// outbound packets all originate from the same `(ip, port)` —
        /// which is exactly what the relay's GATEWAY_REGISTER address
        /// mapping needs to match the gateway's QUIC listener).
        ///
        /// The supplied socket is automatically put into non-blocking mode
        /// for Quinn's tokio runtime.
        pub fn bind_with_socket(
            cfg: QuicEndpointConfig,
            std_socket: std::net::UdpSocket,
        ) -> Result<Self, QuicTransportError> {
            ensure_crypto();
            let (certs, key) = generate_self_signed();
            let mut server_crypto = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| {
                    QuicTransportError::Endpoint(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;

            server_crypto.alpn_protocols = cfg.alpn.clone();
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
            ));

            // v0.29.3: apply the idle-timeout / keepalive transport tuning so
            // gateway-side tunnels survive a 60s relay-sweeper tick and don't
            // get torn down by Quinn defaults under the relay's added RTT.
            // See QuicEndpointConfig field docs.
            let mut transport_config = quinn::TransportConfig::default();
            if let Some(idle_ms) = cfg.max_idle_timeout_ms {
                transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(idle_ms).into()));
            }
            if let Some(ka_ms) = cfg.keep_alive_interval_ms {
                transport_config
                    .keep_alive_interval(Some(std::time::Duration::from_millis(ka_ms as u64)));
            }
            server_config.transport_config(Arc::new(transport_config));

            // Quinn requires the socket be non-blocking for the tokio runtime.
            std_socket.set_nonblocking(true)?;

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                std_socket,
                Arc::new(quinn::TokioRuntime),
            )?;

            Ok(Self {
                _cfg: cfg,
                inner: endpoint,
            })
        }

        /// Variant of `bind_with_socket` that accepts a custom
        /// [`quinn::Runtime`] instead of the default `TokioRuntime`.
        ///
        /// Used by `ztlp listen --punch` to install a
        /// [`crate::punch_socket::PunchRuntime`] that intercepts
        /// hole-punch protocol bytes before Quinn sees them. The
        /// runtime's `wrap_udp_socket` is called by quinn with the
        /// provided std socket, producing the AsyncUdpSocket that
        /// powers the endpoint.
        pub fn bind_with_socket_and_runtime(
            cfg: QuicEndpointConfig,
            std_socket: std::net::UdpSocket,
            runtime: Arc<dyn quinn::Runtime>,
        ) -> Result<Self, QuicTransportError> {
            ensure_crypto();
            let (certs, key) = generate_self_signed();
            let mut server_crypto = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| QuicTransportError::Endpoint(std::io::Error::other(e)))?;

            server_crypto.alpn_protocols = cfg.alpn.clone();
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
            ));

            let mut transport_config = quinn::TransportConfig::default();
            if let Some(idle_ms) = cfg.max_idle_timeout_ms {
                transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(idle_ms).into()));
            }
            if let Some(ka_ms) = cfg.keep_alive_interval_ms {
                transport_config
                    .keep_alive_interval(Some(std::time::Duration::from_millis(ka_ms as u64)));
            }
            server_config.transport_config(Arc::new(transport_config));

            std_socket.set_nonblocking(true)?;

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                std_socket,
                runtime,
            )?;

            Ok(Self {
                _cfg: cfg,
                inner: endpoint,
            })
        }

        pub async fn connect_with_socket(
            cfg: QuicEndpointConfig,
            remote: SocketAddr,
            server_name: &str,
            std_socket: std::net::UdpSocket,
        ) -> Result<QuicConnection, QuicTransportError> {
            ensure_crypto();
            let mut client_crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth();

            client_crypto.alpn_protocols = cfg.alpn.clone();
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
            ));

            // v0.29.3: matching transport tuning for the client side. See
            // QuicEndpointConfig field docs for rationale.
            let mut transport_config = quinn::TransportConfig::default();
            if let Some(idle_ms) = cfg.max_idle_timeout_ms {
                transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(idle_ms).into()));
            }
            if let Some(ka_ms) = cfg.keep_alive_interval_ms {
                transport_config
                    .keep_alive_interval(Some(std::time::Duration::from_millis(ka_ms as u64)));
            }
            client_config.transport_config(Arc::new(transport_config));

            std_socket.set_nonblocking(true)?;
            let mut endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                std_socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            endpoint.set_default_client_config(client_config);

            let conn = endpoint.connect(remote, server_name)?.await?;
            Ok(QuicConnection { inner: conn })
        }

        pub async fn connect(
            cfg: QuicEndpointConfig,
            remote: SocketAddr,
            server_name: &str,
        ) -> Result<QuicConnection, QuicTransportError> {
            ensure_crypto();
            let mut client_crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth();

            client_crypto.alpn_protocols = cfg.alpn.clone();
            let mut client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
            ));

            // v0.29.3: matching transport tuning for the OS-socket-managed
            // client path.
            let mut transport_config = quinn::TransportConfig::default();
            if let Some(idle_ms) = cfg.max_idle_timeout_ms {
                transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(idle_ms).into()));
            }
            if let Some(ka_ms) = cfg.keep_alive_interval_ms {
                transport_config
                    .keep_alive_interval(Some(std::time::Duration::from_millis(ka_ms as u64)));
            }
            client_config.transport_config(Arc::new(transport_config));

            let bind_addr = cfg.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let mut endpoint = quinn::Endpoint::client(bind_addr)?;
            endpoint.set_default_client_config(client_config);

            let conn = endpoint.connect(remote, server_name)?.await?;
            Ok(QuicConnection { inner: conn })
        }

        pub async fn accept(&self) -> Result<QuicConnection, QuicTransportError> {
            let incoming = self.inner.accept().await.ok_or_else(|| {
                QuicTransportError::Endpoint(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "endpoint closed",
                ))
            })?;
            Ok(QuicConnection {
                inner: incoming.await?,
            })
        }
    }
}

pub mod noise_stream {
    use super::tokio_endpoint::QuicConnection;
    use super::QuicTransportError;
    use crate::handshake::{HandshakeContext, HandshakeResult};
    use crate::identity::{NodeId, NodeIdentity};

    pub const STREAM0_MAGIC_V1: u8 = super::STREAM0_MAGIC_V1;
    const MAX_FRAME_SIZE: usize = 65536;

    pub async fn read_ztlp_frame(
        recv: &mut quinn::RecvStream,
    ) -> Result<Vec<u8>, QuicTransportError> {
        let mut magic = [0u8; 1];
        recv.read_exact(&mut magic).await?;
        if magic[0] != STREAM0_MAGIC_V1 {
            return Err(QuicTransportError::BadMagic {
                expected: STREAM0_MAGIC_V1,
                got: magic[0],
            });
        }

        let mut len_bytes = [0u8; 2];
        recv.read_exact(&mut len_bytes).await?;
        let len = u16::from_be_bytes(len_bytes) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(QuicTransportError::FrameTooLarge { sz: len });
        }

        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await?;
        Ok(payload)
    }

    pub async fn write_ztlp_frame(
        send: &mut quinn::SendStream,
        payload: &[u8],
    ) -> Result<(), QuicTransportError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(QuicTransportError::FrameTooLarge { sz: payload.len() });
        }

        let len_bytes = (payload.len() as u16).to_be_bytes();
        let mut frame = Vec::with_capacity(1 + 2 + payload.len());
        frame.push(STREAM0_MAGIC_V1);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(payload);

        send.write_all(&frame).await?;
        Ok(())
    }

    pub async fn run_initiator_handshake(
        conn: &QuicConnection,
        identity: &NodeIdentity,
        responder_id: NodeId,
        service_hash: [u8; 16],
    ) -> Result<HandshakeResult, QuicTransportError> {
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut ctx = HandshakeContext::new_initiator(identity)?;

        let msg1 = ctx.write_message(&[])?;
        send.write_all(&service_hash).await?;
        write_ztlp_frame(&mut send, &msg1).await?;

        let mut sid_buf = [0u8; 12];
        recv.read_exact(&mut sid_buf).await?;
        let session_id = crate::packet::SessionId(sid_buf);

        let msg2 = read_ztlp_frame(&mut recv).await?;
        ctx.read_message(&msg2)?;

        let msg3 = ctx.write_message(&[])?;
        write_ztlp_frame(&mut send, &msg3).await?;

        let (_, init_sess) = ctx.finalize(responder_id, session_id)?;

        // Close our send side of stream-0 since handhshake is done
        // and we will multiplex data onto separate bi-streams mapped 1:1 to TCP connections
        let _ = send.finish();

        Ok(HandshakeResult {
            session: init_sess.clone(),
            // In a network handshake we only hold the local side's session.
            // Populate both alias fields with it so the struct stays exhaustive;
            // QUIC callers only read `.session` / `.session_id`.
            initiator_session: init_sess.clone(),
            responder_session: init_sess,
            session_id,
        })
    }

    pub async fn run_responder_handshake(
        conn: &QuicConnection,
        identity: &NodeIdentity,
        initiator_id: NodeId,
    ) -> Result<(HandshakeResult, [u8; 16]), QuicTransportError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut ctx = HandshakeContext::new_responder(identity)?;

        let mut service_hash = [0u8; 16];
        recv.read_exact(&mut service_hash).await?;
        let msg1 = read_ztlp_frame(&mut recv).await?;
        ctx.read_message(&msg1)?;

        let session_id = crate::packet::SessionId::generate();
        send.write_all(session_id.as_bytes()).await?;

        let msg2 = ctx.write_message(&[])?;
        write_ztlp_frame(&mut send, &msg2).await?;

        let msg3 = read_ztlp_frame(&mut recv).await?;
        ctx.read_message(&msg3)?;

        let (_, resp_sess) = ctx.finalize(initiator_id, session_id)?;

        let _ = send.finish();

        Ok((
            HandshakeResult {
                session: resp_sess.clone(),
                initiator_session: resp_sess.clone(),
                responder_session: resp_sess,
                session_id,
            },
            service_hash,
        ))
    }
}

// ─── Sans-io path (iOS NE — Phase 4) ──────────────────────────────────────
//
// quinn-proto has no IO: the caller drives `Connection` by feeding raw
// UDP datagrams in (`handle_dgram`) and pulling them out (`poll_transmit`).
// Suitable for the NE which owns its own socket and has no tokio runtime.

/// Sans-io QUIC connection state. Phase 0 placeholder.
///
/// Phase 4 will wrap `quinn_proto::Connection`. The current empty
/// struct lets us start writing the iOS-side wiring code (FFI shim
/// in `ffi.rs`) against a stable Rust type without committing to the
/// final field layout.
#[derive(Debug)]
pub struct SansIoConnection {
    // Under `ios-sync`, we wrap quinn-proto. For Phase 4 placeholder tests,
    // we only need it to compile cleanly without pulling tokio.
    pub inner: Option<quinn_proto::Connection>,
}

impl SansIoConnection {
    /// Construct a new sans-io connection.
    pub fn new(_cfg: QuicEndpointConfig) -> Result<Self, QuicTransportError> {
        // We will initialize this from Swift / iOS FFI layer where the certs
        // or keys might come from the native system or our hand-rolled loop,
        // without tokio dependencies. For now, empty Option fulfills the iOS NE path.
        Ok(Self { inner: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_stable() {
        // Locking the ALPN string in a test catches accidental edits.
        // Wire-format constants change == handshake breakage in the
        // field, so we treat this like a wire-compat assertion.
        assert_eq!(ZTLP_ALPN, b"ztlp/1");
    }

    #[test]
    fn stream0_magic_is_ascii_z() {
        // 'Z' = 0x5A. The handshake design picks this so a packet
        // capture is human-readable when debugging.
        assert_eq!(STREAM0_MAGIC_V1, 0x5A);
    }

    #[test]
    fn default_config_advertises_ztlp_alpn() {
        let cfg = QuicEndpointConfig::default();
        assert_eq!(cfg.alpn, vec![ZTLP_ALPN.to_vec()]);
        assert!(cfg.bind.is_none());
    }

    /// v0.29.3 regression: the default transport-config knobs MUST set both
    /// a max_idle_timeout and a keep_alive_interval so:
    ///   - relayed QUIC tunnels survive a ~60s sweeper tick + jitter,
    ///   - and idle tunnels emit keepalives that refresh the relay's
    ///     `{:client_map, ...}` mapping. Removing either field would
    ///     reopen the v0.29.0..v0.29.2 handshake-flakiness window.
    #[test]
    fn default_config_has_quinn_transport_tuning() {
        let cfg = QuicEndpointConfig::default();
        assert_eq!(
            cfg.max_idle_timeout_ms,
            Some(60_000),
            "max_idle_timeout regression — see v0.29.3 release notes"
        );
        assert_eq!(
            cfg.keep_alive_interval_ms,
            Some(15_000),
            "keep_alive_interval regression — see v0.29.3 release notes"
        );
        // keepalive must be strictly less than idle timeout; otherwise the
        // peer's idle clock can fire between two keepalives and the tunnel
        // tears down prematurely.
        match (cfg.keep_alive_interval_ms, cfg.max_idle_timeout_ms) {
            (Some(ka), Some(idle)) => assert!(
                ka < idle,
                "keep_alive_interval ({ka}ms) must be < max_idle_timeout ({idle}ms)"
            ),
            _ => unreachable!("we just asserted both fields are Some above"),
        }
    }

    #[test]
    fn sans_io_constructor_returns_ok() {
        let conn = SansIoConnection::new(QuicEndpointConfig::default());
        assert!(conn.is_ok());
    }
}
