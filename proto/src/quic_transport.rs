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
}

impl Default for QuicEndpointConfig {
    fn default() -> Self {
        Self {
            bind: None,
            alpn: vec![ZTLP_ALPN.to_vec()],
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
            ensure_crypto();
            let (certs, key) = generate_self_signed();
            let mut server_crypto = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| {
                    QuicTransportError::Endpoint(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;

            server_crypto.alpn_protocols = cfg.alpn.clone();
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
            ));

            let bind_addr = cfg.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;

            Ok(Self {
                _cfg: cfg,
                inner: endpoint,
            })
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
            let client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
            ));

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

    pub async fn read_noise_frame(
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

    pub async fn write_noise_frame(
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
    ) -> Result<HandshakeResult, QuicTransportError> {
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut ctx = HandshakeContext::new_initiator(identity)?;

        let msg1 = ctx.write_message(&[])?;
        write_noise_frame(&mut send, &msg1).await?;

        let msg2 = read_noise_frame(&mut recv).await?;
        ctx.read_message(&msg2)?;

        let msg3 = ctx.write_message(&[])?;
        write_noise_frame(&mut send, &msg3).await?;

        let session_id = crate::packet::SessionId::generate();
        let (_, init_sess) = ctx.finalize(responder_id, session_id)?;

        Ok(HandshakeResult {
            initiator_session: init_sess.clone(),
            responder_session: init_sess, // Placeholder
        })
    }

    pub async fn run_responder_handshake(
        conn: &QuicConnection,
        identity: &NodeIdentity,
        initiator_id: NodeId,
    ) -> Result<HandshakeResult, QuicTransportError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut ctx = HandshakeContext::new_responder(identity)?;

        let msg1 = read_noise_frame(&mut recv).await?;
        ctx.read_message(&msg1)?;

        let msg2 = ctx.write_message(&[])?;
        write_noise_frame(&mut send, &msg2).await?;

        let msg3 = read_noise_frame(&mut recv).await?;
        ctx.read_message(&msg3)?;

        let session_id = crate::packet::SessionId::generate();
        let (_, resp_sess) = ctx.finalize(initiator_id, session_id)?;

        Ok(HandshakeResult {
            initiator_session: resp_sess.clone(), // Placeholder
            responder_session: resp_sess,
        })
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

    #[test]
    fn sans_io_constructor_returns_ok() {
        let conn = SansIoConnection::new(QuicEndpointConfig::default());
        assert!(conn.is_ok());
    }
}
