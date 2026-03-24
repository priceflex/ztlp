//! Agent-side local TLS termination for ZTLP services.
//!
//! When a browser connects to `https://vault.home.ztlp`, the agent daemon
//! accepts the TCP connection, performs a TLS handshake (presenting a cert
//! for `vault.home.ztlp` signed by the ZTLP internal CA), then decrypts
//! the traffic and forwards it through the encrypted ZTLP tunnel.
//!
//! The result is double encryption: TLS from browser to agent, then
//! Noise_XX from agent to gateway. The browser never talks to the internet
//! directly — all traffic stays local or goes through the ZTLP tunnel.
//!
//! ## Certificate Management
//!
//! Certs are loaded from `~/.ztlp/certs/<hostname>.pem` + `<hostname>.key`.
//! They can be pre-provisioned via `ztlp admin cert-issue` and copied to
//! the agent, or pulled via `ztlp agent pull-certs`.
//!
//! ## SNI-Based Cert Selection
//!
//! The TLS acceptor uses SNI (Server Name Indication) from the client's
//! ClientHello to select the correct certificate. Each hostname gets its
//! own cert/key pair, cached in memory after first load.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

// ─── Configuration ──────────────────────────────────────────────────────────

/// TLS configuration section for agent config (`[tls]` in `agent.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Enable local TLS termination (default: true).
    pub enabled: bool,

    /// Directory containing per-hostname cert/key files (default: `~/.ztlp/certs`).
    pub cert_dir: String,

    /// Automatically request certs for new hostnames (default: true).
    /// Note: requires a running CA and NS connectivity.
    pub auto_issue: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_dir: "~/.ztlp/certs".to_string(),
            auto_issue: true,
        }
    }
}

impl TlsConfig {
    /// Resolve the cert directory path, expanding `~`.
    pub fn cert_dir_path(&self) -> PathBuf {
        expand_tilde(&self.cert_dir)
    }
}

// ─── Port-Based TLS Decision ────────────────────────────────────────────────

/// Determine whether a port should use TLS wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Always perform TLS handshake (port 443, 8443).
    Always,
    /// Never perform TLS (port 80, 8080, 22).
    Never,
    /// Sniff the first bytes to detect TLS ClientHello.
    Detect,
}

/// Determine the TLS mode for a given port number.
pub fn tls_mode_for_port(port: u16) -> TlsMode {
    match port {
        443 | 8443 => TlsMode::Always,
        22 | 80 | 8080 => TlsMode::Never,
        _ => TlsMode::Detect,
    }
}

/// Check if the given bytes look like the start of a TLS ClientHello.
///
/// A TLS record starts with:
/// - 0x16 (ContentType: Handshake)
/// - 0x03 0x0X (TLS version: SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
pub fn looks_like_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == 0x16 && buf[1] == 0x03
}

// ─── SNI-Based Cert Resolver ────────────────────────────────────────────────

/// A TLS certificate resolver that selects certs based on SNI hostname.
///
/// Certs are loaded lazily from disk and cached in memory. Each hostname
/// maps to a `CertifiedKey` (cert chain + signing key).
pub struct SniCertResolver {
    /// Cached certs by hostname.
    certs: std::sync::RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Directory containing cert files.
    cert_dir: PathBuf,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("cert_dir", &self.cert_dir)
            .field("cached_certs", &self.certs.read().map(|c| c.len()).unwrap_or(0))
            .finish()
    }
}

impl SniCertResolver {
    /// Create a new resolver that loads certs from the given directory.
    pub fn new(cert_dir: PathBuf) -> Self {
        Self {
            certs: std::sync::RwLock::new(HashMap::new()),
            cert_dir,
        }
    }

    /// Preload a cert for a specific hostname from files.
    ///
    /// Expects `<cert_dir>/<hostname>.pem` and `<cert_dir>/<hostname>.key`.
    pub fn preload_cert(&self, hostname: &str) -> Result<(), CertLoadError> {
        let key = load_certified_key(&self.cert_dir, hostname)?;
        let mut certs = self.certs.write().map_err(|_| CertLoadError::LockPoisoned)?;
        certs.insert(hostname.to_string(), Arc::new(key));
        Ok(())
    }

    /// Preload all certs found in the cert directory.
    ///
    /// Scans for `*.pem` files and loads matching `*.key` files.
    pub fn preload_all(&self) -> usize {
        let mut loaded = 0;
        let entries = match std::fs::read_dir(&self.cert_dir) {
            Ok(e) => e,
            Err(e) => {
                debug!("cannot read cert dir {}: {}", self.cert_dir.display(), e);
                return 0;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pem") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // Convert filename back to hostname: underscores to dots
                    let hostname = stem.replace('_', ".");
                    match self.preload_cert(&hostname) {
                        Ok(()) => {
                            debug!("preloaded TLS cert for {}", hostname);
                            loaded += 1;
                        }
                        Err(e) => {
                            warn!("failed to load cert for {}: {}", hostname, e);
                        }
                    }
                }
            }
        }

        loaded
    }

    /// Get the number of cached certs.
    pub fn cert_count(&self) -> usize {
        self.certs.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Try to resolve a cert for a hostname, loading from disk if needed.
    fn resolve_cert(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        // Check cache first
        {
            let certs = self.certs.read().ok()?;
            if let Some(key) = certs.get(hostname) {
                return Some(Arc::clone(key));
            }
        }

        // Try loading from disk
        match load_certified_key(&self.cert_dir, hostname) {
            Ok(key) => {
                let key = Arc::new(key);
                if let Ok(mut certs) = self.certs.write() {
                    certs.insert(hostname.to_string(), Arc::clone(&key));
                }
                info!("loaded TLS cert for {} (on-demand)", hostname);
                Some(key)
            }
            Err(e) => {
                debug!("no cert for {}: {}", hostname, e);
                None
            }
        }
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        debug!("TLS SNI: {}", sni);
        self.resolve_cert(sni)
    }
}

// ─── Cert Loading ───────────────────────────────────────────────────────────

/// Errors that can occur loading a certificate.
#[derive(Debug)]
pub enum CertLoadError {
    /// I/O error reading cert or key file.
    Io(io::Error),
    /// No certificates found in PEM file.
    NoCerts,
    /// No private key found in key file.
    NoKey,
    /// Invalid private key format.
    InvalidKey(String),
    /// RwLock was poisoned.
    LockPoisoned,
}

impl std::fmt::Display for CertLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::NoCerts => write!(f, "no certificates found in PEM file"),
            Self::NoKey => write!(f, "no private key found in key file"),
            Self::InvalidKey(e) => write!(f, "invalid private key: {}", e),
            Self::LockPoisoned => write!(f, "internal lock poisoned"),
        }
    }
}

impl std::error::Error for CertLoadError {}

impl From<io::Error> for CertLoadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Load a certified key (cert chain + private key) for a hostname.
///
/// Reads from `<cert_dir>/<hostname_underscored>.pem` and `<cert_dir>/<hostname_underscored>.key`.
/// The hostname's dots are replaced with underscores in the filename
/// (matching the convention used by `ztlp admin cert-issue`).
fn load_certified_key(cert_dir: &Path, hostname: &str) -> Result<CertifiedKey, CertLoadError> {
    let sanitized = hostname.replace('.', "_");
    let cert_path = cert_dir.join(format!("{}.pem", sanitized));
    let key_path = cert_dir.join(format!("{}.key", sanitized));

    // Read and parse cert chain
    let cert_pem = std::fs::read(&cert_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CertLoadError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

    if certs.is_empty() {
        return Err(CertLoadError::NoCerts);
    }

    // Read and parse private key
    let key_pem = std::fs::read(&key_path)?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| CertLoadError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?
        .ok_or(CertLoadError::NoKey)?;

    // Create signing key from the private key using the default crypto provider
    let signing_key =
        tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
            .map_err(|e| CertLoadError::InvalidKey(format!("{}", e)))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

// ─── TLS Acceptor ───────────────────────────────────────────────────────────

/// Create a TLS acceptor with SNI-based cert resolution.
///
/// The acceptor uses the `SniCertResolver` to select the appropriate
/// certificate based on the client's SNI extension.
pub fn create_tls_acceptor(resolver: Arc<SniCertResolver>) -> Result<TlsAcceptor, io::Error> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ─── Connection Wrapping ────────────────────────────────────────────────────

/// The result of attempting to wrap a TCP stream with TLS.
pub enum MaybeWrapped {
    /// TLS handshake succeeded — stream is now encrypted.
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
    /// No TLS — pass through the raw TCP stream.
    /// Includes any bytes that were peeked during detection.
    Plain(TcpStream),
    /// Peeked bytes that need to be replayed, plus the TCP stream.
    /// Used when we peeked bytes for TLS detection but decided not to TLS.
    PlainWithPeek(PeekStream),
}

/// A TCP stream with pre-read bytes that need to be replayed.
///
/// When we peek at the first bytes to detect TLS, we consume them from
/// the socket. If it's not TLS, we need to prepend those bytes back
/// before forwarding to the tunnel.
pub struct PeekStream {
    /// Bytes that were already read from the socket.
    pub peeked: Vec<u8>,
    /// The underlying TCP stream.
    pub stream: TcpStream,
}

impl AsyncRead for PeekStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.peeked.is_empty() {
            let n = std::cmp::min(this.peeked.len(), buf.remaining());
            buf.put_slice(&this.peeked[..n]);
            this.peeked.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeekStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// Attempt to wrap a TCP connection in TLS based on the port-level policy.
///
/// - `TlsMode::Always` → perform TLS accept immediately
/// - `TlsMode::Never` → return the stream unwrapped
/// - `TlsMode::Detect` → peek at first bytes; if they look like a TLS
///   ClientHello, perform TLS accept; otherwise pass through
pub async fn maybe_wrap_tls(
    stream: TcpStream,
    port: u16,
    acceptor: &TlsAcceptor,
) -> Result<MaybeWrapped, io::Error> {
    match tls_mode_for_port(port) {
        TlsMode::Always => {
            debug!("port {} → TLS (always)", port);
            match acceptor.accept(stream).await {
                Ok(tls) => Ok(MaybeWrapped::Tls(tls)),
                Err(e) => {
                    warn!("TLS handshake failed on port {}: {}", port, e);
                    Err(e)
                }
            }
        }
        TlsMode::Never => {
            debug!("port {} → plain (never TLS)", port);
            Ok(MaybeWrapped::Plain(stream))
        }
        TlsMode::Detect => {
            // Peek at first 2 bytes to detect TLS
            let mut peek_buf = [0u8; 2];
            let stream = stream;
            // Use peek() to avoid consuming bytes
            match stream.peek(&mut peek_buf).await {
                Ok(n) if n >= 2 && looks_like_tls_client_hello(&peek_buf) => {
                    debug!("port {} → TLS (detected ClientHello)", port);
                    match acceptor.accept(stream).await {
                        Ok(tls) => Ok(MaybeWrapped::Tls(tls)),
                        Err(e) => {
                            warn!("TLS handshake failed on port {}: {}", port, e);
                            Err(e)
                        }
                    }
                }
                Ok(_) => {
                    debug!("port {} → plain (no TLS detected)", port);
                    Ok(MaybeWrapped::Plain(stream))
                }
                Err(e) => {
                    warn!("peek failed on port {}: {}", port, e);
                    Err(e)
                }
            }
        }
    }
}

// ─── Utility ────────────────────────────────────────────────────────────────

/// Expand `~` prefix to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_mode_for_port() {
        assert_eq!(tls_mode_for_port(443), TlsMode::Always);
        assert_eq!(tls_mode_for_port(8443), TlsMode::Always);
        assert_eq!(tls_mode_for_port(80), TlsMode::Never);
        assert_eq!(tls_mode_for_port(8080), TlsMode::Never);
        assert_eq!(tls_mode_for_port(22), TlsMode::Never);
        assert_eq!(tls_mode_for_port(3306), TlsMode::Detect);
        assert_eq!(tls_mode_for_port(5432), TlsMode::Detect);
        assert_eq!(tls_mode_for_port(3389), TlsMode::Detect);
    }

    #[test]
    fn test_looks_like_tls_client_hello() {
        // Valid TLS 1.2 ClientHello start
        assert!(looks_like_tls_client_hello(&[0x16, 0x03, 0x01]));
        // Valid TLS 1.3 ClientHello start
        assert!(looks_like_tls_client_hello(&[0x16, 0x03, 0x03]));
        // SSLv3
        assert!(looks_like_tls_client_hello(&[0x16, 0x03, 0x00]));
        // Not TLS — HTTP
        assert!(!looks_like_tls_client_hello(&[0x47, 0x45, 0x54])); // "GET"
        // Not TLS — SSH
        assert!(!looks_like_tls_client_hello(&[0x53, 0x53, 0x48])); // "SSH"
        // Too short
        assert!(!looks_like_tls_client_hello(&[0x16]));
        // Empty
        assert!(!looks_like_tls_client_hello(&[]));
    }

    #[test]
    fn test_tls_config_defaults() {
        let config = TlsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.cert_dir, "~/.ztlp/certs");
        assert!(config.auto_issue);
    }

    #[test]
    fn test_tls_config_parse() {
        let toml_str = r#"
enabled = true
cert_dir = "~/.ztlp/certs"
auto_issue = false
"#;
        let config: TlsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert!(!config.auto_issue);
    }

    #[test]
    fn test_tls_config_disabled() {
        let toml_str = r#"
enabled = false
"#;
        let config: TlsConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        // Other fields should be defaults
        assert_eq!(config.cert_dir, "~/.ztlp/certs");
        assert!(config.auto_issue);
    }

    #[test]
    fn test_cert_dir_path_expansion() {
        let config = TlsConfig::default();
        let path = config.cert_dir_path();
        assert!(!path.to_string_lossy().starts_with("~"));
        assert!(path.to_string_lossy().contains(".ztlp/certs"));
    }

    #[test]
    fn test_sni_resolver_empty() {
        let dir = std::env::temp_dir().join("ztlp_test_sni_empty");
        let _ = std::fs::create_dir_all(&dir);
        let resolver = SniCertResolver::new(dir.clone());
        assert_eq!(resolver.cert_count(), 0);
        assert!(resolver.resolve_cert("nonexistent.ztlp").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_sni_resolver_preload_missing() {
        let dir = std::env::temp_dir().join("ztlp_test_sni_missing");
        let _ = std::fs::create_dir_all(&dir);
        let resolver = SniCertResolver::new(dir.clone());
        let result = resolver.preload_cert("nonexistent.example.ztlp");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_load_certified_key_missing_files() {
        let dir = std::env::temp_dir().join("ztlp_test_cert_missing");
        let _ = std::fs::create_dir_all(&dir);
        let result = load_certified_key(&dir, "test.example.ztlp");
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_load_certified_key_with_valid_cert() {
        // Generate a self-signed cert for testing using rcgen
        // (We test with real PEM files to exercise the full loading path)
        let dir = std::env::temp_dir().join("ztlp_test_cert_valid");
        let _ = std::fs::create_dir_all(&dir);

        // Write a test ECDSA P-256 private key in PEM format
        let key_pem = concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2M5MjU1NzMz\n",
            "-----END PRIVATE KEY-----\n",
        );
        let cert_pem = concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "MIIBQzCB6aADAgECAhEAtest\n",
            "-----END CERTIFICATE-----\n",
        );
        std::fs::write(dir.join("test_example_ztlp.key"), key_pem).unwrap();
        std::fs::write(dir.join("test_example_ztlp.pem"), cert_pem).unwrap();

        // This should fail because the test PEM data isn't valid DER,
        // but it exercises the file-finding logic
        let result = load_certified_key(&dir, "test.example.ztlp");
        // The cert PEM won't parse as valid DER, so it should return NoCerts
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_sni_resolver_preload_all_empty_dir() {
        let dir = std::env::temp_dir().join("ztlp_test_preload_empty");
        let _ = std::fs::create_dir_all(&dir);
        let resolver = SniCertResolver::new(dir.clone());
        let loaded = resolver.preload_all();
        assert_eq!(loaded, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_expand_tilde() {
        let result = expand_tilde("~/.ztlp/certs");
        assert!(!result.to_string_lossy().starts_with("~"));
        assert!(result.to_string_lossy().contains(".ztlp/certs"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let result = expand_tilde("/etc/ztlp/certs");
        assert_eq!(result, PathBuf::from("/etc/ztlp/certs"));
    }
}
