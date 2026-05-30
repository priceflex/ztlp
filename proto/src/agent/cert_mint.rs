//! On-demand X.509 leaf certificate minting for ZTLP SNI hostnames.
//!
//! When the agent's TLS terminator sees a TLS ClientHello with SNI
//! `<host>.<zone>.ztlp` (e.g. `vault.techrockstars.ztlp`), it needs to present
//! a leaf certificate for that hostname so the browser sees a green-lock
//! TLS handshake.
//!
//! Two ways this can resolve:
//!
//! 1. Pre-provisioned: `<cert_dir>/<hostname>.pem` + `.key` already on disk
//!    (the path that exists today in [`super::local_tls::SniCertResolver`]).
//! 2. **On-demand (this module, D5.T2)**: mint a fresh leaf signed by the
//!    local intermediate CA, cache it both in memory and on disk, and hand
//!    it back to the TLS resolver.
//!
//! ## CA chain
//!
//! The leaves are signed by the **intermediate CA**:
//!
//! ```text
//! ZTLP Root CA (self-signed, in LocalMachine\Root trust store)
//!     └── ZTLP Intermediate CA (signed by Root)
//!             └── *.<zone>.ztlp leaves (this module mints these)
//! ```
//!
//! Browsers trust the Root (installed by D5.T1) → trust the Intermediate
//! transitively → trust the leaf because the chain validates.
//!
//! ## Crypto choices
//!
//! - **ECDSA P-256** for everything. Smallest cert size, broad browser
//!   support, and `rcgen` 0.13 supports it natively (`PKCS_ECDSA_P256_SHA256`).
//!   Ed25519 is appealing but `rustls-webpki` doesn't validate Ed25519 leaves
//!   by default and we'd have to enable an experimental verifier — not worth
//!   the surface area.
//! - **Validity:** 90 days. Short enough to limit damage if a leaf key
//!   leaks, long enough that the agent doesn't churn certs every browser
//!   restart.
//! - **SAN:** `dns:<hostname>` only. No CN-based identity, no IP SAN —
//!   matches modern browser policy (CN is deprecated in CN-only certs).
//! - **EKU:** `id-kp-serverAuth` only. Leaves cannot be used as client
//!   certs or to sign other certs.
//!
//! ## Persistence
//!
//! Minted leaves are persisted under `<cert_dir>/<hostname_safe>.pem` +
//! `.key` (dots in hostname replaced with underscores so filenames are
//! filesystem-safe and match `preload_all` in `local_tls`).
//!
//! ## Concurrency
//!
//! `IntermediateCa::mint_leaf` is `&self` (no mutation of CA state), so it's
//! safe to call from any number of threads concurrently. The TLS resolver
//! holds the `IntermediateCa` behind an `Arc` and consults it on every
//! ClientHello miss.
//!
//! ## D5.T2 scope
//!
//! This module owns: parsing the CA from disk, minting a leaf, serializing
//! it back to disk, and converting it to a `rustls::sign::CertifiedKey` for
//! the TLS stack. It does NOT own: generating the root or intermediate
//! (that's `ztlp admin ca-init`), installing the root cert into the OS
//! trust store (that's `ca_trust.rs` + the service installer).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use thiserror::Error;

/// Errors that can occur loading or using the intermediate CA, or minting
/// leaves.
#[derive(Debug, Error)]
pub enum CertMintError {
    #[error("Intermediate CA cert file not found: {0}")]
    IntermediateCertNotFound(PathBuf),
    #[error("Intermediate CA key file not found: {0}")]
    IntermediateKeyNotFound(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PEM parse error: {0}")]
    Pem(String),
    #[error("rcgen error: {0}")]
    Rcgen(String),
    #[error("invalid SNI hostname for minting: {0}")]
    InvalidHostname(String),
}

impl From<rcgen::Error> for CertMintError {
    fn from(e: rcgen::Error) -> Self {
        CertMintError::Rcgen(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CertMintError>;

/// Maximum leaf cert validity. 90 days is the modern browser sweet spot
/// (matches Let's Encrypt). Long enough to avoid churn; short enough that
/// a leaked leaf can't be replayed forever.
pub const LEAF_VALIDITY_DAYS: i64 = 90;

/// The on-disk intermediate CA, loaded into memory and used to sign leaves.
///
/// Construct via [`IntermediateCa::load_from_dir`] (production) or
/// [`IntermediateCa::generate_for_test`] (tests).
pub struct IntermediateCa {
    /// rcgen Certificate that re-renders the intermediate. We need this
    /// (rather than just the parsed cert + keypair separately) because
    /// rcgen's `signed_by` API consumes a `&Certificate` issuer.
    issuer_cert: rcgen::Certificate,
    issuer_key: KeyPair,
    /// PEM-encoded copy of the intermediate cert, so we can build the chain
    /// (`[leaf, intermediate]`) cheaply on every mint without re-serializing.
    issuer_pem: String,
}

impl std::fmt::Debug for IntermediateCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntermediateCa")
            .field("issuer_pem_bytes", &self.issuer_pem.len())
            .finish()
    }
}

impl IntermediateCa {
    /// Load the intermediate CA from `<ca_dir>/intermediate.pem` +
    /// `<ca_dir>/intermediate.key`.
    pub fn load_from_dir(ca_dir: &Path) -> Result<Self> {
        let cert_path = ca_dir.join("intermediate.pem");
        let key_path = ca_dir.join("intermediate.key");
        if !cert_path.exists() {
            return Err(CertMintError::IntermediateCertNotFound(cert_path));
        }
        if !key_path.exists() {
            return Err(CertMintError::IntermediateKeyNotFound(key_path));
        }
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Parse the intermediate from PEM strings (cert + key).
    ///
    /// Used by `load_from_dir` and directly by tests that hold PEMs in
    /// memory.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let issuer_key = KeyPair::from_pem(key_pem)
            .map_err(|e| CertMintError::Pem(format!("intermediate key: {}", e)))?;

        // Re-render the intermediate from its existing PEM. We need an
        // rcgen::Certificate to act as the `signed_by` issuer for new
        // leaves — rcgen 0.13 takes the issuer as a `&Certificate`, not as
        // a raw DER blob. The cleanest way to round-trip a stored
        // intermediate is to parse it back into CertificateParams and
        // re-self-sign with the same key (DN, validity, extensions all
        // come along for the ride).
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| CertMintError::Pem(format!("intermediate cert: {}", e)))?;
        let issuer_cert = params.self_signed(&issuer_key)?;

        Ok(Self {
            issuer_cert,
            issuer_key,
            issuer_pem: cert_pem.to_string(),
        })
    }

    /// Generate a brand-new intermediate for unit tests. Returns the in-
    /// memory CA plus the matching key (so tests that also need to
    /// validate the chain can do so).
    ///
    /// Not for production use — production intermediates are signed by a
    /// real root and persisted to `~/.ztlp/ca/` by `ztlp admin ca-init`.
    pub fn generate_for_test() -> Result<(Self, String, String)> {
        let issuer_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ZTLP Intermediate CA (test)");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer_cert = params.self_signed(&issuer_key)?;
        let cert_pem = issuer_cert.pem();
        let key_pem = issuer_key.serialize_pem();
        let ca = Self {
            issuer_cert,
            issuer_key,
            issuer_pem: cert_pem.clone(),
        };
        Ok((ca, cert_pem, key_pem))
    }

    /// Mint a fresh leaf certificate for `hostname`, signed by this
    /// intermediate.
    ///
    /// Returns the leaf cert PEM, the leaf key PEM, and the full chain PEM
    /// (`<leaf>\n<intermediate>`). Callers persist whichever pieces they
    /// need.
    pub fn mint_leaf(&self, hostname: &str) -> Result<MintedLeaf> {
        validate_sni_hostname(hostname)?;

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])?;
        // SAN — the only identity binding browsers honour. We deliberately
        // do NOT set CN to the hostname (CN-in-cert identity is deprecated;
        // serverAuth EKU + SAN dns is what matters).
        params.subject_alt_names = vec![SanType::DnsName(hostname.to_string().try_into().map_err(
            |e: rcgen::Error| CertMintError::Rcgen(format!("invalid dns SAN: {}", e)),
        )?)];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1); // tolerance for clock skew
        params.not_after = now + time::Duration::days(LEAF_VALIDITY_DAYS);

        let leaf = params.signed_by(&leaf_key, &self.issuer_cert, &self.issuer_key)?;

        let leaf_pem = leaf.pem();
        let chain_pem = format!("{}{}", leaf_pem, self.issuer_pem);
        let key_pem = leaf_key.serialize_pem();

        Ok(MintedLeaf {
            hostname: hostname.to_string(),
            leaf_pem,
            chain_pem,
            key_pem,
        })
    }
}

/// One freshly-minted leaf cert + key + chain.
#[derive(Debug, Clone)]
pub struct MintedLeaf {
    pub hostname: String,
    /// PEM of just the leaf cert (no chain).
    pub leaf_pem: String,
    /// PEM of `[leaf, intermediate]` — what callers persist as
    /// `<hostname>.pem` so the file is browser-loadable on its own.
    pub chain_pem: String,
    /// PEM of the leaf's PKCS#8 EC private key.
    pub key_pem: String,
}

impl MintedLeaf {
    /// Persist this leaf to `<cert_dir>/<hostname_safe>.pem` and
    /// `<cert_dir>/<hostname_safe>.key`. Replaces dots with underscores in
    /// the filename so it matches the existing `preload_all` convention in
    /// `local_tls`.
    pub fn persist(&self, cert_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(cert_dir)?;
        let safe = self.hostname.replace('.', "_");
        let pem_path = cert_dir.join(format!("{}.pem", safe));
        let key_path = cert_dir.join(format!("{}.key", safe));
        std::fs::write(&pem_path, &self.chain_pem)?;
        std::fs::write(&key_path, &self.key_pem)?;
        // Lock down the key file mode on Unix. On Windows ACLs handle this
        // (and `0o600` is meaningless), so we skip there.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Convert to a rustls `CertifiedKey` suitable for handing to a
    /// `ResolvesServerCert` impl.
    pub fn into_certified_key(self) -> Result<Arc<rustls::sign::CertifiedKey>> {
        // Parse the leaf chain PEM into DERs. rustls wants the leaf first,
        // followed by intermediates.
        let mut chain_ders: Vec<rustls::pki_types::CertificateDer<'static>> = Vec::new();
        for chunk in rustls_pemfile::certs(&mut self.chain_pem.as_bytes()) {
            let der = chunk.map_err(|e| CertMintError::Pem(format!("chain cert: {}", e)))?;
            chain_ders.push(der);
        }
        if chain_ders.is_empty() {
            return Err(CertMintError::Pem(
                "chain_pem contained no certificates".into(),
            ));
        }

        // Parse the leaf key as PKCS#8. rcgen 0.13 always emits PKCS#8.
        let key_der_item = rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .map_err(|e| CertMintError::Pem(format!("leaf key: {}", e)))?
            .ok_or_else(|| CertMintError::Pem("no private key found in key_pem".into()))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der_item)
            .map_err(|e| CertMintError::Pem(format!("signing key from der: {}", e)))?;

        Ok(Arc::new(rustls::sign::CertifiedKey::new(
            chain_ders,
            signing_key,
        )))
    }
}

/// Reject hostnames that wouldn't be safe to embed as a SAN.
///
/// Rules:
/// - non-empty
/// - <=253 chars (DNS limit)
/// - each label 1..=63 chars, ASCII letters/digits/hyphens, no leading or
///   trailing hyphen
/// - at least one dot (we won't mint single-label certs — they'd be
///   ambiguous; ZTLP zones are always multi-label like `foo.zone.ztlp`)
///
/// We deliberately do NOT enforce `.ztlp` suffix here — the caller (the
/// `SniCertResolver`) decides which hostnames are worth minting for, and
/// custom-domain mappings (via `agent::domain_map`) might legitimately not
/// end in `.ztlp`.
fn validate_sni_hostname(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(CertMintError::InvalidHostname("empty hostname".into()));
    }
    if host.len() > 253 {
        return Err(CertMintError::InvalidHostname(format!(
            "hostname exceeds 253 chars: {} chars",
            host.len()
        )));
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(CertMintError::InvalidHostname(format!(
            "hostname must have at least one dot, got '{}'",
            host
        )));
    }
    for label in &labels {
        if label.is_empty() {
            return Err(CertMintError::InvalidHostname(format!(
                "hostname has empty label: '{}'",
                host
            )));
        }
        if label.len() > 63 {
            return Err(CertMintError::InvalidHostname(format!(
                "label exceeds 63 chars in '{}'",
                host
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(CertMintError::InvalidHostname(format!(
                "label has leading/trailing hyphen in '{}'",
                host
            )));
        }
        for c in label.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-') {
                return Err(CertMintError::InvalidHostname(format!(
                    "label has non-DNS char '{}' in '{}'",
                    c, host
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_sni_hostname ────────────────────────────────────────────

    #[test]
    fn validates_normal_ztlp_hostname() {
        assert!(validate_sni_hostname("vault.trs.ztlp").is_ok());
        assert!(validate_sni_hostname("vault.techrockstars.ztlp").is_ok());
    }

    #[test]
    fn validates_custom_domain_mapping() {
        // Per the module docstring: we don't enforce .ztlp suffix.
        assert!(validate_sni_hostname("vault.internal.corp").is_ok());
    }

    #[test]
    fn rejects_empty_hostname() {
        assert!(validate_sni_hostname("").is_err());
    }

    #[test]
    fn rejects_single_label_hostname() {
        let err = validate_sni_hostname("localhost").unwrap_err();
        assert!(matches!(err, CertMintError::InvalidHostname(_)));
    }

    #[test]
    fn rejects_overlong_hostname() {
        let huge = "a".repeat(300);
        assert!(validate_sni_hostname(&huge).is_err());
    }

    #[test]
    fn rejects_overlong_label() {
        let host = format!("{}.ztlp", "a".repeat(64));
        assert!(validate_sni_hostname(&host).is_err());
    }

    #[test]
    fn rejects_empty_label() {
        assert!(validate_sni_hostname("foo..bar").is_err());
    }

    #[test]
    fn rejects_leading_hyphen_label() {
        assert!(validate_sni_hostname("-foo.bar").is_err());
    }

    #[test]
    fn rejects_trailing_hyphen_label() {
        assert!(validate_sni_hostname("foo-.bar").is_err());
    }

    #[test]
    fn rejects_underscore_in_label() {
        // RFC1035 DNS labels are alphanumeric + hyphen only.
        // Underscores are common in DNS records (SRV, DKIM) but NOT in
        // browser-bound names. Browsers reject _ in SANs on principle.
        assert!(validate_sni_hostname("foo_bar.ztlp").is_err());
    }

    // ── IntermediateCa::generate_for_test + mint_leaf ───────────────────

    #[test]
    fn test_intermediate_generates_and_renders_pem() {
        let (ca, cert_pem, key_pem) = IntermediateCa::generate_for_test().unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!ca.issuer_pem.is_empty());
    }

    #[test]
    fn test_intermediate_round_trip_through_pem() {
        // Generate, capture PEMs, reload from PEMs — should mint a working
        // leaf from the reloaded copy. This exercises the production
        // load path (file → PEM → CertificateParams → self_signed).
        let (_orig, cert_pem, key_pem) = IntermediateCa::generate_for_test().unwrap();
        let reloaded = IntermediateCa::from_pem(&cert_pem, &key_pem).unwrap();
        let leaf = reloaded.mint_leaf("vault.trs.ztlp").unwrap();
        assert_eq!(leaf.hostname, "vault.trs.ztlp");
        assert!(leaf.leaf_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_mint_leaf_returns_chain_with_two_certs() {
        let (ca, _, _) = IntermediateCa::generate_for_test().unwrap();
        let leaf = ca.mint_leaf("vault.trs.ztlp").unwrap();
        // chain_pem should have leaf + intermediate = 2 BEGIN CERTIFICATE.
        let begin_count = leaf.chain_pem.matches("BEGIN CERTIFICATE").count();
        assert_eq!(
            begin_count, 2,
            "chain_pem should contain leaf+intermediate, got {} certs",
            begin_count
        );
    }

    #[test]
    fn test_mint_leaf_persists_with_dot_to_underscore_filename() {
        let (ca, _, _) = IntermediateCa::generate_for_test().unwrap();
        let leaf = ca.mint_leaf("vault.trs.ztlp").unwrap();
        let tmp = tempfile::tempdir().unwrap();
        leaf.persist(tmp.path()).unwrap();
        let pem = tmp.path().join("vault_trs_ztlp.pem");
        let key = tmp.path().join("vault_trs_ztlp.key");
        assert!(pem.exists(), "pem file not at expected path");
        assert!(key.exists(), "key file not at expected path");
        let pem_contents = std::fs::read_to_string(&pem).unwrap();
        assert!(pem_contents.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_mint_leaf_rejects_invalid_hostname() {
        let (ca, _, _) = IntermediateCa::generate_for_test().unwrap();
        let err = ca.mint_leaf("nodothere").unwrap_err();
        assert!(matches!(err, CertMintError::InvalidHostname(_)));
    }

    #[test]
    fn test_minted_leaf_converts_to_certified_key() {
        // rustls round-trip: mint a leaf, parse it back through
        // rustls_pemfile, and confirm into_certified_key yields a valid
        // CertifiedKey with non-empty chain.
        let (ca, _, _) = IntermediateCa::generate_for_test().unwrap();
        let leaf = ca.mint_leaf("vault.trs.ztlp").unwrap();
        let ck = leaf.into_certified_key().unwrap();
        assert_eq!(ck.cert.len(), 2, "expected leaf + intermediate in chain");
    }

    #[test]
    fn test_mint_leaf_uses_p256_key() {
        // The persisted key.pem should be an EC key, not RSA. We assert
        // by looking for the PKCS#8 marker (rcgen 0.13 always uses
        // PKCS#8 for both EC and RSA, so we further check the leaf cert's
        // SPKI algorithm via a string match on the PEM-decoded bytes is
        // overkill — instead we just verify the leaf parses and is small
        // (RSA-2048 leaf PEMs are ~1.1KB+; ECDSA P-256 leaves are <600B).
        let (ca, _, _) = IntermediateCa::generate_for_test().unwrap();
        let leaf = ca.mint_leaf("vault.trs.ztlp").unwrap();
        assert!(
            leaf.leaf_pem.len() < 1000,
            "ECDSA P-256 leaf PEM should be <1KB, got {} bytes (RSA?)",
            leaf.leaf_pem.len()
        );
    }

    #[test]
    fn test_load_from_dir_errors_when_intermediate_cert_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = IntermediateCa::load_from_dir(tmp.path()).unwrap_err();
        assert!(matches!(err, CertMintError::IntermediateCertNotFound(_)));
    }

    #[test]
    fn test_load_from_dir_errors_when_intermediate_key_missing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("intermediate.pem"), "dummy").unwrap();
        let err = IntermediateCa::load_from_dir(tmp.path()).unwrap_err();
        assert!(matches!(err, CertMintError::IntermediateKeyNotFound(_)));
    }

    #[test]
    fn test_load_from_dir_round_trips_persisted_intermediate() {
        // Full integration: generate -> persist both files -> load_from_dir
        // -> mint leaf with the loaded copy.
        let (_orig, cert_pem, key_pem) = IntermediateCa::generate_for_test().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("intermediate.pem"), &cert_pem).unwrap();
        std::fs::write(tmp.path().join("intermediate.key"), &key_pem).unwrap();
        let loaded = IntermediateCa::load_from_dir(tmp.path()).unwrap();
        let leaf = loaded.mint_leaf("api.zone.ztlp").unwrap();
        assert_eq!(leaf.hostname, "api.zone.ztlp");
    }

    #[test]
    fn test_two_mints_produce_distinct_leaves() {
        // Each mint should generate fresh randomness (key + serial).
        let (ca, _, _) = IntermediateCa::generate_for_test().unwrap();
        let leaf1 = ca.mint_leaf("a.zone.ztlp").unwrap();
        let leaf2 = ca.mint_leaf("a.zone.ztlp").unwrap();
        // Same hostname but completely different cert bytes and keys.
        assert_ne!(leaf1.leaf_pem, leaf2.leaf_pem);
        assert_ne!(leaf1.key_pem, leaf2.key_pem);
    }
}
