//! Post-Quantum Key Encapsulation Mechanism (KEM) framework for ZTLP.
//!
//! Provides a hybrid KEM combining classical X25519 with a post-quantum
//! KEM (ML-KEM/Kyber placeholder) for quantum-resistant key exchange.
//!
//! Architecture:
//! - [`Kem`] trait: generic KEM interface
//! - [`X25519Kem`]: classical KEM using X25519 Diffie-Hellman
//! - [`MlKemPlaceholder`]: API-compatible ML-KEM stub (random bytes)
//! - [`HybridKem`]: combines two KEMs with BLAKE2s key combiner
//!
//! The hybrid approach ensures security even if one KEM is broken:
//! `combined_key = BLAKE2s(x25519_shared || pq_shared || "ztlp-hybrid-kem-v1")`

use std::fmt;

use blake2::{Blake2s256, Digest};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

// ─── Core Types ──────────────────────────────────────────

/// KEM public key (variable-length).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey(pub Vec<u8>);

/// KEM secret key (variable-length, debug-redacted).
#[derive(Clone)]
pub struct KemSecretKey(pub Vec<u8>);

/// KEM ciphertext (encapsulated shared secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemCiphertext(pub Vec<u8>);

/// KEM shared secret (debug-redacted).
#[derive(Clone)]
pub struct KemSharedSecret(pub Vec<u8>);

impl KemSharedSecret {
    /// Raw bytes of the shared secret.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the shared secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecretKey([REDACTED {} bytes])", self.0.len())
    }
}

impl fmt::Debug for KemSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSharedSecret([REDACTED {} bytes])", self.0.len())
    }
}

// ─── Error ───────────────────────────────────────────────

/// Errors that can occur during KEM operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// The supplied public key is malformed or invalid.
    InvalidPublicKey,
    /// The supplied ciphertext is malformed or invalid.
    InvalidCiphertext,
    /// Decapsulation failed (e.g. ciphertext doesn't match keypair).
    DecapsulationFailed,
    /// The supplied secret key is malformed or invalid.
    InvalidSecretKey,
    /// Key/ciphertext size doesn't match the expected size for this KEM.
    KeySizeMismatch { expected: usize, got: usize },
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidCiphertext => write!(f, "invalid ciphertext"),
            Self::DecapsulationFailed => write!(f, "decapsulation failed"),
            Self::InvalidSecretKey => write!(f, "invalid secret key"),
            Self::KeySizeMismatch { expected, got } => {
                write!(f, "key size mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for KemError {}

// ─── KEM Trait ───────────────────────────────────────────

/// Trait for Key Encapsulation Mechanisms.
pub trait Kem: Send + Sync {
    /// Algorithm name.
    fn name(&self) -> &str;

    /// Generate a fresh keypair.
    fn keygen(&self) -> (KemPublicKey, KemSecretKey);

    /// Encapsulate: given a public key, produce `(ciphertext, shared_secret)`.
    fn encapsulate(&self, pk: &KemPublicKey) -> Result<(KemCiphertext, KemSharedSecret), KemError>;

    /// Decapsulate: given a secret key and ciphertext, recover the shared secret.
    fn decapsulate(
        &self,
        sk: &KemSecretKey,
        ct: &KemCiphertext,
    ) -> Result<KemSharedSecret, KemError>;

    /// Public key size in bytes.
    fn public_key_size(&self) -> usize;

    /// Ciphertext size in bytes.
    fn ciphertext_size(&self) -> usize;

    /// Shared secret size in bytes.
    fn shared_secret_size(&self) -> usize;
}

// ─── X25519 KEM ──────────────────────────────────────────

/// Classical X25519 Diffie-Hellman wrapped as a KEM.
///
/// - **Keygen**: generate a random X25519 keypair.
/// - **Encapsulate**: generate an ephemeral keypair, DH with recipient's public key.
/// - **Decapsulate**: DH with the sender's ephemeral public key (the ciphertext).
pub struct X25519Kem;

impl X25519Kem {
    /// Create a new `X25519Kem` instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for X25519Kem {
    fn default() -> Self {
        Self::new()
    }
}

/// Clamp a 32-byte scalar per the X25519 spec (RFC 7748).
fn x25519_clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Generate an X25519 keypair using `curve25519-dalek`.
fn x25519_keygen() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk_bytes = x25519_clamp(sk_bytes);
    let scalar = Scalar::from_bytes_mod_order(sk_bytes);
    let pk = MontgomeryPoint::mul_base(&scalar);
    (pk.to_bytes(), sk_bytes)
}

/// X25519 scalar multiplication: `sk * pk`.
fn x25519_dh(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*sk);
    let point = MontgomeryPoint(*pk);
    (scalar * point).to_bytes()
}

impl Kem for X25519Kem {
    fn name(&self) -> &str {
        "X25519"
    }

    fn keygen(&self) -> (KemPublicKey, KemSecretKey) {
        let (pk, sk) = x25519_keygen();
        (KemPublicKey(pk.to_vec()), KemSecretKey(sk.to_vec()))
    }

    fn encapsulate(&self, pk: &KemPublicKey) -> Result<(KemCiphertext, KemSharedSecret), KemError> {
        if pk.0.len() != 32 {
            return Err(KemError::KeySizeMismatch {
                expected: 32,
                got: pk.0.len(),
            });
        }

        // Ephemeral keypair
        let (eph_pk, eph_sk) = x25519_keygen();

        // DH: shared = eph_sk * recipient_pk
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk.0);
        let shared = x25519_dh(&eph_sk, &pk_arr);

        // Ciphertext = ephemeral public key
        Ok((
            KemCiphertext(eph_pk.to_vec()),
            KemSharedSecret(shared.to_vec()),
        ))
    }

    fn decapsulate(
        &self,
        sk: &KemSecretKey,
        ct: &KemCiphertext,
    ) -> Result<KemSharedSecret, KemError> {
        if sk.0.len() != 32 {
            return Err(KemError::InvalidSecretKey);
        }
        if ct.0.len() != 32 {
            return Err(KemError::InvalidCiphertext);
        }

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk.0);
        let mut ct_arr = [0u8; 32];
        ct_arr.copy_from_slice(&ct.0);
        let shared = x25519_dh(&sk_arr, &ct_arr);

        Ok(KemSharedSecret(shared.to_vec()))
    }

    fn public_key_size(&self) -> usize {
        32
    }
    fn ciphertext_size(&self) -> usize {
        32
    }
    fn shared_secret_size(&self) -> usize {
        32
    }
}

// ─── ML-KEM Placeholder ─────────────────────────────────

/// ML-KEM (Kyber) placeholder — correct API shape, random bytes for crypto.
///
/// Key sizes match ML-KEM-768 (NIST Level 3):
/// - Public key: 1184 bytes
/// - Secret key: 2400 bytes
/// - Ciphertext: 1088 bytes
/// - Shared secret: 32 bytes
///
/// **IMPORTANT**: This is NOT real ML-KEM. It uses random bytes for key material
/// and BLAKE2s for "shared secrets". Replace with `ml-kem` crate for production.
pub struct MlKemPlaceholder;

impl MlKemPlaceholder {
    /// Create a new ML-KEM placeholder instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for MlKemPlaceholder {
    fn default() -> Self {
        Self::new()
    }
}

/// BLAKE2s-256 convenience wrapper using the `blake2` crate.
fn blake2s_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

impl Kem for MlKemPlaceholder {
    fn name(&self) -> &str {
        "ML-KEM-768-placeholder"
    }

    fn keygen(&self) -> (KemPublicKey, KemSecretKey) {
        let mut rng = rand::thread_rng();
        let mut pk = vec![0u8; 1184];
        let mut sk = vec![0u8; 2400];
        rng.fill_bytes(&mut pk);
        rng.fill_bytes(&mut sk);
        // Store pk hash in the first 32 bytes of sk for encaps/decaps matching.
        let pk_hash = blake2s_hash(&pk);
        sk[..32].copy_from_slice(&pk_hash);
        (KemPublicKey(pk), KemSecretKey(sk))
    }

    fn encapsulate(&self, pk: &KemPublicKey) -> Result<(KemCiphertext, KemSharedSecret), KemError> {
        if pk.0.len() != 1184 {
            return Err(KemError::KeySizeMismatch {
                expected: 1184,
                got: pk.0.len(),
            });
        }

        let mut rng = rand::thread_rng();
        let mut ct = vec![0u8; 1088];
        rng.fill_bytes(&mut ct);
        // Embed pk hash so decapsulate can verify.
        let pk_hash = blake2s_hash(&pk.0);
        ct[..32].copy_from_slice(&pk_hash);

        // Shared secret = BLAKE2s(ct || pk)
        let mut input = Vec::with_capacity(ct.len() + pk.0.len());
        input.extend_from_slice(&ct);
        input.extend_from_slice(&pk.0);
        let ss = blake2s_hash(&input);

        Ok((KemCiphertext(ct), KemSharedSecret(ss.to_vec())))
    }

    fn decapsulate(
        &self,
        sk: &KemSecretKey,
        ct: &KemCiphertext,
    ) -> Result<KemSharedSecret, KemError> {
        if sk.0.len() != 2400 {
            return Err(KemError::InvalidSecretKey);
        }
        if ct.0.len() != 1088 {
            return Err(KemError::InvalidCiphertext);
        }
        // Verify pk_hash matches
        if ct.0[..32] != sk.0[..32] {
            return Err(KemError::DecapsulationFailed);
        }
        // Deterministic shared secret from ct + pk_hash (sk prefix).
        // In real ML-KEM this would be lattice-based decapsulation.
        let mut input = Vec::with_capacity(ct.0.len() + 32);
        input.extend_from_slice(&ct.0);
        input.extend_from_slice(&sk.0[..32]);
        let ss = blake2s_hash(&input);
        Ok(KemSharedSecret(ss.to_vec()))
    }

    fn public_key_size(&self) -> usize {
        1184
    }
    fn ciphertext_size(&self) -> usize {
        1088
    }
    fn shared_secret_size(&self) -> usize {
        32
    }
}

// ─── Hybrid KEM ──────────────────────────────────────────

/// Hybrid KEM: combines two KEMs for defense-in-depth.
///
/// `combined_secret = BLAKE2s(classical_ss || pq_ss || "ztlp-hybrid-kem-v1")`
///
/// If either KEM is broken, the other still provides security.
pub struct HybridKem {
    classical: Box<dyn Kem>,
    post_quantum: Box<dyn Kem>,
}

/// Hybrid keypair — holds both classical and post-quantum keypairs.
pub struct HybridKeypair {
    pub classical_pk: KemPublicKey,
    pub classical_sk: KemSecretKey,
    pub pq_pk: KemPublicKey,
    pub pq_sk: KemSecretKey,
}

/// Hybrid ciphertext — holds both classical and post-quantum ciphertexts.
pub struct HybridCiphertext {
    pub classical_ct: KemCiphertext,
    pub pq_ct: KemCiphertext,
}

impl HybridKem {
    /// Create a hybrid KEM from a classical and a post-quantum KEM.
    pub fn new(classical: Box<dyn Kem>, post_quantum: Box<dyn Kem>) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }

    /// Default hybrid: X25519 + ML-KEM-768 placeholder.
    pub fn default_hybrid() -> Self {
        Self::new(
            Box::new(X25519Kem::new()),
            Box::new(MlKemPlaceholder::new()),
        )
    }

    /// Generate hybrid keypair (classical + post-quantum).
    pub fn keygen(&self) -> HybridKeypair {
        let (cpk, csk) = self.classical.keygen();
        let (ppk, psk) = self.post_quantum.keygen();
        HybridKeypair {
            classical_pk: cpk,
            classical_sk: csk,
            pq_pk: ppk,
            pq_sk: psk,
        }
    }

    /// Encapsulate against both classical and post-quantum public keys.
    pub fn encapsulate(
        &self,
        classical_pk: &KemPublicKey,
        pq_pk: &KemPublicKey,
    ) -> Result<(HybridCiphertext, KemSharedSecret), KemError> {
        let (c_ct, c_ss) = self.classical.encapsulate(classical_pk)?;
        let (p_ct, p_ss) = self.post_quantum.encapsulate(pq_pk)?;

        let combined = combine_secrets(&c_ss, &p_ss);

        Ok((
            HybridCiphertext {
                classical_ct: c_ct,
                pq_ct: p_ct,
            },
            combined,
        ))
    }

    /// Decapsulate using both classical and post-quantum secret keys.
    pub fn decapsulate(
        &self,
        keypair: &HybridKeypair,
        ct: &HybridCiphertext,
    ) -> Result<KemSharedSecret, KemError> {
        let c_ss = self
            .classical
            .decapsulate(&keypair.classical_sk, &ct.classical_ct)?;
        let p_ss = self.post_quantum.decapsulate(&keypair.pq_sk, &ct.pq_ct)?;

        Ok(combine_secrets(&c_ss, &p_ss))
    }

    /// Algorithm name (e.g. `"X25519+ML-KEM-768-placeholder"`).
    pub fn name(&self) -> String {
        format!("{}+{}", self.classical.name(), self.post_quantum.name())
    }
}

/// Combine two shared secrets using domain-separated BLAKE2s.
pub fn combine_secrets(ss1: &KemSharedSecret, ss2: &KemSharedSecret) -> KemSharedSecret {
    let domain = b"ztlp-hybrid-kem-v1";
    let mut input = Vec::with_capacity(ss1.0.len() + ss2.0.len() + domain.len());
    input.extend_from_slice(&ss1.0);
    input.extend_from_slice(&ss2.0);
    input.extend_from_slice(domain);
    KemSharedSecret(blake2s_hash(&input).to_vec())
}

// ─── Algorithm Negotiation ───────────────────────────────

/// Supported KEM algorithms for handshake negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// Classical X25519 only.
    X25519,
    /// Post-quantum ML-KEM-768 only.
    MlKem768,
    /// Hybrid X25519 + ML-KEM-768.
    HybridX25519MlKem768,
}

impl KemAlgorithm {
    /// Human-readable algorithm name.
    pub fn name(&self) -> &str {
        match self {
            Self::X25519 => "X25519",
            Self::MlKem768 => "ML-KEM-768",
            Self::HybridX25519MlKem768 => "X25519+ML-KEM-768",
        }
    }

    /// Whether this algorithm provides post-quantum resistance.
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::MlKem768 | Self::HybridX25519MlKem768)
    }

    /// Decode from a single-byte wire format.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::X25519),
            0x02 => Some(Self::MlKem768),
            0x03 => Some(Self::HybridX25519MlKem768),
            _ => None,
        }
    }

    /// Encode to a single-byte wire format.
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::X25519 => 0x01,
            Self::MlKem768 => 0x02,
            Self::HybridX25519MlKem768 => 0x03,
        }
    }
}

// ─── Public helpers (for tests) ──────────────────────────

/// Re-export BLAKE2s-256 for internal test use.
#[doc(hidden)]
pub fn blake2s_256_hash(data: &[u8]) -> [u8; 32] {
    blake2s_hash(data)
}
