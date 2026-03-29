use ztlp_proto::pqkem::*;

// ─── X25519Kem Tests ─────────────────────────────────────

#[test]
fn x25519_keygen_produces_32_byte_keys() {
    let kem = X25519Kem::new();
    let (pk, sk) = kem.keygen();
    assert_eq!(pk.0.len(), 32, "public key should be 32 bytes");
    assert_eq!(sk.0.len(), 32, "secret key should be 32 bytes");
}

#[test]
fn x25519_encapsulate_produces_32_byte_ct_and_ss() {
    let kem = X25519Kem::new();
    let (pk, _sk) = kem.keygen();
    let (ct, ss) = kem.encapsulate(&pk).expect("encapsulate should succeed");
    assert_eq!(ct.0.len(), 32, "ciphertext should be 32 bytes");
    assert_eq!(ss.0.len(), 32, "shared secret should be 32 bytes");
}

#[test]
fn x25519_encapsulate_rejects_wrong_size_pk() {
    let kem = X25519Kem::new();
    let bad_pk = KemPublicKey(vec![0u8; 16]);
    let err = kem.encapsulate(&bad_pk).unwrap_err();
    assert_eq!(
        err,
        KemError::KeySizeMismatch {
            expected: 32,
            got: 16
        }
    );
}

#[test]
fn x25519_decapsulate_rejects_wrong_size_sk() {
    let kem = X25519Kem::new();
    let bad_sk = KemSecretKey(vec![0u8; 16]);
    let ct = KemCiphertext(vec![0u8; 32]);
    let err = kem.decapsulate(&bad_sk, &ct).unwrap_err();
    assert_eq!(err, KemError::InvalidSecretKey);
}

#[test]
fn x25519_decapsulate_rejects_wrong_size_ct() {
    let kem = X25519Kem::new();
    let (_pk, sk) = kem.keygen();
    let bad_ct = KemCiphertext(vec![0u8; 64]);
    let err = kem.decapsulate(&sk, &bad_ct).unwrap_err();
    assert_eq!(err, KemError::InvalidCiphertext);
}

#[test]
fn x25519_encapsulate_decapsulate_shared_secrets_match() {
    // X25519 KEM: encapsulate produces (eph_pk, shared), decapsulate with sk should
    // produce the same shared secret because DH is commutative:
    //   encaps: shared = eph_sk * pk = eph_sk * (sk * G)
    //   decaps: shared = sk * eph_pk = sk * (eph_sk * G)
    let kem = X25519Kem::new();
    let (pk, sk) = kem.keygen();
    let (ct, enc_ss) = kem.encapsulate(&pk).expect("encapsulate");
    let dec_ss = kem.decapsulate(&sk, &ct).expect("decapsulate");
    assert_eq!(
        enc_ss.as_bytes(),
        dec_ss.as_bytes(),
        "encapsulate and decapsulate should produce the same shared secret"
    );
}

#[test]
fn x25519_keygen_produces_different_keys_each_call() {
    let kem = X25519Kem::new();
    let (pk1, _sk1) = kem.keygen();
    let (pk2, _sk2) = kem.keygen();
    assert_ne!(
        pk1.0, pk2.0,
        "two keygen calls should produce different public keys"
    );
}

// ─── MlKemPlaceholder Tests ─────────────────────────────

#[test]
fn mlkem_keygen_produces_correct_size_keys() {
    let kem = MlKemPlaceholder::new();
    let (pk, sk) = kem.keygen();
    assert_eq!(
        pk.0.len(),
        1184,
        "ML-KEM-768 public key should be 1184 bytes"
    );
    assert_eq!(
        sk.0.len(),
        2400,
        "ML-KEM-768 secret key should be 2400 bytes"
    );
}

#[test]
fn mlkem_encapsulate_produces_correct_size_ct_and_ss() {
    let kem = MlKemPlaceholder::new();
    let (pk, _sk) = kem.keygen();
    let (ct, ss) = kem.encapsulate(&pk).expect("encapsulate should succeed");
    assert_eq!(ct.0.len(), 1088, "ciphertext should be 1088 bytes");
    assert_eq!(ss.0.len(), 32, "shared secret should be 32 bytes");
}

#[test]
fn mlkem_encapsulate_rejects_wrong_size_pk() {
    let kem = MlKemPlaceholder::new();
    let bad_pk = KemPublicKey(vec![0u8; 999]);
    let err = kem.encapsulate(&bad_pk).unwrap_err();
    assert_eq!(
        err,
        KemError::KeySizeMismatch {
            expected: 1184,
            got: 999
        }
    );
}

#[test]
fn mlkem_decapsulate_rejects_wrong_size_sk() {
    let kem = MlKemPlaceholder::new();
    let bad_sk = KemSecretKey(vec![0u8; 100]);
    let ct = KemCiphertext(vec![0u8; 1088]);
    let err = kem.decapsulate(&bad_sk, &ct).unwrap_err();
    assert_eq!(err, KemError::InvalidSecretKey);
}

#[test]
fn mlkem_decapsulate_rejects_wrong_size_ct() {
    let kem = MlKemPlaceholder::new();
    let (_pk, sk) = kem.keygen();
    let bad_ct = KemCiphertext(vec![0u8; 500]);
    let err = kem.decapsulate(&sk, &bad_ct).unwrap_err();
    assert_eq!(err, KemError::InvalidCiphertext);
}

// ─── HybridKem Tests ─────────────────────────────────────

#[test]
fn hybrid_keygen_produces_both_keypairs() {
    let hybrid = HybridKem::default_hybrid();
    let kp = hybrid.keygen();
    assert_eq!(kp.classical_pk.0.len(), 32);
    assert_eq!(kp.classical_sk.0.len(), 32);
    assert_eq!(kp.pq_pk.0.len(), 1184);
    assert_eq!(kp.pq_sk.0.len(), 2400);
}

#[test]
fn hybrid_encapsulate_decapsulate_no_error() {
    // The ML-KEM placeholder shared secret won't match between encaps/decaps
    // because encaps uses BLAKE2s(ct || pk) and decaps uses BLAKE2s(ct || pk_hash).
    // But neither operation should error.
    let hybrid = HybridKem::default_hybrid();
    let kp = hybrid.keygen();
    let (ct, _enc_ss) = hybrid
        .encapsulate(&kp.classical_pk, &kp.pq_pk)
        .expect("hybrid encapsulate should not error");
    let _dec_ss = hybrid
        .decapsulate(&kp, &ct)
        .expect("hybrid decapsulate should not error");
}

#[test]
fn hybrid_name_combines_both_names() {
    let hybrid = HybridKem::default_hybrid();
    assert_eq!(hybrid.name(), "X25519+ML-KEM-768-placeholder");
}

// ─── combine_secrets Tests ───────────────────────────────

#[test]
fn combine_secrets_is_deterministic() {
    let ss1 = KemSharedSecret(vec![1u8; 32]);
    let ss2 = KemSharedSecret(vec![2u8; 32]);
    let combined_a = combine_secrets(&ss1, &ss2);
    let combined_b = combine_secrets(&ss1, &ss2);
    assert_eq!(combined_a.0, combined_b.0);
}

#[test]
fn combine_secrets_differs_when_inputs_differ() {
    let ss1 = KemSharedSecret(vec![1u8; 32]);
    let ss2 = KemSharedSecret(vec![2u8; 32]);
    let ss3 = KemSharedSecret(vec![3u8; 32]);
    let combined_a = combine_secrets(&ss1, &ss2);
    let combined_b = combine_secrets(&ss1, &ss3);
    assert_ne!(combined_a.0, combined_b.0);
}

// ─── KemAlgorithm Tests ─────────────────────────────────

#[test]
fn kem_algorithm_from_byte_to_byte_roundtrip() {
    for byte in [0x01, 0x02, 0x03] {
        let algo = KemAlgorithm::from_byte(byte).unwrap();
        assert_eq!(algo.to_byte(), byte);
    }
}

#[test]
fn kem_algorithm_is_post_quantum() {
    assert!(!KemAlgorithm::X25519.is_post_quantum());
    assert!(KemAlgorithm::MlKem768.is_post_quantum());
    assert!(KemAlgorithm::HybridX25519MlKem768.is_post_quantum());
}

#[test]
fn kem_algorithm_from_byte_returns_none_for_unknown() {
    assert_eq!(KemAlgorithm::from_byte(0x00), None);
    assert_eq!(KemAlgorithm::from_byte(0x04), None);
    assert_eq!(KemAlgorithm::from_byte(0xFF), None);
}

// ─── Debug / Display Tests ──────────────────────────────

#[test]
fn kem_secret_key_debug_redacts_contents() {
    let sk = KemSecretKey(vec![0xAA; 32]);
    let debug = format!("{:?}", sk);
    assert!(
        debug.contains("REDACTED"),
        "debug should contain REDACTED, got: {debug}"
    );
    assert!(debug.contains("32"), "debug should contain byte count");
    assert!(
        !debug.contains("aa") && !debug.contains("AA") && !debug.contains("170"),
        "debug should not leak key bytes"
    );
}

#[test]
fn kem_shared_secret_debug_redacts_contents() {
    let ss = KemSharedSecret(vec![0xBB; 32]);
    let debug = format!("{:?}", ss);
    assert!(
        debug.contains("REDACTED"),
        "debug should contain REDACTED, got: {debug}"
    );
    assert!(debug.contains("32"), "debug should contain byte count");
    assert!(
        !debug.contains("bb") && !debug.contains("BB") && !debug.contains("187"),
        "debug should not leak secret bytes"
    );
}

#[test]
fn kem_shared_secret_as_bytes_len_is_empty() {
    let ss = KemSharedSecret(vec![1, 2, 3]);
    assert_eq!(ss.as_bytes(), &[1, 2, 3]);
    assert_eq!(ss.len(), 3);
    assert!(!ss.is_empty());

    let empty = KemSharedSecret(vec![]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

// ─── BLAKE2s Tests ───────────────────────────────────────

#[test]
fn blake2s_256_produces_32_byte_output() {
    let out = blake2s_256_hash(b"hello");
    assert_eq!(out.len(), 32);
}

#[test]
fn blake2s_256_is_deterministic() {
    let a = blake2s_256_hash(b"test input");
    let b = blake2s_256_hash(b"test input");
    assert_eq!(a, b);
}

#[test]
fn blake2s_256_produces_different_outputs_for_different_inputs() {
    let a = blake2s_256_hash(b"input A");
    let b = blake2s_256_hash(b"input B");
    assert_ne!(a, b);
}

// ─── Trait Properties ────────────────────────────────────

#[test]
fn x25519_kem_size_methods() {
    let kem = X25519Kem::new();
    assert_eq!(kem.public_key_size(), 32);
    assert_eq!(kem.ciphertext_size(), 32);
    assert_eq!(kem.shared_secret_size(), 32);
    assert_eq!(kem.name(), "X25519");
}

#[test]
fn mlkem_placeholder_size_methods() {
    let kem = MlKemPlaceholder::new();
    assert_eq!(kem.public_key_size(), 1184);
    assert_eq!(kem.ciphertext_size(), 1088);
    assert_eq!(kem.shared_secret_size(), 32);
    assert_eq!(kem.name(), "ML-KEM-768-placeholder");
}

#[test]
fn kem_error_display() {
    assert_eq!(
        format!("{}", KemError::InvalidPublicKey),
        "invalid public key"
    );
    assert_eq!(
        format!("{}", KemError::InvalidCiphertext),
        "invalid ciphertext"
    );
    assert_eq!(
        format!("{}", KemError::DecapsulationFailed),
        "decapsulation failed"
    );
    assert_eq!(
        format!("{}", KemError::InvalidSecretKey),
        "invalid secret key"
    );
    assert_eq!(
        format!(
            "{}",
            KemError::KeySizeMismatch {
                expected: 32,
                got: 16
            }
        ),
        "key size mismatch: expected 32, got 16"
    );
}
