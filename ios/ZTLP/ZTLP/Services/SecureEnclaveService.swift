// SecureEnclaveService.swift
// ZTLP
//
// iOS Secure Enclave integration for hardware-backed ZTLP identity keys.
//
// The Secure Enclave stores a P-256 key pair that never leaves the hardware.
// ZTLP uses X25519 for Noise_XX, so we derive the X25519 key material from
// the P-256 key using a KDF (HKDF-SHA256). The P-256 key is used for signing
// enrollment tokens and identity verification.
//
// Key lifecycle:
//   1. On first launch, generate a P-256 key pair in the Secure Enclave.
//   2. The public key is exported and used as the ZTLP public key input.
//   3. For X25519 DH, we use ECDH with the P-256 key and derive the shared
//      secret with HKDF (the Rust side handles the X25519 ↔ P-256 bridge).
//   4. For signing, we use ECDSA with SHA-256 directly on the SE.
//
// The Secure Enclave requires:
//   - A device with Secure Enclave hardware (iPhone 5s+, iPad Air+)
//   - The key is bound to the device — cannot be exported or backed up
//   - Biometric/passcode protection is optional (we use .privateKeyUsage)

import Foundation
import Security
import CryptoKit

/// Errors from Secure Enclave operations.
enum SecureEnclaveError: LocalizedError {
    case notAvailable
    case keyGenerationFailed(String)
    case keyNotFound
    case signingFailed(String)
    case dhFailed(String)
    case publicKeyExportFailed
    case accessControlFailed

    var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Secure Enclave is not available on this device"
        case .keyGenerationFailed(let msg):
            return "Key generation failed: \(msg)"
        case .keyNotFound:
            return "Key not found in Secure Enclave"
        case .signingFailed(let msg):
            return "Signing failed: \(msg)"
        case .dhFailed(let msg):
            return "Key agreement failed: \(msg)"
        case .publicKeyExportFailed:
            return "Failed to export public key"
        case .accessControlFailed:
            return "Failed to create access control for Secure Enclave"
        }
    }
}

/// Service for Secure Enclave key operations.
///
/// This wraps CryptoKit's SecureEnclave.P256 APIs and provides the signing
/// and key-agreement callbacks that the ZTLP C library needs.
final class SecureEnclaveService {

    /// Shared singleton.
    static let shared = SecureEnclaveService()

    /// Tag for the ZTLP SE key in the keychain.
    private let keyTag = "com.ztlp.identity.secureenclave"

    /// App group for shared keychain access.
    private let accessGroup = "group.com.ztlp.shared"

    private init() {}

    // MARK: - Availability

    /// Check whether the Secure Enclave is available on this device.
    var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    // MARK: - Key Management

    /// Generate a new P-256 key pair in the Secure Enclave.
    ///
    /// If a key already exists with our tag, it is deleted first.
    ///
    /// - Returns: The raw public key bytes (65 bytes, uncompressed point).
    @discardableResult
    func generateKey() throws -> Data {
        guard isAvailable else { throw SecureEnclaveError.notAvailable }

        // Delete any existing key
        try? deleteKey()

        do {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
                compactRepresentable: false,
                accessControl: makeAccessControl(),
                authenticationContext: nil
            )

            // Store the key's data representation for later retrieval
            let keyData = privateKey.dataRepresentation
            try KeychainService.shared.save(data: keyData, forKey: keyTag)

            return Data(privateKey.publicKey.rawRepresentation)
        } catch let error as SecureEnclaveError {
            throw error
        } catch {
            throw SecureEnclaveError.keyGenerationFailed(error.localizedDescription)
        }
    }

    /// Load the existing Secure Enclave private key.
    ///
    /// - Returns: The SecureEnclave.P256.Signing.PrivateKey, or nil if not found.
    func loadPrivateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard isAvailable else { throw SecureEnclaveError.notAvailable }

        do {
            let keyData = try KeychainService.shared.load(forKey: keyTag)
            return try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: keyData,
                authenticationContext: nil
            )
        } catch is KeychainError {
            throw SecureEnclaveError.keyNotFound
        } catch {
            throw SecureEnclaveError.keyGenerationFailed(error.localizedDescription)
        }
    }

    /// Get the public key bytes of the existing SE key.
    func publicKey() throws -> Data {
        let privateKey = try loadPrivateKey()
        return Data(privateKey.publicKey.rawRepresentation)
    }

    /// Delete the Secure Enclave key.
    func deleteKey() throws {
        try? KeychainService.shared.delete(forKey: keyTag)
    }

    /// Check if a key exists in the Secure Enclave.
    func hasKey() -> Bool {
        guard isAvailable else { return false }
        return (try? loadPrivateKey()) != nil
    }

    // MARK: - Cryptographic Operations

    /// Sign data using the Secure Enclave P-256 key (ECDSA with SHA-256).
    ///
    /// This is used for:
    ///   - Enrollment token signing
    ///   - Identity verification proofs
    ///   - Name-service registration
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The DER-encoded ECDSA signature.
    func sign(data: Data) throws -> Data {
        let privateKey = try loadPrivateKey()
        do {
            let signature = try privateKey.signature(for: data)
            return Data(signature.derRepresentation)
        } catch {
            throw SecureEnclaveError.signingFailed(error.localizedDescription)
        }
    }

    /// Perform ECDH key agreement using the Secure Enclave key.
    ///
    /// The ZTLP protocol uses X25519 for Noise_XX, but the Secure Enclave
    /// only supports P-256. We perform ECDH on P-256 and derive the X25519-
    /// compatible shared secret using HKDF-SHA256.
    ///
    /// - Parameter theirPublicKeyData: The peer's P-256 public key (raw representation).
    /// - Returns: 32-byte derived shared secret compatible with X25519.
    func keyAgreement(theirPublicKeyData: Data) throws -> Data {
        let privateKey = try loadPrivateKey()

        guard let theirPublicKey = try? P256.KeyAgreement.PublicKey(
            rawRepresentation: theirPublicKeyData
        ) else {
            throw SecureEnclaveError.dhFailed("Invalid peer public key")
        }

        // Convert our signing key to a key-agreement key
        // (They share the same underlying SE key, just different CryptoKit types)
        let keyAgreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: privateKey.dataRepresentation,
            authenticationContext: nil
        )

        do {
            let sharedSecret = try keyAgreementKey.sharedSecretFromKeyAgreement(
                with: theirPublicKey
            )

            // Derive a 32-byte key using HKDF for X25519 compatibility
            let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("ztlp-x25519-bridge".utf8),
                sharedInfo: Data("ztlp-noise-xx".utf8),
                outputByteCount: 32
            )

            return derivedKey.withUnsafeBytes { Data($0) }
        } catch {
            throw SecureEnclaveError.dhFailed(error.localizedDescription)
        }
    }

    // MARK: - Helpers

    /// Create access control flags for the Secure Enclave key.
    ///
    /// We use `.privateKeyUsage` which allows signing without biometric prompt.
    /// For higher security, you could add `.biometryCurrentSet` or `.userPresence`.
    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            throw SecureEnclaveError.accessControlFailed
        }
        return access
    }
}
