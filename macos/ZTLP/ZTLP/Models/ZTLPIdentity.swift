// ZTLPIdentity.swift
// ZTLP macOS
//
// Swift model wrapping ZTLP identity information.
// This is a pure data model — actual FFI operations go through ZTLPBridge.

import Foundation

/// Represents a ZTLP node identity.
struct ZTLPIdentityInfo: Identifiable, Equatable, Codable {
    /// The hex-encoded Node ID (32 hex chars = 16 bytes).
    let nodeId: String

    /// The hex-encoded X25519 public key (64 hex chars = 32 bytes).
    let publicKey: String

    /// Identity provider type: "software", "secure_enclave", "android_keystore".
    let providerType: String

    /// When this identity was first created/loaded.
    let createdAt: Date

    /// Optional zone name this identity is enrolled in.
    var zoneName: String?

    /// Optional human-readable label.
    var label: String?

    var id: String { nodeId }

    /// Abbreviated Node ID for display (first 8 + last 4 hex chars).
    var shortNodeId: String {
        guard nodeId.count >= 12 else { return nodeId }
        let prefix = nodeId.prefix(8)
        let suffix = nodeId.suffix(4)
        return "\(prefix)…\(suffix)"
    }

    /// Abbreviated public key for display.
    var shortPublicKey: String {
        guard publicKey.count >= 12 else { return publicKey }
        let prefix = publicKey.prefix(8)
        let suffix = publicKey.suffix(4)
        return "\(prefix)…\(suffix)"
    }

    /// Whether this identity is backed by hardware (Secure Enclave).
    var isHardwareBacked: Bool {
        providerType == "secure_enclave"
    }
}

extension ZTLPIdentityInfo {
    /// Create from a ZTLPIdentityHandle (populated by the FFI bridge).
    static func from(handle: ZTLPIdentityHandle, providerType: String = "software") -> ZTLPIdentityInfo? {
        guard let nodeId = handle.nodeId, let publicKey = handle.publicKey else {
            return nil
        }
        return ZTLPIdentityInfo(
            nodeId: nodeId,
            publicKey: publicKey,
            providerType: providerType,
            createdAt: Date()
        )
    }
}
