// ConnectionStatus.swift
// ZTLP macOS
//
// Connection state model used throughout the app UI.
// Maps to the C library's ZTLP_STATE_* constants and the
// NetworkExtension's tunnel connection state.

import Foundation
import SwiftUI

/// The current state of the ZTLP VPN connection.
enum ConnectionStatus: Int, Equatable, Identifiable {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case reconnecting = 3
    case disconnecting = 4

    var id: Int { rawValue }

    /// Human-readable label.
    var label: String {
        switch self {
        case .disconnected:   return "Disconnected"
        case .connecting:     return "Connecting…"
        case .connected:      return "Connected"
        case .reconnecting:   return "Reconnecting…"
        case .disconnecting:  return "Disconnecting…"
        }
    }

    /// SF Symbol name for the status indicator.
    var systemImage: String {
        switch self {
        case .disconnected:   return "shield.slash"
        case .connecting:     return "shield.lefthalf.filled"
        case .connected:      return "shield.checkered"
        case .reconnecting:   return "arrow.triangle.2.circlepath"
        case .disconnecting:  return "shield.lefthalf.filled"
        }
    }

    /// Accent color for the status indicator.
    var color: Color {
        switch self {
        case .disconnected:   return .secondary
        case .connecting:     return .orange
        case .connected:      return .green
        case .reconnecting:   return .orange
        case .disconnecting:  return .orange
        }
    }

    /// Whether the user can initiate a connect action.
    var canConnect: Bool {
        self == .disconnected
    }

    /// Whether the user can initiate a disconnect action.
    var canDisconnect: Bool {
        self == .connected || self == .reconnecting
    }

    /// Whether the connection is active (sending/receiving data).
    var isActive: Bool {
        self == .connected
    }

    /// Whether a transition animation should be shown.
    var isTransitioning: Bool {
        self == .connecting || self == .reconnecting || self == .disconnecting
    }
}

/// Traffic statistics for display in the UI.
struct TrafficStats: Equatable {
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
    var connectedSince: Date?

    /// Duration of the current connection.
    var duration: TimeInterval? {
        guard let since = connectedSince else { return nil }
        return Date().timeIntervalSince(since)
    }

    /// Formatted bytes sent (e.g., "1.2 MB").
    var formattedBytesSent: String {
        ByteCountFormatter.string(fromByteCount: Int64(bytesSent), countStyle: .binary)
    }

    /// Formatted bytes received (e.g., "3.4 MB").
    var formattedBytesReceived: String {
        ByteCountFormatter.string(fromByteCount: Int64(bytesReceived), countStyle: .binary)
    }

    /// Formatted connection duration (e.g., "01:23:45").
    var formattedDuration: String {
        guard let duration = duration else { return "--:--:--" }
        let hours = Int(duration) / 3600
        let minutes = (Int(duration) % 3600) / 60
        let seconds = Int(duration) % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }
}
