// Color+ZTLP.swift
// ZTLP
//
// Brand colors and design system for the ZTLP iOS app.

import SwiftUI

// MARK: - Brand Colors

extension Color {
    /// Primary brand blue — used for interactive elements, links, tab tint.
    static let ztlpBlue = Color(red: 0.008, green: 0.518, blue: 0.780)
    
    /// Dark variant of brand blue — used for pressed states and dark mode accents.
    static let ztlpBlueDark = Color(red: 0.004, green: 0.388, blue: 0.620)
    
    /// Light variant of brand blue — used for backgrounds and subtle highlights.
    static let ztlpBlueLight = Color(red: 0.133, green: 0.647, blue: 0.875)
    
    /// Success green — connected state, reachable indicators.
    static let ztlpGreen = Color(red: 0.133, green: 0.773, blue: 0.369)
    
    /// Warning orange — connecting, reconnecting states.
    static let ztlpOrange = Color(red: 0.976, green: 0.451, blue: 0.086)
    
    /// Error red — disconnected state, errors, unreachable indicators.
    static let ztlpRed = Color(red: 0.937, green: 0.267, blue: 0.267)
    
    /// Subtle surface color for cards and grouped sections.
    static let ztlpSurface = Color(.systemGray6)
    
    /// Muted text color for labels and descriptions.
    static let ztlpMuted = Color(.systemGray)
}

// MARK: - Gradients

extension LinearGradient {
    /// Hero gradient for the connection ring and status displays.
    static let ztlpShield = LinearGradient(
        colors: [Color.ztlpBlue, Color.ztlpBlueLight],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    
    /// Connected state gradient — vibrant green to blue.
    static let ztlpConnected = LinearGradient(
        colors: [Color.ztlpGreen, Color.ztlpBlue],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    
    /// Disconnected state gradient — muted grays.
    static let ztlpDisconnected = LinearGradient(
        colors: [Color.gray.opacity(0.4), Color.gray.opacity(0.2)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    
    /// Connecting/transitioning state gradient.
    static let ztlpTransitioning = LinearGradient(
        colors: [Color.ztlpOrange, Color.ztlpBlue],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    
    /// Card background gradient — subtle depth.
    static let ztlpCard = LinearGradient(
        colors: [
            Color(.systemBackground),
            Color(.systemGray6).opacity(0.5)
        ],
        startPoint: .top,
        endPoint: .bottom
    )
}

// MARK: - View Modifiers

extension View {
    /// Apply ZTLP card styling with rounded corners and subtle shadow.
    func ztlpCard(padding: CGFloat = 16) -> some View {
        self
            .padding(padding)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(.ultraThinMaterial)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(Color.ztlpBlue.opacity(0.1), lineWidth: 0.5)
            )
    }
    
    /// Apply ZTLP section header styling.
    func ztlpSectionHeader() -> some View {
        self
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Color.ztlpBlue)
            .textCase(.uppercase)
            .tracking(0.5)
    }
}

// MARK: - Connection Status Gradient Helper

extension ConnectionStatus {
    /// Gradient matching the connection state.
    var gradient: LinearGradient {
        switch self {
        case .connected:     return .ztlpConnected
        case .disconnected:  return .ztlpDisconnected
        default:             return .ztlpTransitioning
        }
    }
}
