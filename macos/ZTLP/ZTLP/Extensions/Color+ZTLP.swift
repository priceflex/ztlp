// Color+ZTLP.swift
// ZTLP macOS
//
// Brand colors for the ZTLP app.

import SwiftUI

extension Color {
    /// ZTLP brand blue (#0284c7 — sky-600).
    static let ztlpBlue = Color(red: 2.0 / 255.0, green: 132.0 / 255.0, blue: 199.0 / 255.0)

    /// Darker ZTLP blue for pressed states (#0369a1 — sky-700).
    static let ztlpBlueDark = Color(red: 3.0 / 255.0, green: 105.0 / 255.0, blue: 161.0 / 255.0)

    /// Lighter ZTLP blue for backgrounds (#e0f2fe — sky-100).
    static let ztlpBlueLight = Color(red: 224.0 / 255.0, green: 242.0 / 255.0, blue: 254.0 / 255.0)

    /// Connected green (#22c55e — green-500).
    static let ztlpGreen = Color(red: 34.0 / 255.0, green: 197.0 / 255.0, blue: 94.0 / 255.0)

    /// Warning/reconnecting orange (#f97316 — orange-500).
    static let ztlpOrange = Color(red: 249.0 / 255.0, green: 115.0 / 255.0, blue: 22.0 / 255.0)

    /// Error red (#ef4444 — red-500).
    static let ztlpRed = Color(red: 239.0 / 255.0, green: 68.0 / 255.0, blue: 68.0 / 255.0)
}
