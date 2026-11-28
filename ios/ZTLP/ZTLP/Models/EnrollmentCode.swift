// EnrollmentCode.swift
// Pure helpers for the enrollment form. No I/O, unit tested.

import Foundation

enum EnrollmentCode {
    static let prefix = "ztlp://enroll/"

    enum Problem: Error, Equatable {
        case empty
        case notAZTLPCode
        case incomplete

        var message: String {
            switch self {
            case .empty:
                return "Scan or paste your enrollment code."
            case .notAZTLPCode:
                return "That is not a ZTLP enrollment code. It should start with ztlp://enroll/"
            case .incomplete:
                return "The enrollment code is incomplete. Copy the whole code and try again."
            }
        }
    }

    /// Trim whatever surrounds a pasted or scanned code and check its shape.
    /// The Rust library does the real parsing; this only catches obvious
    /// mistakes before a network round trip.
    static func normalize(_ raw: String) -> Result<String, Problem> {
        // Codes never contain whitespace; mail clients like to wrap them.
        let text = raw.unicodeScalars
            .filter { !CharacterSet.whitespacesAndNewlines.contains($0) }
            .reduce(into: "") { $0.unicodeScalars.append($1) }
        guard !text.isEmpty else { return .failure(.empty) }
        guard text.count >= prefix.count,
              text.prefix(prefix.count).lowercased() == prefix else {
            return .failure(.notAZTLPCode)
        }
        let payload = text.dropFirst(prefix.count)
        // Either base64url data or the "?zone=...&token=..." form.
        guard payload.count >= 8, payload != "?" else { return .failure(.incomplete) }
        if payload.hasPrefix("?") {
            guard payload.contains("token=") else { return .failure(.incomplete) }
        }
        return .success(prefix + payload)
    }

    /// Code carried by a `ztlp://` URL that opened the app (for example from
    /// the system Camera), or nil when the URL is something else.
    static func fromIncomingURL(_ url: URL) -> String? {
        guard url.scheme?.lowercased() == "ztlp" else { return nil }
        if case .success(let code) = normalize(url.absoluteString) { return code }
        return nil
    }
}

enum DeviceName {
    static let maxLength = 40
    static let fallback = "iphone"

    /// Turn a free-form device name ("Steven’s iPhone 17 Pro") into a single
    /// DNS-style label ("stevens-iphone-17-pro"): lowercase ASCII letters,
    /// digits and inner hyphens only.
    static func clean(_ raw: String) -> String {
        let folded = raw.folding(
            options: [.diacriticInsensitive, .caseInsensitive, .widthInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        ).lowercased()

        var out = ""
        var pendingHyphen = false
        for scalar in folded.unicodeScalars {
            let isLetter = scalar.value >= 97 && scalar.value <= 122
            let isDigit = scalar.value >= 48 && scalar.value <= 57
            if isLetter || isDigit {
                let needsHyphen = pendingHyphen && !out.isEmpty
                if out.count + (needsHyphen ? 2 : 1) > maxLength { break }
                if needsHyphen { out.append("-") }
                pendingHyphen = false
                out.unicodeScalars.append(scalar)
            } else if scalar == "'" || scalar == "\u{2019}" || scalar == "\u{2018}" {
                // Apostrophes vanish: "steven's" -> "stevens".
                continue
            } else {
                pendingHyphen = true
            }
        }
        return out.isEmpty ? fallback : out
    }
}
