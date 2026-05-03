// NetworkBenchmark.swift
// ZTLP
//
// Removed in the Nebula-style pivot (S1.5).
//
// The in-process network benchmark drove ZTLPBridge directly
// (ztlp_connect / ztlp_send / ns_resolve) from the main app. That
// path no longer exists — the real benchmark now runs through the
// Network Extension. See the handoff docs for the new benchmark
// surface.
//
// File retained empty for pbxproj stability.

import Foundation
