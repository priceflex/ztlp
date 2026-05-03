// ZTLPBridge.swift
// ZTLP
//
// Removed in the Nebula-style pivot (S1.5).
//
// The legacy in-process ZTLPBridge drove 11 tokio-runtime FFIs
// (ztlp_router_new / ztlp_connect / ztlp_send / ztlp_tunnel_start /
// ztlp_set_recv_callback / …) that R4 deleted. In the new dual-lib
// architecture the main app no longer touches the ZTLP Rust libs
// directly — all tunnel I/O runs inside the Network Extension
// (ZTLPTunnel target → PacketTunnelProvider → ZTLPTunnelConnection).
//
// The file is retained (empty) to keep the Xcode pbxproj reference
// valid without surgical project-file edits. Delete the pbxproj
// entries and remove this file in a later cleanup pass.

import Foundation
