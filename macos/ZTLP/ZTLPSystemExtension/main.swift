// main.swift
// ZTLPSystemExtension
//
// Entry point for the system extension process.
// NetworkExtension's PlugIn hosting uses NEProvider.startSystemExtensionMode().

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
