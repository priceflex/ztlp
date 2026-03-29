//! # ZTLP Proto — Zero Trust Layer Protocol Prototype
//!
//! A minimal but real implementation of the ZTLP protocol, demonstrating:
//!
//! - **Identity**: 128-bit NodeID generation and X25519 key management
//! - **Packet format**: Exact bit-level ZTLP headers (handshake + compact data)
//! - **Pipeline**: Three-layer admission (magic → session → auth tag)
//! - **Session**: Session state with anti-replay windows
//! - **Handshake**: Noise_XX mutual authentication
//! - **Transport**: Async UDP with encrypted data flow
//!
//! ```text
//!    ┌────────────────────────────────────────┐
//!    │         Inbound ZTLP Packet            │
//!    └───────────────┬────────────────────────┘
//!                    ▼
//!    ┌────────────────────────────────────────┐
//!    │  Layer 1: Magic == 0x5A37?             │  ← nanoseconds, no crypto
//!    └───────────────┬────────────────────────┘
//!                    ▼
//!    ┌────────────────────────────────────────┐
//!    │  Layer 2: SessionID in allowlist?       │  ← microseconds, no crypto
//!    └───────────────┬────────────────────────┘
//!                    ▼
//!    ┌────────────────────────────────────────┐
//!    │  Layer 3: HeaderAuthTag valid?          │  ← real crypto cost
//!    └───────────────┬────────────────────────┘
//!                    ▼
//!    ┌────────────────────────────────────────┐
//!    │  ✓ Decrypt + Forward                   │
//!    └────────────────────────────────────────┘
//! ```

// Note: unsafe_code is denied in all modules except ffi.rs, which requires
// unsafe for C FFI interop. The ffi module uses #![allow(unsafe_code)] locally.
#![deny(unsafe_code)]

pub mod admission;
pub mod agent;
pub mod android;
pub mod anti_replay;
pub mod batch;
pub mod congestion;
pub mod dns;
pub mod enrollment;
pub mod error;
pub mod fec;
#[allow(unsafe_code)]
pub mod ffi;
pub mod gro_batch;
#[allow(unsafe_code)]
pub mod gso;
pub mod handshake;
pub mod identity;
pub mod metrics;
pub mod mobile;
pub mod nat;
#[allow(unsafe_code)]
pub mod pacing;
pub mod packet;
pub mod packet_router;
pub mod pipeline;
pub mod pmtu;
pub mod policy;
pub mod pqkem;
pub mod punch;
pub mod reject;
pub mod rekey;
pub mod relay;
pub mod relay_pool;
pub mod roaming;
pub mod security;
pub mod send_controller;
pub mod session;
pub mod session_manager;
pub mod stats;
pub mod transport;
pub mod tunnel;
pub mod updater;
pub mod vip;
