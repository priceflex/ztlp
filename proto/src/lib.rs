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

// ── Always-available modules (sync, no tokio) ─────────────────────────
pub mod admission;
#[cfg(feature = "tokio-runtime")]
pub mod agent;
pub mod android;
pub mod client_profile;
pub mod anti_replay;
pub mod enrollment;
pub mod error;
pub mod fec;
#[allow(unsafe_code)]
pub mod ffi;
pub mod handshake;
pub mod identity;
pub mod metrics;
pub mod packet;
pub mod packet_router;
pub mod pipeline;
pub mod pmtu;
pub mod pqkem;
pub mod reject;
pub mod rekey;
pub mod relay_pool;
pub mod roaming;
pub mod security;
pub mod session;
pub mod stats;
pub mod updater;

// ── Tokio-runtime modules (gated out of iOS NE builds) ────────────────
#[cfg(feature = "tokio-runtime")]
#[allow(unsafe_code)]
pub mod ack_socket;
#[cfg(feature = "tokio-runtime")]
pub mod batch;
#[cfg(feature = "tokio-runtime")]
pub mod congestion;
#[cfg(feature = "tokio-runtime")]
pub mod dns;
#[cfg(feature = "tokio-runtime")]
pub mod gro_batch;
#[cfg(feature = "tokio-runtime")]
#[allow(unsafe_code)]
pub mod gso;
pub mod mobile;
#[cfg(feature = "tokio-runtime")]
pub mod nat;
#[cfg(feature = "tokio-runtime")]
#[allow(unsafe_code)]
pub mod pacing;
#[cfg(feature = "tokio-runtime")]
pub mod policy;
#[cfg(feature = "tokio-runtime")]
pub mod punch;
#[cfg(feature = "tokio-runtime")]
pub mod relay;
#[cfg(feature = "tokio-runtime")]
pub mod send_controller;
#[cfg(feature = "tokio-runtime")]
pub mod session_manager;
#[cfg(feature = "tokio-runtime")]
pub mod transport;
#[cfg(feature = "tokio-runtime")]
pub mod tunnel;
#[cfg(feature = "tokio-runtime")]
pub mod vip;
