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

#![deny(unsafe_code)]

pub mod admission;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod packet;
pub mod pipeline;
pub mod relay;
pub mod session;
pub mod transport;
pub mod tunnel;
