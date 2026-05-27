//! Operator-facing admin helpers (v0.32 M7).
//!
//! Pure formatting helpers extracted from CLI subcommands so they can be
//! unit-tested without spinning up real NS / sockets. The thin CLI handler
//! lives in `bin/ztlp-cli.rs`.

pub mod gateway_candidates;
