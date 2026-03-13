//! ZTLP Agent — background daemon with DNS resolver, TCP proxy, and SSH integration.
//!
//! The agent makes ZTLP connections seamless and transparent. Instead of
//! manually running `ztlp connect` with IP addresses, users simply use
//! ZTLP names (or custom domain names) as regular hostnames.
//!
//! ## Components
//!
//! - **config** — Agent configuration (TOML)
//! - **domain_map** — Custom domain → ZTLP zone mapping
//! - **proxy** — SSH ProxyCommand (stdin/stdout ↔ ZTLP tunnel)
//! - **vip_pool** — Virtual IP allocator
//! - **dns** — DNS resolver for `*.ztlp` + custom zones
//! - **control** — Unix socket control interface
//! - **daemon** — Agent daemon main loop
//! - **stream** — Stream multiplexing over ZTLP tunnels
//! - **tunnel_pool** — Managed tunnel lifecycle with auto-reconnect

pub mod config;
pub mod control;
pub mod daemon;
pub mod discovery;
pub mod dns;
pub mod dns_setup;
pub mod domain_map;
pub mod proxy;
pub mod renewal;
pub mod stream;
pub mod tunnel_pool;
pub mod vip_pool;
