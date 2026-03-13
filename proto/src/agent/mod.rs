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
//! - **dns** — DNS resolver for `*.ztlp` + custom zones
//! - **vip_pool** — Virtual IP allocator
//! - **tunnel_manager** — Tunnel lifecycle, pooling, reconnect
//! - **control** — Unix socket control interface
//! - **daemon** — Agent daemon main loop
//! - **renewal** — Credential renewal daemon
//! - **dns_setup** — System DNS configuration helpers

pub mod config;
pub mod domain_map;
pub mod proxy;
