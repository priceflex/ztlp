//! ztlp-service crate library surface.
//!
//! Exposes the install/uninstall plumbing and the SCM dispatcher entry point
//! so integration tests can poke at them without going through the binary
//! entrypoint.

pub mod install;
pub mod service;

/// Windows service name registered with the SCM.
///
/// Single source of truth shared by `install::install()` (sc.exe create)
/// and `service::run_service()` (service_dispatcher::start).
pub const SERVICE_NAME: &str = "ZtlpAgent";
