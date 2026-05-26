//! ztlp-service crate library surface.
//!
//! Exposes the install/uninstall plumbing and the SCM dispatcher entry point
//! so integration tests can poke at them without going through the binary
//! entrypoint.

pub mod install;
pub mod service;
pub mod supervisor;

/// Windows service name registered with the SCM.
///
/// Single source of truth shared by `install::install()` (sc.exe create)
/// and `service::run_service()` (service_dispatcher::start).
pub const SERVICE_NAME: &str = "ZtlpAgent";

/// Directory under ProgramData that holds the agent's runtime state
/// (token file, logs, etc.). Windows-only.
///
/// Single source of truth shared by `install::harden_token_file_acl()`
/// and `service::build_agent_child_spec()` — both of which need to know
/// where the LocalSystem daemon will look for its bearer token.
#[cfg(target_os = "windows")]
pub const TOKEN_DIR: &str = r"C:\ProgramData\ZTLP";

/// Absolute path to the agent's bearer token file. Windows-only.
///
/// Written by the daemon running as LocalSystem; read by the Tauri UI
/// running in the user session (ACL granted by `harden_token_file_acl`).
#[cfg(target_os = "windows")]
pub const TOKEN_FILE: &str = r"C:\ProgramData\ZTLP\agent.token";
