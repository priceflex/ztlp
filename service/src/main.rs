//! `ztlp-service` binary entrypoint.
//!
//! Provides three subcommands:
//!   * `install`   — register the Windows service via sc.exe
//!   * `uninstall` — remove the Windows service via sc.exe (idempotent)
//!   * `run`       — the SCM-invoked entrypoint (D2.T2 dispatcher;
//!     D2.T3 replaces the placeholder run_loop with the
//!     real child-process supervisor)
//!
//! On non-Windows targets all three return a clean "unsupported on this
//! platform" error so the binary still builds and behaves predictably in CI.

use clap::{Parser, Subcommand};
use ztlp_service::{install, service};

#[derive(Parser, Debug)]
#[command(
    name = "ztlp-service",
    version,
    about = "ZTLP Windows service host",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Register the ZTLP agent as a Windows service.
    Install,
    /// Remove the ZTLP agent Windows service.
    Uninstall,
    /// Run as the Windows service (invoked by the SCM).
    Run,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Install => install::install(),
        Command::Uninstall => install::uninstall(),
        Command::Run => service::run_service(),
    };

    if let Err(err) = result {
        eprintln!("ztlp-service: {err:#}");
        std::process::exit(1);
    }
}
