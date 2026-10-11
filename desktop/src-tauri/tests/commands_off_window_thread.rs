//! ZT-10 guard: no Tauri command that does I/O may run on the window thread.
//!
//! Live on TRSWCRM2 (2026-10-11): the ZTLP window sat at "ZTLP (Not
//! Responding)" with the Setup page claiming the agent was not running while
//! the agent was healthy. Every `#[tauri::command]` in this app was a plain
//! `fn`, and in Tauri 2 a plain `fn` command runs on the main (window)
//! thread. `setup_status` waits up to 5 s on the agent (retried once),
//! `enroll` up to 120 s, and the setup steps spawn `ztlp.exe`; while any of
//! them waits the window cannot repaint. The Home page polls every 2 s, so
//! the freeze repeated forever.
//!
//! Rule enforced here: a command whose body talks to the agent (`ipc::`),
//! spawns a process (`Command::new`, `.output()`, `.status()`), or does
//! tunnel work (`tunnel::`) must be `pub async fn` and must hand the
//! blocking part to `spawn_blocking`. Pure state readers may stay sync.

use std::fs;
use std::path::PathBuf;

fn src(name: &str) -> String {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", name].iter().collect();
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// (name, is_async, body) for every `#[tauri::command]` in `source`.
fn commands(source: &str) -> Vec<(String, bool, String)> {
    let mut out = Vec::new();
    let mut rest = source;
    // Only the attribute on its own line counts; comments mention it too.
    const ATTR: &str = "\n#[tauri::command]\n";
    while let Some(i) = rest.find(ATTR) {
        let after = &rest[i + ATTR.len()..];
        let sig_end = after.find('{').expect("command has a body");
        let sig = after[..sig_end].trim();
        let is_async = sig.contains("async fn ");
        let name = sig
            .split("fn ")
            .nth(1)
            .and_then(|s| s.split(['(', '<']).next())
            .expect("fn name")
            .trim()
            .to_string();
        // body: brace-match from the first '{'
        let body_start = sig_end;
        let mut depth = 0usize;
        let mut end = body_start;
        for (j, c) in after[body_start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + j + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push((name, is_async, after[body_start..end].to_string()));
        rest = &after[end..];
    }
    out
}

fn does_io(body: &str) -> bool {
    [
        "ipc::",
        "ipc_request",
        "tunnel::",
        "Command::new",
        ".output()",
        ".status()",
        "process_enrollment",
    ]
    .iter()
    .any(|needle| body.contains(needle))
}

/// Body of `fn <name>(` in `source` (brace-matched), if present.
fn fn_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    // `fn name(` or a generic `fn name<`
    let i = source
        .find(&format!("fn {name}("))
        .or_else(|| source.find(&format!("fn {name}<")))?;
    let after = &source[i..];
    let open = after.find('{')?;
    let mut depth = 0usize;
    for (j, c) in after[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after[open..open + j + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The effective body of a command: its own body plus the body of any
/// `<name>_sync` helper it delegates to. A wrapper that offloads to a helper
/// is judged by what the helper does.
fn effective_body(source: &str, name: &str, body: &str) -> String {
    match fn_body(source, &format!("{name}_sync")) {
        Some(helper) if body.contains(&format!("{name}_sync")) => format!("{body}\n{helper}"),
        _ => body.to_string(),
    }
}

#[test]
fn every_io_command_is_async_and_offloads_to_spawn_blocking() {
    let mut violations = Vec::new();
    let mut checked = 0;
    for file in ["commands.rs", "setup.rs"] {
        let source = src(file);
        for (name, is_async, body) in commands(&source) {
            let full = effective_body(&source, &name, &body);
            if !does_io(&full) {
                continue;
            }
            checked += 1;
            // the offload may be direct (`spawn_blocking`) or through the
            // module's helper (`blocking(` / `off_window_thread(`); the
            // helpers are pinned below to really call spawn_blocking
            let offloads = body.contains("spawn_blocking")
                || body.contains("blocking(")
                || body.contains("off_window_thread(");
            if !is_async {
                violations.push(format!(
                    "{file}::{name} does I/O but is a plain `fn` (runs on the window thread)"
                ));
            } else if !offloads {
                violations.push(format!(
                    "{file}::{name} is async but runs its blocking I/O inline (blocks a runtime worker)"
                ));
            }
        }
    }
    // 7 in commands.rs (connect, disconnect, get_attached, enroll,
    // get_services, get_traffic_stats, save_config? no: pure) + 7 in
    // setup.rs minus pure readers. Pin the floor so a refactor that hides
    // I/O behind a name the scanner does not know gets noticed.
    assert!(
        checked >= 11,
        "expected to find the I/O commands, found {checked}"
    );
    assert!(violations.is_empty(), "\n{}\n", violations.join("\n"));
}

#[test]
fn the_offload_helpers_really_use_spawn_blocking() {
    // the guard above trusts `blocking(` and `off_window_thread(`; pin that
    // they are what they claim, so nobody can satisfy the guard with a
    // helper that just calls the closure inline
    let c = src("commands.rs");
    let b = fn_body(&c, "blocking").expect("commands.rs has a `blocking` helper");
    assert!(
        b.contains("spawn_blocking"),
        "commands::blocking must use spawn_blocking"
    );
    let s = src("setup.rs");
    let o = fn_body(&s, "off_window_thread").expect("setup.rs has `off_window_thread`");
    assert!(
        o.contains("spawn_blocking"),
        "setup::off_window_thread must use spawn_blocking"
    );
}

#[test]
fn the_parser_sees_the_known_commands() {
    let names: Vec<String> = commands(&src("commands.rs"))
        .into_iter()
        .chain(commands(&src("setup.rs")))
        .map(|(n, _, _)| n)
        .collect();
    for want in ["enroll", "setup_status", "get_status", "setup_install_dns"] {
        assert!(
            names.iter().any(|n| n == want),
            "missing {want} in {names:?}"
        );
    }
}
