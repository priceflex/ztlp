//! D1.T4 — tests for load_agent_token: reads ~/.ztlp/agent.token (or
//! ZTLP_AGENT_TOKEN_PATH override) and returns Some(trimmed_content)
//! or None on any read/empty/missing condition.

use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;
use ztlp_proto::agent::config::load_agent_token;

// ZTLP_AGENT_TOKEN_PATH is a process-global env var; serialize tests
// that mutate it to avoid races under cargo's parallel test runner.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_token_path<R>(path: &std::path::Path, f: impl FnOnce() -> R) -> R {
    let _g = ENV_LOCK.lock().unwrap();
    let prev = std::env::var_os("ZTLP_AGENT_TOKEN_PATH");
    std::env::set_var("ZTLP_AGENT_TOKEN_PATH", path);
    let result = f();
    match prev {
        Some(v) => std::env::set_var("ZTLP_AGENT_TOKEN_PATH", v),
        None => std::env::remove_var("ZTLP_AGENT_TOKEN_PATH"),
    }
    result
}

#[test]
fn returns_none_when_file_missing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nope.token");
    assert!(with_token_path(&path, load_agent_token).is_none());
}

#[test]
fn returns_some_trimmed_content_when_file_present() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    fs::write(&path, "  abcd1234ef\n").unwrap();
    let got = with_token_path(&path, load_agent_token);
    assert_eq!(got.as_deref(), Some("abcd1234ef"));
}

#[test]
fn returns_none_when_file_is_empty() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    fs::write(&path, "").unwrap();
    assert!(with_token_path(&path, load_agent_token).is_none());
}

#[test]
fn returns_none_when_file_is_whitespace_only() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    fs::write(&path, "   \n\t\n   ").unwrap();
    assert!(with_token_path(&path, load_agent_token).is_none());
}

#[test]
fn returns_some_for_real_64_char_hex() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    let tok = "deadbeefcafef00d".repeat(4);
    assert_eq!(tok.len(), 64);
    fs::write(&path, &tok).unwrap();
    assert_eq!(
        with_token_path(&path, load_agent_token).as_deref(),
        Some(tok.as_str())
    );
}
