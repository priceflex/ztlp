//! D1.T3 — tests for ensure_token_file: generate-or-load a 32-byte
//! token, persist as 64 hex chars, restrictive perms on unix.

use std::fs;
use tempfile::TempDir;
use ztlp_proto::agent::daemon::ensure_token_file;

#[test]
fn first_call_creates_64_char_hex_token() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    let token = ensure_token_file(&path).expect("first ensure must succeed");
    assert_eq!(token.len(), 64, "32 raw bytes -> 64 hex chars");
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex only, got: {token}"
    );
    let on_disk = fs::read_to_string(&path).unwrap();
    assert_eq!(on_disk.trim(), token);
}

#[test]
fn second_call_returns_existing_token() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    let first = ensure_token_file(&path).unwrap();
    let second = ensure_token_file(&path).unwrap();
    assert_eq!(first, second, "ensure must be idempotent");
}

#[test]
fn two_calls_to_different_paths_produce_different_tokens() {
    let dir = TempDir::new().unwrap();
    let a = ensure_token_file(&dir.path().join("a.token")).unwrap();
    let b = ensure_token_file(&dir.path().join("b.token")).unwrap();
    assert_ne!(a, b, "fresh tokens must not collide");
}

#[test]
fn creates_parent_directories() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nested").join("subdir").join("agent.token");
    ensure_token_file(&path).expect("must create parent dirs");
    assert!(path.exists());
}

#[test]
fn whitespace_only_file_is_treated_as_missing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    fs::write(&path, "   \n\t  \n").unwrap();
    let token = ensure_token_file(&path).expect("whitespace-only must regenerate");
    assert_eq!(token.len(), 64);
    // ensure the file got overwritten
    assert_eq!(fs::read_to_string(&path).unwrap().trim(), token);
}

#[cfg(unix)]
#[test]
fn unix_permissions_are_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    ensure_token_file(&path).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "token must not be world/group readable, got 0o{mode:o}"
    );
}
