//! Windows NRPT-based DNS interception for ZTLP zones.
//!
//! On Windows, the agent installs Name Resolution Policy Table (NRPT) rules
//! that point `*.<zone>.ztlp` (and any custom domain in `domain_map`) at the
//! agent's local DNS resolver (default `127.0.0.53:5353`). When the agent
//! uninstalls or unenrolls, those rules are removed cleanly via a marker
//! comment (`ZTLP-managed`) so we never touch operator-installed rules.
//!
//! ## Why NRPT?
//!
//! NRPT is built into Windows DNS Client and ships back to Windows 7+. It lets
//! you direct queries for a namespace (e.g. `.techrockstars.ztlp`) at specific
//! name servers WITHOUT taking over the global resolver. Browsers, `nslookup`,
//! `Resolve-DnsName`, and the WinHTTP / WinINet stacks all honor it.
//!
//! ## Module shape
//!
//! - `NrptRule` — value type describing one rule (namespace, name servers, comment).
//! - `NrptApi` — trait the agent depends on. Production impl uses PowerShell;
//!   test impl is an in-memory `HashMap`.
//! - `FakeNrptApi` — in-memory implementation used by tests (and by non-Windows
//!   compile targets so the agent crate still builds on Linux/macOS for CI).
//! - `setup_zones` / `teardown_managed` — high-level operations that use any
//!   `NrptApi` impl. These are the public API the agent calls.
//!
//! The production `WindowsNrptApi` arrives in D4.T2.

use std::collections::HashMap;
use std::sync::Mutex;

/// Marker stamped into every ZTLP-managed NRPT rule's `Comment` field. The
/// teardown path uses this exact string to decide which rules it owns.
///
/// Operators who add their own NRPT rules with a different (or no) comment
/// are safe — `teardown_managed` will never touch them.
pub const ZTLP_NRPT_MARKER: &str = "ZTLP-managed";

/// One NRPT rule.
///
/// Mirrors the relevant subset of the PowerShell `DnsClientNrptRule` object.
/// We deliberately do NOT carry every field (DNSSEC, encryption, etc.) — the
/// agent only needs namespace + name servers + comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrptRule {
    /// Namespace the rule matches, e.g. `.techrockstars.ztlp`.
    ///
    /// NRPT namespaces start with a leading dot. We enforce that invariant in
    /// `setup_zones` so callers can pass plain zone names like
    /// `techrockstars.ztlp` and we'll normalize.
    pub namespace: String,
    /// Name servers queries get forwarded to. Each entry is `host:port`.
    /// For ZTLP we always pass exactly one: the agent's local resolver.
    pub name_servers: Vec<String>,
    /// Free-form comment. We always set this to `ZTLP_NRPT_MARKER` for rules
    /// we own.
    pub comment: String,
}

/// Result of an NRPT operation.
#[derive(Debug)]
pub enum NrptError {
    /// The underlying PowerShell call returned non-zero.
    CommandFailed { stderr: String, exit_code: i32 },
    /// The PowerShell command emitted unexpected output we couldn't parse.
    ParseError(String),
    /// I/O failure invoking PowerShell.
    Io(std::io::Error),
}

impl std::fmt::Display for NrptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NrptError::CommandFailed { stderr, exit_code } => {
                write!(f, "NRPT command failed (exit {}): {}", exit_code, stderr)
            }
            NrptError::ParseError(s) => write!(f, "NRPT output parse error: {}", s),
            NrptError::Io(e) => write!(f, "NRPT I/O error: {}", e),
        }
    }
}

impl std::error::Error for NrptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NrptError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for NrptError {
    fn from(e: std::io::Error) -> Self {
        NrptError::Io(e)
    }
}

/// Abstraction over the Windows NRPT API.
///
/// Production impl shells out to PowerShell. Test impl is in-memory. The agent
/// only ever sees this trait — `cfg(windows)` selects the production impl at
/// runtime through `default_nrpt_api()`.
pub trait NrptApi: Send + Sync {
    /// Add a rule. Adding the same namespace twice with the same name servers
    /// is a no-op (idempotent). Adding it with DIFFERENT name servers replaces
    /// the existing rule.
    fn add_rule(&self, rule: &NrptRule) -> Result<(), NrptError>;

    /// Remove the rule matching `namespace`. Removing a non-existent rule is
    /// NOT an error — the operation is idempotent on the teardown side too.
    fn remove_rule(&self, namespace: &str) -> Result<(), NrptError>;

    /// List every NRPT rule currently registered on the system. Callers
    /// filter by `comment` themselves; this API returns everything so an
    /// operator-installed rule with a different comment is observable.
    fn list_rules(&self) -> Result<Vec<NrptRule>, NrptError>;
}

// ─── In-memory fake (tests + non-Windows builds) ───────────────────────────

/// In-memory `NrptApi` impl backed by a `HashMap<namespace, rule>`. Used by
/// every unit test in this module and by the agent itself on non-Windows
/// targets (so `cargo build` works on Linux/macOS even though the production
/// path never fires there).
#[derive(Default)]
pub struct FakeNrptApi {
    rules: Mutex<HashMap<String, NrptRule>>,
}

impl FakeNrptApi {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(HashMap::new()),
        }
    }

    /// Test helper: pre-seed a rule (used to simulate operator-installed rules
    /// from outside ZTLP).
    pub fn seed(&self, rule: NrptRule) {
        self.rules
            .lock()
            .expect("FakeNrptApi mutex poisoned")
            .insert(rule.namespace.clone(), rule);
    }

    /// Test helper: count rules currently registered.
    pub fn len(&self) -> usize {
        self.rules.lock().expect("FakeNrptApi mutex poisoned").len()
    }

    /// Test helper: returns true if zero rules registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NrptApi for FakeNrptApi {
    fn add_rule(&self, rule: &NrptRule) -> Result<(), NrptError> {
        let mut guard = self.rules.lock().expect("FakeNrptApi mutex poisoned");
        guard.insert(rule.namespace.clone(), rule.clone());
        Ok(())
    }

    fn remove_rule(&self, namespace: &str) -> Result<(), NrptError> {
        let mut guard = self.rules.lock().expect("FakeNrptApi mutex poisoned");
        guard.remove(namespace);
        Ok(())
    }

    fn list_rules(&self) -> Result<Vec<NrptRule>, NrptError> {
        let guard = self.rules.lock().expect("FakeNrptApi mutex poisoned");
        Ok(guard.values().cloned().collect())
    }
}

// ─── High-level setup / teardown ───────────────────────────────────────────

/// Normalize a zone name into an NRPT namespace.
///
/// NRPT namespaces are leading-dot strings. Caller may pass either
/// `techrockstars.ztlp` or `.techrockstars.ztlp`; we always emit the
/// dot-prefixed form so PowerShell accepts it.
pub fn normalize_namespace(zone: &str) -> String {
    let trimmed = zone.trim();
    if trimmed.is_empty() {
        return String::from(".");
    }
    if trimmed.starts_with('.') {
        trimmed.to_string()
    } else {
        format!(".{}", trimmed)
    }
}

/// Install NRPT rules for every zone and custom-domain suffix in the list.
///
/// `namespaces` is the list of zone names or custom-domain suffixes. We
/// normalize each one to the leading-dot form before installing.
/// `agent_resolver` is the address of the agent's local DNS resolver,
/// e.g. `127.0.0.53:5353`.
///
/// Returns the list of namespaces actually installed (after normalization +
/// dedup). The operation is idempotent — calling `setup_zones` twice with
/// the same args results in the same final state.
pub fn setup_zones<A: NrptApi>(
    api: &A,
    namespaces: &[String],
    agent_resolver: &str,
) -> Result<Vec<String>, NrptError> {
    let mut installed = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in namespaces {
        let ns = normalize_namespace(raw);
        if !seen.insert(ns.clone()) {
            continue; // dedup: same namespace already processed this call
        }
        let rule = NrptRule {
            namespace: ns.clone(),
            name_servers: vec![agent_resolver.to_string()],
            comment: ZTLP_NRPT_MARKER.to_string(),
        };
        api.add_rule(&rule)?;
        installed.push(ns);
    }
    Ok(installed)
}

/// Remove every NRPT rule whose `comment` matches `ZTLP_NRPT_MARKER`. Rules
/// installed by operators (with a different comment, or no comment) are
/// untouched.
///
/// Returns the list of namespaces actually removed.
pub fn teardown_managed<A: NrptApi>(api: &A) -> Result<Vec<String>, NrptError> {
    let all = api.list_rules()?;
    let mut removed = Vec::new();
    for rule in all {
        if rule.comment == ZTLP_NRPT_MARKER {
            api.remove_rule(&rule.namespace)?;
            removed.push(rule.namespace);
        }
    }
    Ok(removed)
}

// ─── Default API selector ──────────────────────────────────────────────────

/// Construct the production NRPT API for the current target.
///
/// On Windows, this returns a `WindowsNrptApi` that shells out to PowerShell
/// (added in D4.T2). On every other target, it returns a `FakeNrptApi` so
/// the agent crate builds and the dns_setup module degrades gracefully — the
/// non-Windows agent doesn't install NRPT rules because there's no NRPT to
/// install.
///
/// Callers that want a deterministic test instance should construct
/// `FakeNrptApi::new()` directly.
pub fn default_nrpt_api() -> Box<dyn NrptApi> {
    #[cfg(windows)]
    {
        // D4.T2 plugs in WindowsNrptApi here. Until that lands the agent
        // still gets the fake on Windows, which is harmless because the
        // dns_setup path doesn't call it yet.
        Box::new(FakeNrptApi::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(FakeNrptApi::new())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_namespace_adds_leading_dot() {
        assert_eq!(
            normalize_namespace("techrockstars.ztlp"),
            ".techrockstars.ztlp"
        );
    }

    #[test]
    fn normalize_namespace_is_idempotent_on_leading_dot() {
        assert_eq!(
            normalize_namespace(".techrockstars.ztlp"),
            ".techrockstars.ztlp"
        );
    }

    #[test]
    fn normalize_namespace_trims_whitespace() {
        assert_eq!(
            normalize_namespace("  techrockstars.ztlp  "),
            ".techrockstars.ztlp"
        );
    }

    #[test]
    fn normalize_namespace_empty_becomes_lone_dot() {
        // Pathological input: empty string. We emit "." rather than panic so
        // downstream PowerShell shows a clear "invalid namespace" error
        // instead of us crashing.
        assert_eq!(normalize_namespace(""), ".");
    }

    #[test]
    fn fake_nrpt_api_starts_empty() {
        let api = FakeNrptApi::new();
        assert!(api.is_empty());
        assert_eq!(api.list_rules().unwrap().len(), 0);
    }

    #[test]
    fn fake_nrpt_api_add_then_list_returns_rule() {
        let api = FakeNrptApi::new();
        let rule = NrptRule {
            namespace: ".techrockstars.ztlp".into(),
            name_servers: vec!["127.0.0.53:5353".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        api.add_rule(&rule).unwrap();
        let listed = api.list_rules().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], rule);
    }

    #[test]
    fn fake_nrpt_api_add_same_namespace_replaces_rule() {
        let api = FakeNrptApi::new();
        let v1 = NrptRule {
            namespace: ".techrockstars.ztlp".into(),
            name_servers: vec!["127.0.0.53:5353".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        let v2 = NrptRule {
            namespace: ".techrockstars.ztlp".into(),
            name_servers: vec!["127.0.0.54:5353".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        api.add_rule(&v1).unwrap();
        api.add_rule(&v2).unwrap();
        let listed = api.list_rules().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name_servers, vec!["127.0.0.54:5353"]);
    }

    #[test]
    fn fake_nrpt_api_remove_unknown_is_noop() {
        let api = FakeNrptApi::new();
        // Removing a namespace that was never added must NOT error.
        api.remove_rule(".does-not-exist.ztlp").unwrap();
        assert!(api.is_empty());
    }

    #[test]
    fn fake_nrpt_api_remove_existing_succeeds() {
        let api = FakeNrptApi::new();
        let rule = NrptRule {
            namespace: ".techrockstars.ztlp".into(),
            name_servers: vec!["127.0.0.53:5353".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        api.add_rule(&rule).unwrap();
        assert_eq!(api.len(), 1);
        api.remove_rule(".techrockstars.ztlp").unwrap();
        assert!(api.is_empty());
    }

    // ─── setup_zones ───────────────────────────────────────────────────────

    #[test]
    fn setup_zones_installs_normalized_namespaces() {
        let api = FakeNrptApi::new();
        let installed = setup_zones(
            &api,
            &["techrockstars.ztlp".into(), ".acme.ztlp".into()],
            "127.0.0.53:5353",
        )
        .unwrap();
        assert_eq!(
            installed,
            vec![".techrockstars.ztlp".to_string(), ".acme.ztlp".to_string()]
        );
        assert_eq!(api.len(), 2);
    }

    #[test]
    fn setup_zones_stamps_managed_marker() {
        let api = FakeNrptApi::new();
        setup_zones(&api, &["techrockstars.ztlp".into()], "127.0.0.53:5353").unwrap();
        let listed = api.list_rules().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].comment, ZTLP_NRPT_MARKER);
    }

    #[test]
    fn setup_zones_dedups_within_one_call() {
        // Passing the same zone twice (or pre-normalized + plain) must not
        // result in duplicate add_rule calls. The fake API would happily
        // overwrite, but the returned "installed" list should still report
        // ONE namespace so callers don't double-count.
        let api = FakeNrptApi::new();
        let installed = setup_zones(
            &api,
            &[
                "techrockstars.ztlp".into(),
                ".techrockstars.ztlp".into(),
                "techrockstars.ztlp".into(),
            ],
            "127.0.0.53:5353",
        )
        .unwrap();
        assert_eq!(installed, vec![".techrockstars.ztlp".to_string()]);
        assert_eq!(api.len(), 1);
    }

    #[test]
    fn setup_zones_called_twice_is_idempotent() {
        // The D4.T3 idempotency guarantee: a second setup_zones with the same
        // args must result in the same final state, not double the rules.
        let api = FakeNrptApi::new();
        let zones = vec!["techrockstars.ztlp".into(), "acme.ztlp".into()];
        setup_zones(&api, &zones, "127.0.0.53:5353").unwrap();
        setup_zones(&api, &zones, "127.0.0.53:5353").unwrap();
        assert_eq!(api.len(), 2);
    }

    // ─── teardown_managed ──────────────────────────────────────────────────

    #[test]
    fn teardown_managed_removes_only_marked_rules() {
        let api = FakeNrptApi::new();
        // Operator-installed rule we must NEVER touch.
        api.seed(NrptRule {
            namespace: ".corp.internal".into(),
            name_servers: vec!["10.0.0.53".into()],
            comment: "IT-managed".into(),
        });
        // ZTLP-managed rule.
        setup_zones(&api, &["techrockstars.ztlp".into()], "127.0.0.53:5353").unwrap();
        assert_eq!(api.len(), 2);

        let removed = teardown_managed(&api).unwrap();
        assert_eq!(removed, vec![".techrockstars.ztlp".to_string()]);
        // Operator rule still there.
        let remaining = api.list_rules().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].namespace, ".corp.internal");
    }

    #[test]
    fn teardown_managed_handles_no_managed_rules() {
        // Pure operator rules — teardown should report no removals and leave
        // them alone.
        let api = FakeNrptApi::new();
        api.seed(NrptRule {
            namespace: ".corp.internal".into(),
            name_servers: vec!["10.0.0.53".into()],
            comment: "IT-managed".into(),
        });
        let removed = teardown_managed(&api).unwrap();
        assert!(removed.is_empty());
        assert_eq!(api.len(), 1);
    }

    #[test]
    fn teardown_managed_on_empty_system_is_noop() {
        let api = FakeNrptApi::new();
        let removed = teardown_managed(&api).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn teardown_managed_called_twice_is_idempotent() {
        let api = FakeNrptApi::new();
        setup_zones(&api, &["techrockstars.ztlp".into()], "127.0.0.53:5353").unwrap();
        teardown_managed(&api).unwrap();
        let removed_second = teardown_managed(&api).unwrap();
        assert!(removed_second.is_empty());
        assert!(api.is_empty());
    }

    #[test]
    fn setup_then_teardown_then_setup_works() {
        // Lifecycle smoke: install → uninstall → re-install. Common case when
        // the user re-enrolls into the same zone after a teardown.
        let api = FakeNrptApi::new();
        setup_zones(&api, &["techrockstars.ztlp".into()], "127.0.0.53:5353").unwrap();
        assert_eq!(api.len(), 1);
        teardown_managed(&api).unwrap();
        assert!(api.is_empty());
        setup_zones(&api, &["techrockstars.ztlp".into()], "127.0.0.53:5353").unwrap();
        assert_eq!(api.len(), 1);
    }
}
