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

/// Windows NRPT can only route a namespace to an IP address (implicit port
/// 53). If the agent's DNS resolver is not listening on port 53, return a
/// `loopback_alias:port` form and the caller must bind the resolver to
/// `loopback_alias:53` and install a loopback alias so the NRPT rule works.
///
/// Real bug found live (2026-08-30, DESKTOP-CBSQDNE): `Add-DnsClientNrptRule`
/// given `127.0.0.53:5353` silently stored an EMPTY `NameServers` list and
/// Chrome got `DNS_PROBE_FINISHED_NXDOMAIN` — no error, no warning. NRPT
/// rules only take bare IPs. On Windows, the dedicated loopback alias
/// `127.0.0.53` was clearly intended for port 53 all along.
pub struct WindowsNrptListenPlan {
    /// The resolver socket the daemon must bind: `ip:53` on the alias (or
    /// the configured address when it's already on port 53).
    pub bind_addr: std::net::SocketAddr,
    /// The bare IP (no port) to hand to NRPT.
    pub nrpt_server: std::net::IpAddr,
    /// `true` when the resolver needs the dedicated loopback alias and the
    /// caller must ensure `nrpt_server` is present on the loopback adapter
    /// before binding (a no-op on the common Windows case where it already
    /// exists).
    pub needs_alias: bool,
}

/// Plan the Windows listen-address + NRPT-server pair for a configured DNS
/// listen address.
///
/// - Configured `127.0.0.53:53`  -> bind there, NRPT `127.0.0.53`, no alias work.
/// - Configured `127.0.0.53:5353` (or any non-53 port on the alias) -> bind
///   `127.0.0.53:53`, NRPT `127.0.0.53`, `needs_alias = true`.
/// - Configured `0.0.0.0:53` / `127.0.0.1:53` -> bind as configured, NRPT
///   `127.0.0.1` (loopback primary), no alias work.
pub fn plan_windows_nrpt_listen(listen: &str) -> Result<WindowsNrptListenPlan, String> {
    let (host, port): (String, u16) = match listen.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| format!("bad port in {listen}"))?;
            (h.to_string(), port)
        }
        None => {
            return Err(format!(
                "dns.listen {listen:?} has no host:port; Windows NRPT requires a \
                 loopback address on port 53 (use e.g. 127.0.0.53:53)"
            ))
        }
    };

    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| format!("dns.listen host {host:?} is not an IP literal"))?;

    if port == 53 {
        return Ok(WindowsNrptListenPlan {
            bind_addr: (ip, 53).into(),
            nrpt_server: ip,
            needs_alias: false,
        });
    }

    // Port != 53: NRPT can't express it, so move the resolver to port 53 on
    // the dedicated loopback alias (127.0.0.53). This is safe because
    // 127.0.0.53 is a loopback-only address the agent already uses.
    let alias: std::net::IpAddr = "127.0.0.53"
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    Ok(WindowsNrptListenPlan {
        bind_addr: (alias, 53).into(),
        nrpt_server: alias,
        needs_alias: ip != alias,
    })
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
pub fn setup_zones<A: NrptApi + ?Sized>(
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
pub fn teardown_managed<A: NrptApi + ?Sized>(api: &A) -> Result<Vec<String>, NrptError> {
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

// ─── Production Windows impl (PowerShell shell-out) ────────────────────────

/// Production [`NrptApi`] implementation that invokes PowerShell to read and
/// mutate Windows DNS Client NRPT state. Used only on `cfg(windows)`; other
/// targets get [`FakeNrptApi`] from [`default_nrpt_api`].
///
/// We deliberately shell out to `powershell.exe` instead of binding directly
/// to the WMI / CIM provider because:
///
/// 1. The cmdlets (`Add-DnsClientNrptRule` etc.) are the supported public
///    contract; their underlying WMI classes are not. Microsoft has changed
///    the class names twice across Win 10 builds.
/// 2. NRPT mutations only fire when a service-tier process (`LocalSystem` /
///    elevated) runs the cmdlets. PowerShell inherits the parent token, so
///    the service host's existing privilege is enough.
/// 3. The CIM provider for NRPT isn't easily callable from Rust without a
///    third-party WMI crate; PowerShell is already on every Windows box.
///
/// We use a tiny invariant in the PowerShell snippets:
///   `Get-DnsClientNrptRule | Select-Object Namespace, NameServers, Comment | ConvertTo-Json -Compress -Depth 3`
/// This collapses the inherently weird PS output into something the parser
/// can turn into [`NrptRule`] regardless of locale / culture settings.
pub struct WindowsNrptApi {
    /// Override for tests / dependency injection. Defaults to
    /// `"powershell.exe"`. The full path can be passed when LocalSystem's
    /// PATH is unreliable.
    powershell_path: String,
}

impl Default for WindowsNrptApi {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsNrptApi {
    /// Construct a production API with the default `powershell.exe` lookup.
    pub fn new() -> Self {
        Self {
            powershell_path: String::from("powershell.exe"),
        }
    }

    /// Construct a production API with a specific PowerShell path. Used by
    /// the Windows service host when LocalSystem's PATH might not resolve
    /// `powershell.exe`.
    pub fn with_powershell_path(path: impl Into<String>) -> Self {
        Self {
            powershell_path: path.into(),
        }
    }

    /// Helper: build a `-Command` argument that emits the rule list as JSON.
    ///
    /// `@()` wrapper forces an array even when there's exactly one rule —
    /// PowerShell's default behavior of unwrapping single-element arrays
    /// would otherwise produce a JSON object on one rule and an array on N>1,
    /// which the parser has to handle either way but tests are easier when
    /// it's always an array.
    pub(crate) fn list_command() -> String {
        String::from(
            "@(Get-DnsClientNrptRule | Select-Object Namespace, NameServers, Comment) \
             | ConvertTo-Json -Compress -Depth 3",
        )
    }

    /// Helper: build a `-Command` argument that adds (or upserts) a rule.
    ///
    /// `Add-DnsClientNrptRule` doesn't support "upsert" natively. We first
    /// remove any rule with the same namespace (-ErrorAction SilentlyContinue
    /// so removing a non-existent rule isn't fatal), then add the fresh one.
    /// This matches the trait's idempotent-add contract.
    pub(crate) fn add_command(rule: &NrptRule) -> String {
        // PowerShell single-quoted strings have NO escape sequences except
        // for doubled '' to represent a literal '. NRPT namespaces and
        // comments shouldn't contain single quotes in any realistic input,
        // but we double-up just in case so a malicious / weird value can't
        // break out of the string literal.
        let ns = rule.namespace.replace('\'', "''");
        let comment = rule.comment.replace('\'', "''");
        let servers = rule
            .name_servers
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{ns}' }} \
                | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; \
             Add-DnsClientNrptRule -Namespace '{ns}' -NameServers @({servers}) \
                -Comment '{comment}' -ErrorAction Stop",
            ns = ns,
            servers = servers,
            comment = comment,
        )
    }

    /// Helper: build a `-Command` argument that removes a rule by namespace.
    pub(crate) fn remove_command(namespace: &str) -> String {
        let ns = namespace.replace('\'', "''");
        format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{ns}' }} \
                | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue",
            ns = ns
        )
    }
}

/// Parse the JSON emitted by [`WindowsNrptApi::list_command`].
///
/// PowerShell's `ConvertTo-Json` quirks the parser handles:
///
/// - **Empty input.** When no rules exist, `Get-DnsClientNrptRule` emits
///   nothing, the `@()` wrap forces a JSON empty array `[]`, but on very
///   old PowerShell (≤ 5.1) the pipeline can also emit literal `null`.
///   Both map to an empty [`Vec`].
/// - **Single rule unwrap.** Even with `@()`, certain locales emit a single
///   object instead of an array. We accept both shapes.
/// - **`NameServers` field shape.** PowerShell renders the underlying CIM
///   `NameServers` property as either a string (single server) or an array
///   of strings (multiple). Both forms are accepted.
/// - **`Comment` may be missing.** Operator-installed rules without a
///   comment have a `null` JSON field. We treat that as `""`.
///
/// Returns parse errors as [`NrptError::ParseError`] with the offending JSON
/// snippet included so an operator can diagnose it from the agent logs.
pub(crate) fn parse_list_output(stdout: &str) -> Result<Vec<NrptRule>, NrptError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null") {
        return Ok(Vec::new());
    }
    // Try array first, then single object.
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| NrptError::ParseError(format!("invalid JSON ({}): {}", e, trimmed)))?;
    let entries: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Object(_) => vec![value],
        serde_json::Value::Null => return Ok(Vec::new()),
        other => {
            return Err(NrptError::ParseError(format!(
                "expected array/object, got {:?}",
                other
            )))
        }
    };
    let mut rules = Vec::with_capacity(entries.len());
    for entry in entries {
        // NRPT's `Namespace` is a string[] in the underlying CIM model, so
        // `ConvertTo-Json` always emits it as a JSON array — even when the rule
        // only covers one namespace. PowerShell 5.1 / Windows Server are
        // particularly strict about this; older mocked tests used a bare string
        // and missed the array shape (caught in the v0.34.3 D4 smoke run on
        // DESKTOP-LRC8DKH). Accept both shapes for forward-compat.
        let namespace = match entry.get("Namespace") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .find_map(|v| v.as_str().map(|s| s.to_string()))
                .ok_or_else(|| {
                    NrptError::ParseError(format!(
                        "Namespace array is empty or non-string in {}",
                        entry
                    ))
                })?,
            _ => {
                return Err(NrptError::ParseError(format!(
                    "missing Namespace field in {}",
                    entry
                )))
            }
        };
        let name_servers = match entry.get("NameServers") {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            Some(serde_json::Value::Null) | None => Vec::new(),
            Some(other) => {
                return Err(NrptError::ParseError(format!(
                    "unexpected NameServers shape: {:?}",
                    other
                )))
            }
        };
        let comment = entry
            .get("Comment")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        rules.push(NrptRule {
            namespace,
            name_servers,
            comment,
        });
    }
    Ok(rules)
}

#[cfg(windows)]
impl NrptApi for WindowsNrptApi {
    fn add_rule(&self, rule: &NrptRule) -> Result<(), NrptError> {
        let cmd = Self::add_command(rule);
        run_powershell(&self.powershell_path, &cmd)?;
        Ok(())
    }

    fn remove_rule(&self, namespace: &str) -> Result<(), NrptError> {
        let cmd = Self::remove_command(namespace);
        run_powershell(&self.powershell_path, &cmd)?;
        Ok(())
    }

    fn list_rules(&self) -> Result<Vec<NrptRule>, NrptError> {
        let cmd = Self::list_command();
        let stdout = run_powershell(&self.powershell_path, &cmd)?;
        parse_list_output(&stdout)
    }
}

#[cfg(windows)]
fn run_powershell(path: &str, command: &str) -> Result<String, NrptError> {
    use std::process::Command;
    let output = Command::new(path)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .map_err(NrptError::Io)?;
    if !output.status.success() {
        return Err(NrptError::CommandFailed {
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ─── Default API selector ──────────────────────────────────────────────────

/// Construct the production NRPT API for the current target.
///
/// On Windows, this returns a [`WindowsNrptApi`] that shells out to PowerShell.
/// On every other target, it returns a [`FakeNrptApi`] so the agent crate
/// builds and the `dns_setup` module degrades gracefully — the non-Windows
/// agent doesn't install NRPT rules because there's no NRPT to install.
///
/// Callers that want a deterministic test instance should construct
/// [`FakeNrptApi::new`] directly.
pub fn default_nrpt_api() -> Box<dyn NrptApi> {
    #[cfg(windows)]
    {
        Box::new(WindowsNrptApi::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(FakeNrptApi::new())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    // ─── Regression: NRPT NameServers must never carry a colon-port ───────
    //
    // Real bug (2026-08-30, DESKTOP-CBSQDNE): `Add-DnsClientNrptRule` given
    // `127.0.0.53:5353` silently stored an EMPTY NameServers list and
    // Chrome got DNS_PROBE_FINISHED_NXDOMAIN — the command reported
    // success, the rule existed, it pointed nowhere. These tests lock in
    // the invariant that every rule this module installs carries a BARE IP
    // with no `:port`, because NRPT can only route a namespace to an IP
    // on implicit port 53.

    /// Helper mirroring the guard the `setup_status` / `dns_configured`
    /// check applies: a rule is USABLE iff it has at least one server and
    /// every server is a bare IP (no colon-port).
    fn rule_is_usable(rule: &NrptRule) -> bool {
        !rule.name_servers.is_empty() && rule.name_servers.iter().all(|s| !s.contains(':'))
    }

    /// The exact live failure shape: a rule whose single server is a
    /// host:port string. `parse_list_output` must parse it faithfully (we
    /// cannot know Windows mangled it) and the usability guard must
    /// classify it as NOT usable — so `dns_configured` reports false and
    /// the wizard re-runs dns-setup instead of showing a green check.
    #[test]
    fn host_port_server_is_parsed_but_not_usable() {
        let json = r#"[{"Namespace":[".demo.spongebob.ztlp"],"NameServers":["127.0.0.53:5353"],"Comment":"ZTLP-managed"}]"#;
        let rules = parse_list_output(json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name_servers, vec!["127.0.0.53:5353"]);
        assert!(
            !rule_is_usable(&rules[0]),
            "a host:port server must NOT count as a usable NRPT rule"
        );
    }

    /// The live EMPTY-list shape (what Windows actually stored).
    #[test]
    fn empty_name_servers_is_not_usable() {
        let rule = NrptRule {
            namespace: ".demo.spongebob.ztlp".into(),
            name_servers: Vec::new(),
            comment: ZTLP_NRPT_MARKER.into(),
        };
        assert!(!rule_is_usable(&rule));
    }

    /// A bare-IP server IS usable.
    #[test]
    fn bare_ip_server_is_usable() {
        let rule = NrptRule {
            namespace: ".demo.spongebob.ztlp".into(),
            name_servers: vec!["127.0.0.53".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        assert!(rule_is_usable(&rule));
    }

    /// End-to-end through `setup_zones`: the installed rule's NameServers is
    /// exactly the string the caller handed in — pinning the contract that
    /// the caller (CLI) must hand a bare IP.
    #[test]
    fn setup_zones_stores_the_given_server_verbatim() {
        let api = FakeNrptApi::new();
        let installed =
            setup_zones(&api, &["demo.spongebob.ztlp".to_string()], "127.0.0.53").unwrap();
        assert_eq!(installed, vec![".demo.spongebob.ztlp"]);
        let rules = api.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(
            rule_is_usable(&rules[0]),
            "server handed to setup_zones must produce a usable rule: {:?}",
            rules[0]
        );
    }

    // ─── plan_windows_nrpt_listen ─────────────────────────────────────────

    #[test]
    fn plan_port_53_uses_configured_address() {
        let p = plan_windows_nrpt_listen("127.0.0.53:53").unwrap();
        assert_eq!(p.bind_addr, "127.0.0.53:53".parse().unwrap());
        assert_eq!(p.nrpt_server.to_string(), "127.0.0.53");
        assert!(!p.needs_alias);
    }

    #[test]
    fn plan_non_53_port_moves_resolver_to_alias_port_53() {
        // The live-bug case: configured 5353 (mDNS), NRPT needs port 53.
        let p = plan_windows_nrpt_listen("127.0.0.53:5353").unwrap();
        assert_eq!(p.bind_addr, "127.0.0.53:53".parse().unwrap());
        assert_eq!(p.nrpt_server.to_string(), "127.0.0.53");
        assert!(!p.needs_alias, "alias is the configured host itself");
    }

    #[test]
    fn plan_127_0_0_1_non_53_moves_to_alias() {
        let p = plan_windows_nrpt_listen("127.0.0.1:5353").unwrap();
        assert_eq!(p.bind_addr, "127.0.0.53:53".parse().unwrap());
        assert_eq!(p.nrpt_server.to_string(), "127.0.0.53");
        assert!(p.needs_alias);
    }

    #[test]
    fn plan_rejects_host_without_port() {
        assert!(plan_windows_nrpt_listen("127.0.0.53").is_err());
    }

    #[test]
    fn plan_rejects_non_ip_host() {
        assert!(plan_windows_nrpt_listen("localhost:53").is_err());
    }
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

    // ─── WindowsNrptApi command-builder tests ──────────────────────────────
    //
    // The actual PowerShell invocation is `cfg(windows)`-only, so the trait
    // impl can't be exercised from this Linux dev box. But the COMMAND
    // STRINGS the impl emits are platform-agnostic and trivially testable.
    // Catching a typo in the PowerShell here is cheap; catching it on a
    // Windows bench after a 90-second build is not.

    #[test]
    fn windows_list_command_uses_array_wrap_and_compress() {
        let cmd = WindowsNrptApi::list_command();
        // Array wrap so single-rule output is still JSON array.
        assert!(cmd.contains("@(Get-DnsClientNrptRule"));
        // Always emit Namespace / NameServers / Comment in that order.
        assert!(cmd.contains("Namespace, NameServers, Comment"));
        // Compressed JSON so we don't have to deal with newlines.
        assert!(cmd.contains("ConvertTo-Json -Compress -Depth 3"));
    }

    #[test]
    fn windows_add_command_upserts_via_remove_then_add() {
        let rule = NrptRule {
            namespace: ".techrockstars.ztlp".into(),
            name_servers: vec!["127.0.0.53:5353".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        let cmd = WindowsNrptApi::add_command(&rule);
        // Must remove any pre-existing rule with the same namespace first.
        assert!(cmd.contains("Remove-DnsClientNrptRule"));
        assert!(cmd.contains("-ErrorAction SilentlyContinue"));
        // ...then add the new one.
        assert!(cmd.contains("Add-DnsClientNrptRule"));
        // Namespace, name server, and comment all rendered in the command.
        assert!(cmd.contains("'.techrockstars.ztlp'"));
        assert!(cmd.contains("'127.0.0.53:5353'"));
        assert!(cmd.contains("'ZTLP-managed'"));
        // The add path uses -ErrorAction Stop so real failures DO bubble up.
        assert!(cmd.contains("Add-DnsClientNrptRule") && cmd.contains("-ErrorAction Stop"));
    }

    #[test]
    fn windows_add_command_handles_multiple_name_servers() {
        // Future-proofing: if we ever ship multi-resolver NRPT (primary +
        // fallback), the command builder shouldn't drop the second entry.
        let rule = NrptRule {
            namespace: ".techrockstars.ztlp".into(),
            name_servers: vec!["127.0.0.53:5353".into(), "127.0.0.54:5353".into()],
            comment: ZTLP_NRPT_MARKER.into(),
        };
        let cmd = WindowsNrptApi::add_command(&rule);
        assert!(cmd.contains("'127.0.0.53:5353'"));
        assert!(cmd.contains("'127.0.0.54:5353'"));
        // Servers must be comma-separated inside the @() PowerShell array.
        assert!(cmd.contains("@('127.0.0.53:5353','127.0.0.54:5353')"));
    }

    #[test]
    fn windows_add_command_escapes_embedded_single_quotes() {
        // Adversarial input: a comment containing a single quote could break
        // out of the PS string literal. PowerShell doubles '' to escape.
        let rule = NrptRule {
            namespace: ".acme.ztlp".into(),
            name_servers: vec!["127.0.0.53:5353".into()],
            comment: "operator's note".into(),
        };
        let cmd = WindowsNrptApi::add_command(&rule);
        // Doubled '' inside the literal.
        assert!(cmd.contains("'operator''s note'"));
        // Outer literal still closed.
        assert!(!cmd.contains("'operator's"));
    }

    #[test]
    fn windows_remove_command_filters_by_namespace() {
        let cmd = WindowsNrptApi::remove_command(".techrockstars.ztlp");
        assert!(cmd.contains("Where-Object"));
        assert!(cmd.contains("$_.Namespace -eq '.techrockstars.ztlp'"));
        assert!(cmd.contains("Remove-DnsClientNrptRule"));
        // SilentlyContinue so removing an absent rule isn't an error — that
        // mirrors the trait's idempotent-remove contract.
        assert!(cmd.contains("-ErrorAction SilentlyContinue"));
    }

    // ─── parse_list_output tests ───────────────────────────────────────────
    //
    // Captured sample shapes from real Windows PowerShell output. The parser
    // must accept all of them.

    #[test]
    fn parse_list_empty_string_returns_empty() {
        assert!(parse_list_output("").unwrap().is_empty());
        assert!(parse_list_output("   \n\t  ").unwrap().is_empty());
    }

    #[test]
    fn parse_list_literal_null_returns_empty() {
        // PowerShell 5.1 sometimes emits the JSON token "null" when the
        // pipeline produces nothing. Newer versions emit "[]". Both must
        // map to empty.
        assert!(parse_list_output("null").unwrap().is_empty());
        assert!(parse_list_output("NULL").unwrap().is_empty()); // case-insensitive guard
        assert!(parse_list_output("[]").unwrap().is_empty());
    }

    #[test]
    fn parse_list_single_rule_as_array() {
        // The expected shape after the @() wrap forces array.
        let json = r#"[{"Namespace":".techrockstars.ztlp","NameServers":"127.0.0.53:5353","Comment":"ZTLP-managed"}]"#;
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].namespace, ".techrockstars.ztlp");
        assert_eq!(parsed[0].name_servers, vec!["127.0.0.53:5353"]);
        assert_eq!(parsed[0].comment, "ZTLP-managed");
    }

    #[test]
    fn parse_list_single_rule_as_bare_object() {
        // Some Windows locales unwrap the @() array. Parser must still cope.
        let json = r#"{"Namespace":".techrockstars.ztlp","NameServers":"127.0.0.53:5353","Comment":"ZTLP-managed"}"#;
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].namespace, ".techrockstars.ztlp");
    }

    #[test]
    fn parse_list_multiple_rules_with_multi_server() {
        let json = concat!(
            r#"[{"Namespace":".techrockstars.ztlp","NameServers":["127.0.0.53:5353","127.0.0.54:5353"],"Comment":"ZTLP-managed"},"#,
            r#"{"Namespace":".corp.internal","NameServers":["10.0.0.53"],"Comment":"IT-managed"}]"#,
        );
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 2);
        // First rule: ZTLP-managed, two servers.
        assert_eq!(parsed[0].namespace, ".techrockstars.ztlp");
        assert_eq!(parsed[0].name_servers.len(), 2);
        assert_eq!(parsed[0].comment, "ZTLP-managed");
        // Second rule: operator's, one server.
        assert_eq!(parsed[1].namespace, ".corp.internal");
        assert_eq!(parsed[1].comment, "IT-managed");
    }

    #[test]
    fn parse_list_handles_missing_comment_field() {
        // Operator rules without a comment get `null` in JSON.
        let json = r#"[{"Namespace":".legacy.zone","NameServers":"10.0.0.1","Comment":null}]"#;
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].comment, "");
    }

    #[test]
    fn parse_list_handles_omitted_nameservers() {
        // A pathological rule with no name servers — parser shouldn't crash.
        let json = r#"[{"Namespace":".weird.zone","NameServers":null,"Comment":"weird"}]"#;
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name_servers.len(), 0);
    }

    #[test]
    fn parse_list_returns_parse_error_on_garbage() {
        let err = parse_list_output("not json at all").unwrap_err();
        match err {
            NrptError::ParseError(msg) => {
                assert!(msg.contains("invalid JSON"), "msg = {}", msg);
            }
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    /// Regression: PowerShell 5.1 on Windows emits `Namespace` as a JSON array
    /// (the underlying CIM type is `string[]`), even when there's only one
    /// namespace per rule. The original parser was string-only and rejected the
    /// real shape with a misleading "missing Namespace" error. This test pins
    /// the actual JSON captured from `DESKTOP-LRC8DKH` during the D4 smoke run
    /// on 2026-05-30.
    #[test]
    fn parse_list_accepts_namespace_array_real_windows_output() {
        // Exact shape from `Get-DnsClientNrptRule | Select-Object Namespace,NameServers,Comment | ConvertTo-Json -Compress`
        // on PowerShell 5.1.19041.6456 / Windows Server 2022.
        let json = r#"{"Comment":"ZTLP-managed","NameServers":null,"Namespace":[".trs.ztlp"]}"#;
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].namespace, ".trs.ztlp");
        assert_eq!(parsed[0].comment, "ZTLP-managed");
    }

    /// Regression: when the rule has BOTH namespace and name-servers as arrays
    /// — the most common multi-zone shape.
    #[test]
    fn parse_list_accepts_namespace_array_with_servers_array() {
        let json = r#"[{"Namespace":[".trs.ztlp"],"NameServers":["127.0.0.53:5353"],"Comment":"ZTLP-managed"}]"#;
        let parsed = parse_list_output(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].namespace, ".trs.ztlp");
        assert_eq!(parsed[0].name_servers, vec!["127.0.0.53:5353"]);
    }

    /// Edge case: namespace array is empty — should fail with a clear error
    /// (NOT the old "missing Namespace" message which would be misleading).
    #[test]
    fn parse_list_rejects_empty_namespace_array() {
        let json = r#"[{"Namespace":[],"NameServers":["127.0.0.53"],"Comment":"x"}]"#;
        let err = parse_list_output(json).unwrap_err();
        match err {
            NrptError::ParseError(msg) => {
                assert!(
                    msg.contains("empty") || msg.contains("non-string"),
                    "msg = {}",
                    msg
                );
            }
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    #[test]
    fn parse_list_returns_parse_error_when_namespace_missing() {
        // A rule with no Namespace field can't be reconstructed.
        let json = r#"[{"NameServers":"127.0.0.53:5353","Comment":"orphan"}]"#;
        let err = parse_list_output(json).unwrap_err();
        match err {
            NrptError::ParseError(msg) => {
                assert!(msg.contains("Namespace"), "msg = {}", msg);
            }
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    #[test]
    fn windows_nrpt_api_default_path_is_powershell_exe() {
        let api = WindowsNrptApi::new();
        assert_eq!(api.powershell_path, "powershell.exe");
    }

    #[test]
    fn windows_nrpt_api_can_override_powershell_path() {
        let api = WindowsNrptApi::with_powershell_path(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        );
        assert_eq!(
            api.powershell_path,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        );
    }
}
