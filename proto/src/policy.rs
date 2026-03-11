//! Access control policy engine for the ZTLP CLI tunnel.
//!
//! Provides per-service access control based on client identity.
//! Policies are loaded from a TOML config file (`~/.ztlp/policy.toml`).
//!
//! # Policy File Format
//!
//! ```toml
//! # Default policy: deny all unless explicitly allowed
//! default = "deny"
//!
//! [[services]]
//! name = "ssh"
//! allow = ["steve.ops.techrockstars.ztlp", "*.admins.techrockstars.ztlp"]
//!
//! [[services]]
//! name = "rdp"
//! allow = ["*.techs.techrockstars.ztlp"]
//!
//! [[services]]
//! name = "web"
//! allow = ["*"]  # any authenticated node
//! ```
//!
//! # Identity Matching
//!
//! - Exact match: `"steve.ops.techrockstars.ztlp"`
//! - Wildcard suffix: `"*.ops.techrockstars.ztlp"` matches any name ending in `.ops.techrockstars.ztlp`
//! - Universal: `"*"` matches all authenticated identities
//! - Hex pubkey fallback: if no NS name is available, the client's X25519
//!   public key (hex-encoded) is used as identity

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{info, warn, debug};

/// The policy engine — holds rules for all services.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Per-service rules: service name → allowed patterns.
    rules: HashMap<String, Vec<String>>,
    /// Default policy when no rule exists for a service.
    /// `true` = allow (open), `false` = deny (zero trust).
    default_allow: bool,
}

impl PolicyEngine {
    /// Create a new policy engine with no rules (default deny).
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            default_allow: false,
        }
    }

    /// Create an open policy engine that allows everything.
    /// Used when no policy file is configured.
    pub fn allow_all() -> Self {
        Self {
            rules: HashMap::new(),
            default_allow: true,
        }
    }

    /// Load policy from a TOML file.
    ///
    /// Returns `Ok(PolicyEngine)` on success, or an error string.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("failed to read policy file '{}': {}", path.display(), e))?;

        Self::from_toml(&content)
    }

    /// Parse policy from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, String> {
        // Simple TOML parser — we only need `default` and `[[services]]`
        let mut rules: HashMap<String, Vec<String>> = HashMap::new();
        let mut default_allow = false;

        let mut current_service: Option<String> = None;
        let mut current_allow: Vec<String> = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Default policy
            if line.starts_with("default") {
                if let Some(val) = extract_string_value(line) {
                    default_allow = val == "allow";
                }
                continue;
            }

            // New service section
            if line == "[[services]]" {
                // Save previous service if any
                if let Some(name) = current_service.take() {
                    rules.insert(name, std::mem::take(&mut current_allow));
                }
                continue;
            }

            // Service name
            if line.starts_with("name") {
                if let Some(val) = extract_string_value(line) {
                    current_service = Some(val);
                }
                continue;
            }

            // Allow list
            if line.starts_with("allow") {
                if let Some(list) = extract_string_array(line) {
                    current_allow = list;
                }
                continue;
            }
        }

        // Don't forget the last service
        if let Some(name) = current_service {
            rules.insert(name, current_allow);
        }

        let engine = Self {
            rules,
            default_allow,
        };

        info!("loaded {} policy rules (default: {})",
            engine.rules.len(),
            if engine.default_allow { "allow" } else { "deny" }
        );

        Ok(engine)
    }

    /// Check if an identity is authorized to access a service.
    ///
    /// `identity` is either a ZTLP-NS zone name or hex-encoded public key.
    /// `service` is the service name from the DstSvcID field.
    pub fn authorize(&self, identity: &str, service: &str) -> bool {
        match self.rules.get(service) {
            Some(patterns) => {
                let allowed = patterns.iter().any(|p| matches_pattern(identity, p));
                if allowed {
                    debug!("policy ALLOW: {} → {}", identity, service);
                } else {
                    warn!("policy DENY: {} → {} (not in allow list)", identity, service);
                }
                allowed
            }
            None => {
                // No rule for this service — use default
                if self.default_allow {
                    debug!("policy ALLOW (default): {} → {}", identity, service);
                } else {
                    warn!("policy DENY (no rule): {} → {}", identity, service);
                }
                self.default_allow
            }
        }
    }

    /// Add or update a policy rule at runtime.
    pub fn put_rule(&mut self, service: &str, allow: Vec<String>) {
        self.rules.insert(service.to_string(), allow);
    }

    /// Remove a policy rule.
    pub fn remove_rule(&mut self, service: &str) {
        self.rules.remove(service);
    }

    /// List all rules.
    pub fn rules(&self) -> &HashMap<String, Vec<String>> {
        &self.rules
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether any rules are defined.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an identity matches a pattern.
///
/// - `"*"` matches everything
/// - `"*.zone.ztlp"` matches any identity ending in `.zone.ztlp`
/// - Otherwise, exact match
fn matches_pattern(identity: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return identity.ends_with(&format!(".{}", suffix))
            || identity == suffix;
    }
    identity == pattern
}

/// Extract a string value from a line like `key = "value"`.
fn extract_string_value(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    let val = line[eq + 1..].trim();
    if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
        Some(val[1..val.len() - 1].to_string())
    } else {
        Some(val.to_string())
    }
}

/// Extract a string array from a line like `allow = ["a", "b", "c"]`.
fn extract_string_array(line: &str) -> Option<Vec<String>> {
    let eq = line.find('=')?;
    let val = line[eq + 1..].trim();
    if !val.starts_with('[') || !val.ends_with(']') {
        return None;
    }
    let inner = &val[1..val.len() - 1];
    let items: Vec<String> = inner.split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some(items)
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern("steve.ops.ztlp", "steve.ops.ztlp"));
        assert!(!matches_pattern("steve.ops.ztlp", "mike.ops.ztlp"));
    }

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(matches_pattern("steve.ops.ztlp", "*.ops.ztlp"));
        assert!(matches_pattern("mike.ops.ztlp", "*.ops.ztlp"));
        assert!(!matches_pattern("steve.techs.ztlp", "*.ops.ztlp"));
    }

    #[test]
    fn test_matches_pattern_wildcard_exact_suffix() {
        // "*.ops.ztlp" should also match "ops.ztlp" itself
        assert!(matches_pattern("ops.ztlp", "*.ops.ztlp"));
    }

    #[test]
    fn test_matches_pattern_universal() {
        assert!(matches_pattern("anything", "*"));
        assert!(matches_pattern("", "*"));
    }

    #[test]
    fn test_policy_from_toml() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["steve.ops.ztlp", "*.admins.ztlp"]

[[services]]
name = "rdp"
allow = ["*.techs.ztlp"]

[[services]]
name = "web"
allow = ["*"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        assert_eq!(engine.len(), 3);
        assert!(!engine.default_allow);

        // SSH rules
        assert!(engine.authorize("steve.ops.ztlp", "ssh"));
        assert!(engine.authorize("bob.admins.ztlp", "ssh"));
        assert!(!engine.authorize("mike.techs.ztlp", "ssh"));

        // RDP rules
        assert!(engine.authorize("mike.techs.ztlp", "rdp"));
        assert!(!engine.authorize("steve.ops.ztlp", "rdp"));

        // Web — open to all
        assert!(engine.authorize("anyone.anywhere.ztlp", "web"));

        // Unknown service — default deny
        assert!(!engine.authorize("steve.ops.ztlp", "database"));
    }

    #[test]
    fn test_policy_default_allow() {
        let toml = r#"
default = "allow"

[[services]]
name = "ssh"
allow = ["*.admins.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();

        // SSH restricted
        assert!(engine.authorize("bob.admins.ztlp", "ssh"));
        assert!(!engine.authorize("mike.techs.ztlp", "ssh"));

        // Unknown service — default allow
        assert!(engine.authorize("anyone", "anything"));
    }

    #[test]
    fn test_policy_no_rules() {
        let engine = PolicyEngine::new();
        // Default deny, no rules
        assert!(!engine.authorize("anyone", "ssh"));
    }

    #[test]
    fn test_policy_allow_all() {
        let engine = PolicyEngine::allow_all();
        // No rules, but default is allow
        assert!(engine.authorize("anyone", "anything"));
    }

    #[test]
    fn test_policy_put_remove_rule() {
        let mut engine = PolicyEngine::new();
        engine.put_rule("ssh", vec!["*.ops.ztlp".to_string()]);

        assert!(engine.authorize("steve.ops.ztlp", "ssh"));
        assert!(!engine.authorize("mike.techs.ztlp", "ssh"));

        engine.remove_rule("ssh");
        assert!(!engine.authorize("steve.ops.ztlp", "ssh")); // default deny
    }

    #[test]
    fn test_policy_hex_pubkey_identity() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["a1b2c3d4e5f6"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();

        // Hex pubkey as identity
        assert!(engine.authorize("a1b2c3d4e5f6", "ssh"));
        assert!(!engine.authorize("ffffff000000", "ssh"));
    }

    #[test]
    fn test_extract_string_value() {
        assert_eq!(extract_string_value(r#"name = "ssh""#), Some("ssh".to_string()));
        assert_eq!(extract_string_value(r#"default = "deny""#), Some("deny".to_string()));
    }

    #[test]
    fn test_extract_string_array() {
        let result = extract_string_array(r#"allow = ["a", "b", "*.c.ztlp"]"#).unwrap();
        assert_eq!(result, vec!["a", "b", "*.c.ztlp"]);
    }
}
