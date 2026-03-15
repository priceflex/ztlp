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
//! - Group membership: `"group:techs@zone.ztlp"` checks if the identity's
//!   owner user is a member of the named group (requires NS query)
//! - Role matching: `"role:admin"` checks if the identity's owner user has
//!   the specified role (requires NS query)
//! - Hex pubkey fallback: if no NS name is available, the client's X25519
//!   public key (hex-encoded) is used as identity

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

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

        info!(
            "loaded {} policy rules (default: {})",
            engine.rules.len(),
            if engine.default_allow {
                "allow"
            } else {
                "deny"
            }
        );

        Ok(engine)
    }

    /// Check if an identity is authorized to access a service (synchronous).
    ///
    /// `identity` is either a ZTLP-NS zone name or hex-encoded public key.
    /// `service` is the service name from the DstSvcID field.
    ///
    /// **Note:** This method does NOT support `group:` or `role:` patterns.
    /// Use `authorize_async` with an `NsResolver` for full policy support.
    pub fn authorize(&self, identity: &str, service: &str) -> bool {
        match self.rules.get(service) {
            Some(patterns) => {
                let allowed = patterns.iter().any(|p| matches_pattern(identity, p));
                if allowed {
                    debug!("policy ALLOW: {} → {}", identity, service);
                } else {
                    warn!(
                        "policy DENY: {} → {} (not in allow list)",
                        identity, service
                    );
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

    /// Check if an identity is authorized, with full `group:` and `role:` support.
    ///
    /// When a pattern starts with `group:`, queries NS for the GROUP record
    /// and checks if the identity (or its owning user) is in the members list.
    ///
    /// When a pattern starts with `role:`, queries NS for the identity's owner
    /// USER record and checks the role field.
    ///
    /// Falls back to synchronous pattern matching for exact/wildcard patterns.
    pub async fn authorize_async(
        &self,
        identity: &str,
        service: &str,
        resolver: &dyn NsResolver,
    ) -> bool {
        match self.rules.get(service) {
            Some(patterns) => {
                let mut allowed = false;
                for p in patterns {
                    if matches_pattern_async(identity, p, resolver).await {
                        allowed = true;
                        break;
                    }
                }
                if allowed {
                    debug!("policy ALLOW: {} → {}", identity, service);
                } else {
                    warn!(
                        "policy DENY: {} → {} (not in allow list)",
                        identity, service
                    );
                }
                allowed
            }
            None => {
                if self.default_allow {
                    debug!("policy ALLOW (default): {} → {}", identity, service);
                } else {
                    warn!("policy DENY (no rule): {} → {}", identity, service);
                }
                self.default_allow
            }
        }
    }

    /// Returns true if any pattern in the loaded rules uses `group:` or `role:`.
    pub fn has_identity_patterns(&self) -> bool {
        self.rules.values().any(|patterns| {
            patterns
                .iter()
                .any(|p| p.starts_with("group:") || p.starts_with("role:"))
        })
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

use std::future::Future;
use std::pin::Pin;

/// Trait for resolving identity information from ZTLP-NS.
///
/// Implementations query the NS server to resolve group membership,
/// user roles, and device-to-user ownership mappings.
///
/// Methods return boxed futures for dyn-compatibility.
pub trait NsResolver: Send + Sync {
    /// Get the members of a group by name (e.g., "techs@tunnel.ztlp").
    /// Returns a list of user names, or empty vec on error/not found.
    fn group_members(
        &self,
        group_name: &str,
    ) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + '_>>;

    /// Get the role of a user by name (e.g., "alice@tunnel.ztlp").
    /// Returns the role string (e.g., "admin", "tech", "user") or None.
    fn user_role(
        &self,
        user_name: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>>;

    /// Resolve a device/KEY name to its owning user name.
    /// E.g., "alice.tunnel.ztlp" → "alice@tunnel.ztlp"
    /// Returns None if no DEVICE record exists or no owner is set.
    fn device_owner(
        &self,
        device_name: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>>;
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
        return identity.ends_with(&format!(".{}", suffix)) || identity == suffix;
    }
    identity == pattern
}

/// Async pattern matcher that supports `group:` and `role:` prefixes.
///
/// For `group:techs@zone.ztlp`:
///   1. Query GROUP record → get members list
///   2. Check if the identity name is directly in members (user identity)
///   3. If not, resolve device → owner, check if owner is in members
///
/// For `role:admin`:
///   1. Try querying USER record for the identity directly
///   2. If not found, resolve device → owner, then query owner's USER record
///   3. Check if the role matches
async fn matches_pattern_async(identity: &str, pattern: &str, resolver: &dyn NsResolver) -> bool {
    // Fast path: non-identity patterns use sync matching
    if !pattern.starts_with("group:") && !pattern.starts_with("role:") {
        return matches_pattern(identity, pattern);
    }

    if let Some(group_name) = pattern.strip_prefix("group:") {
        let members = resolver.group_members(group_name).await;
        if members.is_empty() {
            debug!("group '{}' has no members or not found", group_name);
            return false;
        }

        // Check 1: Is the identity itself in the members list?
        // (handles case where identity IS a user name, e.g., "alice@tunnel.ztlp")
        if members.iter().any(|m| m == identity) {
            debug!(
                "identity '{}' is directly a member of '{}'",
                identity, group_name
            );
            return true;
        }

        // Check 2: Resolve device → owner, check if owner is in members
        if let Some(owner) = resolver.device_owner(identity).await {
            if members.iter().any(|m| m == &owner) {
                debug!(
                    "identity '{}' owner '{}' is a member of '{}'",
                    identity, owner, group_name
                );
                return true;
            }
        }

        debug!(
            "identity '{}' is NOT a member of '{}'",
            identity, group_name
        );
        false
    } else if let Some(required_role) = pattern.strip_prefix("role:") {
        // Check 1: Try the identity as a user name directly
        if let Some(role) = resolver.user_role(identity).await {
            if role == required_role {
                debug!("identity '{}' has role '{}'", identity, required_role);
                return true;
            }
        }

        // Check 2: Resolve device → owner, check owner's role
        if let Some(owner) = resolver.device_owner(identity).await {
            if let Some(role) = resolver.user_role(&owner).await {
                if role == required_role {
                    debug!(
                        "identity '{}' owner '{}' has role '{}'",
                        identity, owner, required_role
                    );
                    return true;
                }
            }
        }

        debug!(
            "identity '{}' does NOT have role '{}'",
            identity, required_role
        );
        false
    } else {
        false
    }
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
    let items: Vec<String> = inner
        .split(',')
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
        assert_eq!(
            extract_string_value(r#"name = "ssh""#),
            Some("ssh".to_string())
        );
        assert_eq!(
            extract_string_value(r#"default = "deny""#),
            Some("deny".to_string())
        );
    }

    #[test]
    fn test_extract_string_array() {
        let result = extract_string_array(r#"allow = ["a", "b", "*.c.ztlp"]"#).unwrap();
        assert_eq!(result, vec!["a", "b", "*.c.ztlp"]);
    }

    #[test]
    fn test_has_identity_patterns() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["group:techs@tunnel.ztlp", "group:admins@tunnel.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        assert!(engine.has_identity_patterns());

        let toml2 = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["alice.tunnel.ztlp"]
"#;
        let engine2 = PolicyEngine::from_toml(toml2).unwrap();
        assert!(!engine2.has_identity_patterns());
    }

    #[test]
    fn test_role_pattern_detection() {
        let toml = r#"
default = "deny"

[[services]]
name = "admin"
allow = ["role:admin"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        assert!(engine.has_identity_patterns());
    }

    // ── Async tests with mock NsResolver ────────────────────────────

    /// Mock NS resolver for testing group/role policy evaluation.
    struct MockResolver {
        groups: HashMap<String, Vec<String>>,
        users: HashMap<String, String>,   // user_name → role
        devices: HashMap<String, String>, // device_name → owner
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                groups: HashMap::new(),
                users: HashMap::new(),
                devices: HashMap::new(),
            }
        }
    }

    impl NsResolver for MockResolver {
        fn group_members(
            &self,
            group_name: &str,
        ) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + '_>> {
            let result = self.groups.get(group_name).cloned().unwrap_or_default();
            Box::pin(async move { result })
        }

        fn user_role(
            &self,
            user_name: &str,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
            let result = self.users.get(user_name).cloned();
            Box::pin(async move { result })
        }

        fn device_owner(
            &self,
            device_name: &str,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
            let result = self.devices.get(device_name).cloned();
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn test_group_policy_direct_user() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["group:techs@tunnel.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        let mut resolver = MockResolver::new();
        resolver.groups.insert(
            "techs@tunnel.ztlp".to_string(),
            vec![
                "alice@tunnel.ztlp".to_string(),
                "bob@tunnel.ztlp".to_string(),
            ],
        );

        // User identity directly in group
        assert!(
            engine
                .authorize_async("alice@tunnel.ztlp", "ssh", &resolver)
                .await
        );
        assert!(
            !engine
                .authorize_async("eve@tunnel.ztlp", "ssh", &resolver)
                .await
        );
    }

    #[tokio::test]
    async fn test_group_policy_device_to_owner() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["group:techs@tunnel.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        let mut resolver = MockResolver::new();
        resolver.groups.insert(
            "techs@tunnel.ztlp".to_string(),
            vec!["alice@tunnel.ztlp".to_string()],
        );
        // Device "alice.tunnel.ztlp" is owned by user "alice@tunnel.ztlp"
        resolver.devices.insert(
            "alice.tunnel.ztlp".to_string(),
            "alice@tunnel.ztlp".to_string(),
        );
        // Eve's device
        resolver
            .devices
            .insert("eve.tunnel.ztlp".to_string(), "eve@tunnel.ztlp".to_string());

        // Device resolves to owner who IS in the group
        assert!(
            engine
                .authorize_async("alice.tunnel.ztlp", "ssh", &resolver)
                .await
        );
        // Device resolves to owner who is NOT in the group
        assert!(
            !engine
                .authorize_async("eve.tunnel.ztlp", "ssh", &resolver)
                .await
        );
    }

    #[tokio::test]
    async fn test_role_policy() {
        let toml = r#"
default = "deny"

[[services]]
name = "admin"
allow = ["role:admin"]

[[services]]
name = "ssh"
allow = ["role:tech", "role:admin"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        let mut resolver = MockResolver::new();
        resolver
            .users
            .insert("bob@tunnel.ztlp".to_string(), "admin".to_string());
        resolver
            .users
            .insert("alice@tunnel.ztlp".to_string(), "tech".to_string());
        resolver
            .users
            .insert("eve@tunnel.ztlp".to_string(), "user".to_string());
        // Device mappings
        resolver.devices.insert(
            "alice.tunnel.ztlp".to_string(),
            "alice@tunnel.ztlp".to_string(),
        );
        resolver
            .devices
            .insert("eve.tunnel.ztlp".to_string(), "eve@tunnel.ztlp".to_string());

        // Admin service: only admin role
        assert!(
            engine
                .authorize_async("bob@tunnel.ztlp", "admin", &resolver)
                .await
        );
        assert!(
            !engine
                .authorize_async("alice@tunnel.ztlp", "admin", &resolver)
                .await
        );

        // SSH service: tech or admin
        assert!(
            engine
                .authorize_async("alice.tunnel.ztlp", "ssh", &resolver)
                .await
        );
        assert!(
            !engine
                .authorize_async("eve.tunnel.ztlp", "ssh", &resolver)
                .await
        );
    }

    #[tokio::test]
    async fn test_mixed_patterns() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["group:techs@tunnel.ztlp", "bob.tunnel.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        let mut resolver = MockResolver::new();
        resolver.groups.insert(
            "techs@tunnel.ztlp".to_string(),
            vec!["alice@tunnel.ztlp".to_string()],
        );
        resolver.devices.insert(
            "alice.tunnel.ztlp".to_string(),
            "alice@tunnel.ztlp".to_string(),
        );

        // bob.tunnel.ztlp matches exact pattern
        assert!(
            engine
                .authorize_async("bob.tunnel.ztlp", "ssh", &resolver)
                .await
        );
        // alice.tunnel.ztlp matches via group (device → owner → group member)
        assert!(
            engine
                .authorize_async("alice.tunnel.ztlp", "ssh", &resolver)
                .await
        );
        // eve matches nothing
        assert!(
            !engine
                .authorize_async("eve.tunnel.ztlp", "ssh", &resolver)
                .await
        );
    }

    #[tokio::test]
    async fn test_group_not_found() {
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["group:nonexistent@tunnel.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        let resolver = MockResolver::new(); // Empty — no groups

        assert!(
            !engine
                .authorize_async("alice.tunnel.ztlp", "ssh", &resolver)
                .await
        );
    }

    #[tokio::test]
    async fn test_sync_authorize_ignores_group_patterns() {
        // The sync `authorize` doesn't resolve groups — it treats "group:..." as a
        // literal string, which won't match any identity. This is expected.
        let toml = r#"
default = "deny"

[[services]]
name = "ssh"
allow = ["group:techs@tunnel.ztlp"]
"#;
        let engine = PolicyEngine::from_toml(toml).unwrap();
        // Sync authorize: "group:techs@tunnel.ztlp" is not == "alice.tunnel.ztlp"
        assert!(!engine.authorize("alice.tunnel.ztlp", "ssh"));
    }
}
