//! Custom domain → ZTLP zone mapping.
//!
//! Maps user-friendly domain names (e.g., `fileserver.internal.techrockstars.com`)
//! to ZTLP-NS names (e.g., `fileserver.techrockstars.ztlp`) so that companies
//! can use their own domain names while ZTLP handles identity underneath.
//!
//! ## Examples
//!
//! ```text
//! domain_map:
//!   "internal.techrockstars.com" → "techrockstars.ztlp"
//!   "vpn.acmecorp.com"          → "acme.techrockstars.ztlp"
//!
//! Resolution:
//!   "fileserver.internal.techrockstars.com"
//!     → strip suffix "internal.techrockstars.com"
//!     → prefix = "fileserver"
//!     → ZTLP name = "fileserver.techrockstars.ztlp"
//! ```

use std::collections::HashMap;

/// A domain mapper that translates custom domain names to ZTLP-NS names.
#[derive(Debug, Clone)]
pub struct DomainMapper {
    /// Map of custom domain suffix → ZTLP zone.
    /// Sorted by suffix length (longest first) for correct matching.
    mappings: Vec<(String, String)>,
}

impl DomainMapper {
    /// Create a new domain mapper from a config-style HashMap.
    ///
    /// The map keys are custom domain suffixes and values are ZTLP zones.
    pub fn new(domain_map: &HashMap<String, String>) -> Self {
        let mut mappings: Vec<(String, String)> = domain_map
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect();

        // Sort by suffix length descending — longest match wins
        mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self { mappings }
    }

    /// Create an empty mapper (no custom domains configured).
    pub fn empty() -> Self {
        Self {
            mappings: Vec::new(),
        }
    }

    /// Try to map a hostname to a ZTLP-NS name.
    ///
    /// Returns `Some(ztlp_name)` if the hostname matches a configured custom
    /// domain suffix, or `None` if it doesn't match anything.
    ///
    /// # Examples
    ///
    /// ```text
    /// mapper.resolve("fileserver.internal.techrockstars.com")
    ///   → Some("fileserver.techrockstars.ztlp")
    ///
    /// mapper.resolve("db.vpn.acmecorp.com")
    ///   → Some("db.acme.techrockstars.ztlp")
    ///
    /// mapper.resolve("google.com")
    ///   → None
    /// ```
    pub fn resolve(&self, hostname: &str) -> Option<String> {
        let hostname_lower = hostname.to_lowercase();

        for (suffix, ztlp_zone) in &self.mappings {
            // Check if hostname ends with `.{suffix}` (with dot separator)
            let with_dot = format!(".{}", suffix);
            if let Some(prefix) = hostname_lower.strip_suffix(&with_dot) {
                if !prefix.is_empty() {
                    return Some(format!("{}.{}", prefix, ztlp_zone));
                }
            }

            // Also check exact match (bare zone, no prefix)
            if hostname_lower == *suffix {
                return Some(ztlp_zone.clone());
            }
        }

        None
    }

    /// Check if a hostname is a native `*.ztlp` name.
    pub fn is_ztlp_name(hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        lower.ends_with(".ztlp") || lower == "ztlp"
    }

    /// Check if a hostname should be handled by the agent.
    ///
    /// Returns `true` if it's a `*.ztlp` name or matches a custom domain mapping.
    pub fn should_handle(&self, hostname: &str) -> bool {
        Self::is_ztlp_name(hostname) || self.resolve(hostname).is_some()
    }

    /// Resolve a hostname to a ZTLP-NS name, handling both native `*.ztlp`
    /// names and custom domain mappings.
    ///
    /// For native ZTLP names, returns the name as-is.
    /// For custom domains, maps through the domain_map.
    /// For unrecognized hostnames, returns `None`.
    pub fn to_ztlp_name(&self, hostname: &str) -> Option<String> {
        if Self::is_ztlp_name(hostname) {
            Some(hostname.to_lowercase())
        } else {
            self.resolve(hostname)
        }
    }

    /// Returns the number of configured mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Returns true if no mappings are configured.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mapper() -> DomainMapper {
        let mut map = HashMap::new();
        map.insert(
            "internal.techrockstars.com".to_string(),
            "techrockstars.ztlp".to_string(),
        );
        map.insert(
            "vpn.acmecorp.com".to_string(),
            "acme.techrockstars.ztlp".to_string(),
        );
        map.insert(
            "internal.widgetinc.com".to_string(),
            "widget.techrockstars.ztlp".to_string(),
        );
        DomainMapper::new(&map)
    }

    #[test]
    fn test_basic_resolution() {
        let mapper = test_mapper();

        assert_eq!(
            mapper.resolve("fileserver.internal.techrockstars.com"),
            Some("fileserver.techrockstars.ztlp".to_string())
        );

        assert_eq!(
            mapper.resolve("db.vpn.acmecorp.com"),
            Some("db.acme.techrockstars.ztlp".to_string())
        );

        assert_eq!(
            mapper.resolve("nas.internal.widgetinc.com"),
            Some("nas.widget.techrockstars.ztlp".to_string())
        );
    }

    #[test]
    fn test_case_insensitive() {
        let mapper = test_mapper();

        assert_eq!(
            mapper.resolve("FileServer.Internal.TechRockStars.COM"),
            Some("fileserver.techrockstars.ztlp".to_string())
        );
    }

    #[test]
    fn test_no_match() {
        let mapper = test_mapper();

        assert_eq!(mapper.resolve("google.com"), None);
        assert_eq!(mapper.resolve("random.example.org"), None);
        assert_eq!(mapper.resolve("techrockstars.com"), None); // no "internal." prefix
    }

    #[test]
    fn test_bare_zone_match() {
        let mapper = test_mapper();

        // Bare zone (no hostname prefix) returns the ZTLP zone itself
        assert_eq!(
            mapper.resolve("internal.techrockstars.com"),
            Some("techrockstars.ztlp".to_string())
        );
    }

    #[test]
    fn test_nested_subdomain() {
        let mapper = test_mapper();

        // Multi-level prefix
        assert_eq!(
            mapper.resolve("a.b.c.internal.techrockstars.com"),
            Some("a.b.c.techrockstars.ztlp".to_string())
        );
    }

    #[test]
    fn test_is_ztlp_name() {
        assert!(DomainMapper::is_ztlp_name("server.corp.ztlp"));
        assert!(DomainMapper::is_ztlp_name("server.ZTLP"));
        assert!(DomainMapper::is_ztlp_name("a.b.c.ztlp"));
        assert!(!DomainMapper::is_ztlp_name("server.com"));
        assert!(!DomainMapper::is_ztlp_name("ztlp.com"));
    }

    #[test]
    fn test_should_handle() {
        let mapper = test_mapper();

        // Native ZTLP names
        assert!(mapper.should_handle("server.corp.ztlp"));

        // Custom domain mappings
        assert!(mapper.should_handle("fileserver.internal.techrockstars.com"));

        // Not handled
        assert!(!mapper.should_handle("google.com"));
    }

    #[test]
    fn test_to_ztlp_name() {
        let mapper = test_mapper();

        // Native ZTLP — pass through
        assert_eq!(
            mapper.to_ztlp_name("server.corp.ztlp"),
            Some("server.corp.ztlp".to_string())
        );

        // Custom domain — map
        assert_eq!(
            mapper.to_ztlp_name("fileserver.internal.techrockstars.com"),
            Some("fileserver.techrockstars.ztlp".to_string())
        );

        // Unknown — None
        assert_eq!(mapper.to_ztlp_name("google.com"), None);
    }

    #[test]
    fn test_empty_mapper() {
        let mapper = DomainMapper::empty();
        assert!(mapper.is_empty());
        assert_eq!(mapper.len(), 0);

        // Still handles native ZTLP names
        assert!(mapper.should_handle("server.corp.ztlp"));
        assert!(!mapper.should_handle("server.internal.techrockstars.com"));
    }

    #[test]
    fn test_longest_match_wins() {
        // If "corp.example.com" and "example.com" are both mapped,
        // "server.corp.example.com" should match "corp.example.com"
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), "example.ztlp".to_string());
        map.insert(
            "corp.example.com".to_string(),
            "corp.example.ztlp".to_string(),
        );
        let mapper = DomainMapper::new(&map);

        assert_eq!(
            mapper.resolve("server.corp.example.com"),
            Some("server.corp.example.ztlp".to_string())
        );

        assert_eq!(
            mapper.resolve("server.example.com"),
            Some("server.example.ztlp".to_string())
        );
    }
}
