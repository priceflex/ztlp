//! Credential renewal daemon — monitors certificate lifetime and NS record TTLs.
//!
//! The renewal daemon runs as a background task within the agent and handles:
//!
//! - **Certificate renewal**: Monitors cert expiry, sends RENEW (0x09) to NS
//!   at the configured threshold (default: 67% of lifetime).
//! - **NS record refresh**: Re-registers KEY and SVC records at 75% TTL
//!   with ±10% jitter to prevent thundering-herd effects.
//! - **Config hot-reload**: Watches `~/.ztlp/agent.toml` for changes.
//!
//! ## Renewal timeline
//!
//! ```text
//! Certificate (90 day lifetime):
//!   Day 0 ─────── Day 60 (67%) ─── Day 68 (75%) ─── Day 90 (expiry)
//!                  ↑ first try      ↑ urgent retry    ↑ too late
//!
//! NS record (24 hour TTL):
//!   Hour 0 ────── Hour 18 (75%) ── Hour 22 ────────── Hour 24 (expiry)
//!                  ↑ refresh         ↑ retry           ↑ stale
//! ```
//!
//! ## Jitter
//!
//! Jitter prevents all agents from refreshing at exactly the same time.
//! Default: ±10% of TTL. For a 24h TTL, refresh happens between 16.2h–19.8h.

use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default certificate renewal threshold (fraction of lifetime elapsed).
pub const DEFAULT_CERT_THRESHOLD: f64 = 0.67;

/// Default NS record refresh threshold (fraction of TTL elapsed).
pub const DEFAULT_NS_REFRESH_THRESHOLD: f64 = 0.75;

/// Default jitter factor (±10% of TTL).
pub const DEFAULT_JITTER: f64 = 0.10;

/// Check interval for the renewal task.
pub const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum number of consecutive renewal failures before backing off.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Backoff multiplier after MAX_CONSECUTIVE_FAILURES.
const FAILURE_BACKOFF_MULTIPLIER: u32 = 4;

// ─── Credential state ───────────────────────────────────────────────────────

/// Type of credential being managed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKind {
    /// Node certificate (Ed25519 identity cert, long-lived).
    Certificate,
    /// NS KEY record (public key registration, medium TTL).
    NsKeyRecord,
    /// NS SVC record (service endpoint, medium TTL).
    NsSvcRecord,
    /// Relay Admission Token secret (rotated periodically).
    RatSecret,
}

impl std::fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialKind::Certificate => write!(f, "certificate"),
            CredentialKind::NsKeyRecord => write!(f, "NS KEY record"),
            CredentialKind::NsSvcRecord => write!(f, "NS SVC record"),
            CredentialKind::RatSecret => write!(f, "RAT secret"),
        }
    }
}

/// State of a managed credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalState {
    /// Credential is fresh, no action needed.
    Fresh,
    /// Renewal window is open — should attempt renewal.
    Due,
    /// Renewal in progress.
    Renewing,
    /// Renewal failed, will retry.
    Failed {
        /// Number of consecutive failures.
        attempts: u32,
        /// When to next retry.
        next_retry: Instant,
    },
    /// Credential has expired (renewal too late).
    Expired,
}

/// A tracked credential with renewal metadata.
#[derive(Debug, Clone)]
pub struct ManagedCredential {
    /// What kind of credential.
    pub kind: CredentialKind,
    /// Descriptive label (e.g., zone name, record name).
    pub label: String,
    /// When the credential was issued/registered.
    pub issued_at: Instant,
    /// How long the credential is valid.
    pub lifetime: Duration,
    /// Renewal threshold (fraction of lifetime, e.g., 0.67).
    pub threshold: f64,
    /// Jitter factor (e.g., 0.10 for ±10%).
    pub jitter: f64,
    /// Computed renewal deadline (with jitter applied).
    pub renewal_at: Instant,
    /// Current renewal state.
    pub state: RenewalState,
    /// Total successful renewals.
    pub renewals_count: u64,
    /// Last successful renewal time.
    pub last_renewed: Option<Instant>,
    /// Consecutive failure count.
    pub consecutive_failures: u32,
}

impl ManagedCredential {
    /// Create a new managed credential.
    pub fn new(
        kind: CredentialKind,
        label: impl Into<String>,
        issued_at: Instant,
        lifetime: Duration,
        threshold: f64,
        jitter: f64,
    ) -> Self {
        let renewal_at = compute_renewal_time(issued_at, lifetime, threshold, jitter);

        Self {
            kind,
            label: label.into(),
            issued_at,
            lifetime,
            threshold,
            jitter,
            renewal_at,
            state: RenewalState::Fresh,
            renewals_count: 0,
            last_renewed: None,
            consecutive_failures: 0,
        }
    }

    /// Check if this credential needs renewal.
    pub fn needs_renewal(&self) -> bool {
        match self.state {
            RenewalState::Fresh => Instant::now() >= self.renewal_at,
            RenewalState::Due => true,
            RenewalState::Failed { next_retry, .. } => Instant::now() >= next_retry,
            RenewalState::Renewing | RenewalState::Expired => false,
        }
    }

    /// Check if the credential has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.issued_at + self.lifetime
    }

    /// Time until expiry.
    pub fn time_to_expiry(&self) -> Duration {
        let expires_at = self.issued_at + self.lifetime;
        let now = Instant::now();
        if now >= expires_at {
            Duration::ZERO
        } else {
            expires_at - now
        }
    }

    /// Time until renewal is due.
    pub fn time_to_renewal(&self) -> Duration {
        let now = Instant::now();
        if now >= self.renewal_at {
            Duration::ZERO
        } else {
            self.renewal_at - now
        }
    }

    /// Fraction of lifetime elapsed (0.0 to 1.0+).
    pub fn elapsed_fraction(&self) -> f64 {
        let elapsed = Instant::now().duration_since(self.issued_at);
        elapsed.as_secs_f64() / self.lifetime.as_secs_f64()
    }

    /// Mark renewal as started.
    pub fn mark_renewing(&mut self) {
        self.state = RenewalState::Renewing;
    }

    /// Mark renewal as successful. Resets the credential with a new lifetime.
    pub fn mark_renewed(&mut self, new_lifetime: Duration) {
        let now = Instant::now();
        self.issued_at = now;
        self.lifetime = new_lifetime;
        self.renewal_at = compute_renewal_time(now, new_lifetime, self.threshold, self.jitter);
        self.state = RenewalState::Fresh;
        self.renewals_count += 1;
        self.last_renewed = Some(now);
        self.consecutive_failures = 0;

        debug!(
            "{} {} renewed (next renewal in {:?})",
            self.kind,
            self.label,
            self.time_to_renewal()
        );
    }

    /// Mark renewal as failed.
    pub fn mark_failed(&mut self) {
        self.consecutive_failures += 1;
        let backoff = compute_failure_backoff(self.consecutive_failures);
        self.state = RenewalState::Failed {
            attempts: self.consecutive_failures,
            next_retry: Instant::now() + backoff,
        };

        warn!(
            "{} {} renewal failed (attempt {}, retry in {:?})",
            self.kind, self.label, self.consecutive_failures, backoff
        );
    }

    /// Update state based on current time.
    pub fn tick(&mut self) {
        match self.state {
            RenewalState::Fresh => {
                if self.is_expired() {
                    self.state = RenewalState::Expired;
                } else if Instant::now() >= self.renewal_at {
                    self.state = RenewalState::Due;
                }
            }
            RenewalState::Failed { next_retry, .. } => {
                if self.is_expired() {
                    self.state = RenewalState::Expired;
                } else if Instant::now() >= next_retry {
                    self.state = RenewalState::Due;
                }
            }
            _ => {}
        }
    }
}

/// Summary info for a managed credential (for status reporting).
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub kind: CredentialKind,
    pub label: String,
    pub state: RenewalState,
    pub lifetime_secs: u64,
    pub elapsed_fraction: f64,
    pub time_to_expiry_secs: u64,
    pub time_to_renewal_secs: u64,
    pub renewals_count: u64,
}

// ─── Credential tracker ─────────────────────────────────────────────────────

/// Tracks all managed credentials for the agent.
pub struct CredentialTracker {
    credentials: Vec<ManagedCredential>,
}

impl Default for CredentialTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }

    /// Register a credential for tracking.
    pub fn register(&mut self, cred: ManagedCredential) {
        info!(
            "tracking {} '{}' (lifetime {:?}, renew at {:.0}%)",
            cred.kind,
            cred.label,
            cred.lifetime,
            cred.threshold * 100.0
        );
        self.credentials.push(cred);
    }

    /// Tick all credentials — update states based on current time.
    pub fn tick(&mut self) {
        for cred in &mut self.credentials {
            cred.tick();
        }
    }

    /// Get all credentials that need renewal.
    pub fn due_for_renewal(&self) -> Vec<&ManagedCredential> {
        self.credentials
            .iter()
            .filter(|c| c.needs_renewal())
            .collect()
    }

    /// Get all expired credentials.
    pub fn expired(&self) -> Vec<&ManagedCredential> {
        self.credentials.iter().filter(|c| c.is_expired()).collect()
    }

    /// Get credential info for all tracked credentials.
    pub fn info(&self) -> Vec<CredentialInfo> {
        self.credentials
            .iter()
            .map(|c| CredentialInfo {
                kind: c.kind.clone(),
                label: c.label.clone(),
                state: c.state.clone(),
                lifetime_secs: c.lifetime.as_secs(),
                elapsed_fraction: c.elapsed_fraction(),
                time_to_expiry_secs: c.time_to_expiry().as_secs(),
                time_to_renewal_secs: c.time_to_renewal().as_secs(),
                renewals_count: c.renewals_count,
            })
            .collect()
    }

    /// Get a mutable reference to a credential by label.
    pub fn get_mut(&mut self, label: &str) -> Option<&mut ManagedCredential> {
        self.credentials.iter_mut().find(|c| c.label == label)
    }

    /// Number of tracked credentials.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Check if tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Compute the renewal time with jitter.
///
/// Returns `issued_at + (lifetime * threshold) ± (lifetime * jitter)`.
fn compute_renewal_time(
    issued_at: Instant,
    lifetime: Duration,
    threshold: f64,
    jitter: f64,
) -> Instant {
    let base = lifetime.as_secs_f64() * threshold;

    // Apply deterministic jitter based on a hash of the current time.
    // In a real implementation, this would use a proper PRNG, but for
    // testing determinism we use a simple approach.
    let jitter_range = lifetime.as_secs_f64() * jitter;
    // Generate a pseudo-random value in [-1, 1] using the nanosecond
    // part of the issued time as a seed.
    let seed = issued_at.elapsed().as_nanos() as u64;
    let jitter_value = ((seed % 1000) as f64 / 500.0 - 1.0) * jitter_range;

    let renewal_secs = (base + jitter_value).max(0.0);
    issued_at + Duration::from_secs_f64(renewal_secs)
}

/// Compute backoff for consecutive failures.
fn compute_failure_backoff(consecutive_failures: u32) -> Duration {
    if consecutive_failures <= MAX_CONSECUTIVE_FAILURES {
        // Linear backoff: 1min, 2min, 3min, 4min, 5min
        Duration::from_secs(consecutive_failures as u64 * 60)
    } else {
        // After max failures, longer backoff: 20min, then 20min...
        Duration::from_secs(
            MAX_CONSECUTIVE_FAILURES as u64 * 60 * FAILURE_BACKOFF_MULTIPLIER as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_cred(label: &str, lifetime_secs: u64) -> ManagedCredential {
        ManagedCredential::new(
            CredentialKind::Certificate,
            label,
            Instant::now(),
            Duration::from_secs(lifetime_secs),
            DEFAULT_CERT_THRESHOLD,
            0.0, // No jitter for deterministic tests
        )
    }

    fn ns_cred(label: &str, ttl_secs: u64) -> ManagedCredential {
        ManagedCredential::new(
            CredentialKind::NsKeyRecord,
            label,
            Instant::now(),
            Duration::from_secs(ttl_secs),
            DEFAULT_NS_REFRESH_THRESHOLD,
            0.0,
        )
    }

    #[test]
    fn test_fresh_credential() {
        let cred = cert_cred("node.corp.ztlp", 86400 * 90);
        assert!(!cred.needs_renewal());
        assert!(!cred.is_expired());
        assert_eq!(cred.state, RenewalState::Fresh);
    }

    #[test]
    fn test_expired_credential() {
        let mut cred = ManagedCredential::new(
            CredentialKind::Certificate,
            "expired.ztlp",
            Instant::now() - Duration::from_secs(100),
            Duration::from_secs(50), // already past lifetime
            0.67,
            0.0,
        );
        cred.tick();
        assert!(cred.is_expired());
        assert_eq!(cred.state, RenewalState::Expired);
    }

    #[test]
    fn test_due_for_renewal() {
        // Create credential that's already past threshold
        let mut cred = ManagedCredential::new(
            CredentialKind::NsKeyRecord,
            "test.ztlp",
            Instant::now() - Duration::from_secs(80),
            Duration::from_secs(100),
            0.75, // 75% = 75s, we're at 80s
            0.0,
        );
        cred.tick();
        assert_eq!(cred.state, RenewalState::Due);
        assert!(cred.needs_renewal());
    }

    #[test]
    fn test_mark_renewed() {
        let mut cred = cert_cred("test.ztlp", 3600);
        cred.mark_renewing();
        assert_eq!(cred.state, RenewalState::Renewing);

        cred.mark_renewed(Duration::from_secs(7200));
        assert_eq!(cred.state, RenewalState::Fresh);
        assert_eq!(cred.renewals_count, 1);
        assert!(cred.last_renewed.is_some());
        assert_eq!(cred.lifetime, Duration::from_secs(7200));
    }

    #[test]
    fn test_mark_failed_backoff() {
        let mut cred = cert_cred("test.ztlp", 3600);
        cred.mark_failed();
        assert_eq!(cred.consecutive_failures, 1);
        assert!(matches!(
            cred.state,
            RenewalState::Failed { attempts: 1, .. }
        ));

        cred.mark_failed();
        assert_eq!(cred.consecutive_failures, 2);
        assert!(matches!(
            cred.state,
            RenewalState::Failed { attempts: 2, .. }
        ));
    }

    #[test]
    fn test_renewal_resets_failures() {
        let mut cred = cert_cred("test.ztlp", 3600);
        cred.mark_failed();
        cred.mark_failed();
        cred.mark_failed();
        assert_eq!(cred.consecutive_failures, 3);

        cred.mark_renewed(Duration::from_secs(3600));
        assert_eq!(cred.consecutive_failures, 0);
        assert_eq!(cred.state, RenewalState::Fresh);
    }

    #[test]
    fn test_elapsed_fraction() {
        let cred = ManagedCredential::new(
            CredentialKind::Certificate,
            "test.ztlp",
            Instant::now() - Duration::from_secs(50),
            Duration::from_secs(100),
            0.67,
            0.0,
        );
        let frac = cred.elapsed_fraction();
        assert!((0.49..=0.51).contains(&frac), "fraction: {}", frac);
    }

    #[test]
    fn test_time_to_expiry() {
        let cred = ManagedCredential::new(
            CredentialKind::Certificate,
            "test.ztlp",
            Instant::now() - Duration::from_secs(50),
            Duration::from_secs(100),
            0.67,
            0.0,
        );
        let tte = cred.time_to_expiry();
        assert!(tte.as_secs() >= 49 && tte.as_secs() <= 51);
    }

    #[test]
    fn test_compute_failure_backoff() {
        assert_eq!(compute_failure_backoff(1), Duration::from_secs(60));
        assert_eq!(compute_failure_backoff(2), Duration::from_secs(120));
        assert_eq!(compute_failure_backoff(5), Duration::from_secs(300));
        assert_eq!(compute_failure_backoff(6), Duration::from_secs(1200)); // 20min
        assert_eq!(compute_failure_backoff(100), Duration::from_secs(1200));
    }

    #[test]
    fn test_credential_display() {
        assert_eq!(format!("{}", CredentialKind::Certificate), "certificate");
        assert_eq!(format!("{}", CredentialKind::NsKeyRecord), "NS KEY record");
        assert_eq!(format!("{}", CredentialKind::NsSvcRecord), "NS SVC record");
        assert_eq!(format!("{}", CredentialKind::RatSecret), "RAT secret");
    }

    // ── Tracker tests ───────────────────────────────────────────────────

    #[test]
    fn test_tracker_register_and_info() {
        let mut tracker = CredentialTracker::new();
        assert!(tracker.is_empty());

        tracker.register(cert_cred("node.corp.ztlp", 86400 * 90));
        tracker.register(ns_cred("node.corp.ztlp", 86400));

        assert_eq!(tracker.len(), 2);
        let info = tracker.info();
        assert_eq!(info.len(), 2);
    }

    #[test]
    fn test_tracker_due_for_renewal() {
        let mut tracker = CredentialTracker::new();

        // Fresh cert (not due)
        tracker.register(cert_cred("fresh.ztlp", 86400 * 90));

        // Already-past-threshold NS record
        tracker.register(ManagedCredential::new(
            CredentialKind::NsKeyRecord,
            "stale.ztlp",
            Instant::now() - Duration::from_secs(80),
            Duration::from_secs(100),
            0.75,
            0.0,
        ));

        tracker.tick();
        let due = tracker.due_for_renewal();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].label, "stale.ztlp");
    }

    #[test]
    fn test_tracker_get_mut() {
        let mut tracker = CredentialTracker::new();
        tracker.register(cert_cred("test.ztlp", 3600));

        let cred = tracker.get_mut("test.ztlp").unwrap();
        cred.mark_renewing();
        assert_eq!(cred.state, RenewalState::Renewing);
    }

    #[test]
    fn test_tracker_expired() {
        let mut tracker = CredentialTracker::new();
        tracker.register(ManagedCredential::new(
            CredentialKind::Certificate,
            "dead.ztlp",
            Instant::now() - Duration::from_secs(200),
            Duration::from_secs(100),
            0.67,
            0.0,
        ));

        let expired = tracker.expired();
        assert_eq!(expired.len(), 1);
    }
}
