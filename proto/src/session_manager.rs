//! Multi-session manager for the ZTLP listener.
//!
//! Handles concurrent ZTLP sessions on a single UDP socket by dispatching
//! received packets to the correct session based on SessionID. Provides:
//!
//! - Session tracking with a HashMap<SessionId, SessionState>
//! - Half-open session timeout (defense against memory exhaustion)
//! - Max sessions enforcement with REJECT(CAPACITY_FULL)
//! - Proper cleanup when sessions close
//!
//! ## Architecture
//!
//! The dispatcher runs as a single task that reads all UDP packets from the
//! shared socket. It routes:
//! - Handshake packets (HELLO) → handshake handler (new sessions)
//! - Data packets → per-session channel → bridge task
//!
//! Each established session gets a `tokio::sync::mpsc` channel for receiving
//! its demuxed packets, so bridge tasks don't race on the socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex, Notify};

use crate::packet::SessionId;

/// Tracks the state of a single session in the multi-session manager.
#[derive(Debug)]
pub struct SessionEntry {
    /// When this session was created.
    pub created_at: Instant,
    /// When we last saw activity.
    pub last_activity: Instant,
    /// Whether the handshake is complete.
    pub established: bool,
    /// Channel sender for routing packets to this session's bridge task.
    pub tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// Peer address (client endpoint).
    pub peer_addr: SocketAddr,
}

/// Shared state for the session manager.
pub struct SessionManager {
    /// Active sessions indexed by SessionId.
    pub sessions: Mutex<HashMap<SessionId, SessionEntry>>,
    /// Maximum allowed concurrent sessions.
    pub max_sessions: usize,
    /// Half-open session timeout.
    pub half_open_timeout: Duration,
    /// Established session idle timeout.
    pub idle_timeout: Duration,
    /// Count of active sessions (atomic for fast reads).
    pub active_count: AtomicUsize,
    /// Notifier for session cleanup events.
    pub cleanup_notify: Notify,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
            half_open_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            active_count: AtomicUsize::new(0),
            cleanup_notify: Notify::new(),
        }
    }

    /// Check if we can accept a new session.
    pub fn can_accept(&self) -> bool {
        self.active_count.load(Ordering::Relaxed) < self.max_sessions
    }

    /// Register a new half-open session.
    ///
    /// Returns a receiver channel for the session's bridge task.
    pub async fn register(
        &self,
        session_id: SessionId,
        peer_addr: SocketAddr,
        buffer_size: usize,
    ) -> Option<mpsc::Receiver<(Vec<u8>, SocketAddr)>> {
        let mut sessions = self.sessions.lock().await;
        if sessions.len() >= self.max_sessions {
            return None;
        }

        let (tx, rx) = mpsc::channel(buffer_size);
        let now = Instant::now();
        sessions.insert(
            session_id,
            SessionEntry {
                created_at: now,
                last_activity: now,
                established: false,
                tx,
                peer_addr,
            },
        );
        self.active_count.fetch_add(1, Ordering::Relaxed);
        Some(rx)
    }

    /// Mark a session as established (handshake complete).
    pub async fn set_established(&self, session_id: &SessionId) {
        let mut sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.get_mut(session_id) {
            entry.established = true;
            entry.last_activity = Instant::now();
        }
    }

    /// Remove a session.
    pub async fn remove(&self, session_id: &SessionId) {
        let mut sessions = self.sessions.lock().await;
        if sessions.remove(session_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.cleanup_notify.notify_one();
        }
    }

    /// Route a packet to the correct session.
    ///
    /// Returns `true` if the packet was delivered, `false` if no session found.
    pub async fn route_packet(
        &self,
        session_id: &SessionId,
        data: Vec<u8>,
        from: SocketAddr,
    ) -> bool {
        let sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.get(session_id) {
            // Try send; if the channel is full, the session is overwhelmed — drop
            entry.tx.try_send((data, from)).is_ok()
        } else {
            false
        }
    }

    /// Touch a session (update last_activity timestamp).
    pub async fn touch(&self, session_id: &SessionId) {
        let mut sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.get_mut(session_id) {
            entry.last_activity = Instant::now();
        }
    }

    /// Clean up expired sessions.
    ///
    /// Returns the SessionIds of removed sessions.
    pub async fn cleanup_expired(&self) -> Vec<SessionId> {
        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();
        let mut expired = Vec::new();

        sessions.retain(|sid, entry| {
            let timeout = if entry.established {
                self.idle_timeout
            } else {
                self.half_open_timeout
            };

            if now.duration_since(entry.last_activity) > timeout {
                expired.push(*sid);
                false
            } else {
                true
            }
        });

        let removed = expired.len();
        if removed > 0 {
            self.active_count.fetch_sub(removed, Ordering::Relaxed);
        }

        expired
    }

    /// Get the current session count.
    pub fn count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Get a snapshot of session IDs (for testing/monitoring).
    pub async fn session_ids(&self) -> Vec<SessionId> {
        let sessions = self.sessions.lock().await;
        sessions.keys().copied().collect()
    }

    /// Check if a session exists.
    pub async fn has_session(&self, session_id: &SessionId) -> bool {
        let sessions = self.sessions.lock().await;
        sessions.contains_key(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn test_register_and_count() {
        let mgr = SessionManager::new(100);
        assert_eq!(mgr.count(), 0);

        let sid = SessionId::generate();
        let rx = mgr.register(sid, test_addr(5000), 32).await;
        assert!(rx.is_some());
        assert_eq!(mgr.count(), 1);
        assert!(mgr.has_session(&sid).await);
    }

    #[tokio::test]
    async fn test_max_sessions_enforced() {
        let mgr = SessionManager::new(2);

        let s1 = SessionId::generate();
        let s2 = SessionId::generate();
        let s3 = SessionId::generate();

        assert!(mgr.register(s1, test_addr(5001), 32).await.is_some());
        assert!(mgr.register(s2, test_addr(5002), 32).await.is_some());
        // Third should fail — at capacity
        assert!(mgr.register(s3, test_addr(5003), 32).await.is_none());
        assert_eq!(mgr.count(), 2);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let mgr = SessionManager::new(100);
        let sid = SessionId::generate();
        let _rx = mgr.register(sid, test_addr(5000), 32).await.unwrap();
        assert_eq!(mgr.count(), 1);

        mgr.remove(&sid).await;
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.has_session(&sid).await);
    }

    #[tokio::test]
    async fn test_route_packet() {
        let mgr = SessionManager::new(100);
        let sid = SessionId::generate();
        let addr = test_addr(5000);
        let mut rx = mgr.register(sid, addr, 32).await.unwrap();

        let data = vec![1, 2, 3];
        assert!(mgr.route_packet(&sid, data.clone(), addr).await);

        let (recv_data, recv_addr) = rx.recv().await.unwrap();
        assert_eq!(recv_data, data);
        assert_eq!(recv_addr, addr);
    }

    #[tokio::test]
    async fn test_route_unknown_session() {
        let mgr = SessionManager::new(100);
        let sid = SessionId::generate();
        assert!(!mgr.route_packet(&sid, vec![1], test_addr(5000)).await);
    }

    #[tokio::test]
    async fn test_cleanup_half_open_expired() {
        let _mgr = SessionManager::new(100);
        // Override timeout to 0 for testing
        let mgr = SessionManager {
            half_open_timeout: Duration::from_millis(1),
            ..SessionManager::new(100)
        };

        let sid = SessionId::generate();
        let _rx = mgr.register(sid, test_addr(5000), 32).await.unwrap();

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(10)).await;

        let expired = mgr.cleanup_expired().await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], sid);
        assert_eq!(mgr.count(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_established_survives() {
        let mgr = SessionManager {
            half_open_timeout: Duration::from_millis(1),
            idle_timeout: Duration::from_secs(60),
            ..SessionManager::new(100)
        };

        let sid = SessionId::generate();
        let _rx = mgr.register(sid, test_addr(5000), 32).await.unwrap();
        mgr.set_established(&sid).await;

        // Wait past half-open timeout
        tokio::time::sleep(Duration::from_millis(10)).await;

        let expired = mgr.cleanup_expired().await;
        assert!(expired.is_empty());
        assert_eq!(mgr.count(), 1);
    }

    #[tokio::test]
    async fn test_can_accept() {
        let mgr = SessionManager::new(1);
        assert!(mgr.can_accept());

        let _rx = mgr
            .register(SessionId::generate(), test_addr(5000), 32)
            .await;
        assert!(!mgr.can_accept());
    }

    #[tokio::test]
    async fn test_half_open_attack_protection() {
        // Simulate many half-open sessions with short timeout
        let mgr = SessionManager {
            half_open_timeout: Duration::from_millis(10),
            ..SessionManager::new(100)
        };

        // Fill up with half-open sessions
        let mut receivers = Vec::new();
        for i in 0..100 {
            let sid = SessionId::generate();
            if let Some(rx) = mgr.register(sid, test_addr(5000 + i), 32).await {
                receivers.push(rx);
            }
        }
        assert_eq!(mgr.count(), 100);
        assert!(!mgr.can_accept());

        // Wait for cleanup
        tokio::time::sleep(Duration::from_millis(50)).await;
        let expired = mgr.cleanup_expired().await;
        assert_eq!(expired.len(), 100);
        assert_eq!(mgr.count(), 0);
        assert!(mgr.can_accept());
    }

    #[tokio::test]
    async fn test_multiple_concurrent_sessions() {
        let mgr = SessionManager::new(100);
        let mut sids = Vec::new();
        let mut receivers = Vec::new();

        for i in 0..5 {
            let sid = SessionId::generate();
            let rx = mgr.register(sid, test_addr(6000 + i), 32).await.unwrap();
            mgr.set_established(&sid).await;
            sids.push(sid);
            receivers.push(rx);
        }

        assert_eq!(mgr.count(), 5);

        // Route packets to each session
        for (i, sid) in sids.iter().enumerate() {
            let data = vec![i as u8; 10];
            assert!(
                mgr.route_packet(sid, data, test_addr(6000 + i as u16))
                    .await
            );
        }

        // Verify each session received its own packet
        for (i, rx) in receivers.iter_mut().enumerate() {
            let (data, _) = rx.recv().await.unwrap();
            assert_eq!(data, vec![i as u8; 10]);
        }
    }
}
