//! Tests for VIP proxy HTTP keep-alive awareness and stream reuse protocol.
//!
//! Covers:
//! 1. HttpTracker Content-Length parsing
//! 2. HttpTracker chunked transfer-encoding detection
//! 3. HttpTracker request completion counting
//! 4. HttpTracker Connection: close handling
//! 5. StreamState transitions (Active → Reopening → Active)
//! 6. FRAME_STREAM_RESET constant value

use ztlp_proto::vip::{HttpState, HttpTracker, StreamState, FRAME_STREAM_RESET};

// ─── HttpTracker: Content-Length ─────────────────────────────────────────────

#[test]
fn test_http_tracker_content_length_basic() {
    let mut tracker = HttpTracker::new();
    assert_eq!(tracker.requests_completed(), 0);
    assert!(matches!(tracker.state(), HttpState::WaitingForResponse));

    // Feed a complete HTTP response with Content-Length
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    tracker.feed(response);

    assert_eq!(tracker.requests_completed(), 1);
}

#[test]
fn test_http_tracker_content_length_zero() {
    let mut tracker = HttpTracker::new();

    // Response with zero-length body (e.g., 204 No Content)
    let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    tracker.feed(response);

    assert_eq!(tracker.requests_completed(), 1);
}

#[test]
fn test_http_tracker_content_length_split_delivery() {
    let mut tracker = HttpTracker::new();

    // Headers arrive first
    tracker.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");
    assert_eq!(tracker.requests_completed(), 0);

    // Body arrives in chunks
    tracker.feed(b"hello"); // 5 bytes
    assert_eq!(tracker.requests_completed(), 0);

    tracker.feed(b"world"); // 5 more bytes = 10 total
    assert_eq!(tracker.requests_completed(), 1);
}

#[test]
fn test_http_tracker_content_length_headers_split() {
    let mut tracker = HttpTracker::new();

    // Headers split across two feeds
    tracker.feed(b"HTTP/1.1 200 OK\r\nContent-Len");
    assert_eq!(tracker.requests_completed(), 0);

    tracker.feed(b"gth: 3\r\n\r\nabc");
    assert_eq!(tracker.requests_completed(), 1);
}

// ─── HttpTracker: Chunked Transfer-Encoding ─────────────────────────────────

#[test]
fn test_http_tracker_chunked_basic() {
    let mut tracker = HttpTracker::new();

    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n0\r\n\r\n";
    tracker.feed(response);

    assert_eq!(tracker.requests_completed(), 1);
}

#[test]
fn test_http_tracker_chunked_split_delivery() {
    let mut tracker = HttpTracker::new();

    tracker.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert_eq!(tracker.requests_completed(), 0);

    tracker.feed(b"5\r\nhello\r\n");
    assert_eq!(tracker.requests_completed(), 0);

    tracker.feed(b"0\r\n\r\n");
    assert_eq!(tracker.requests_completed(), 1);
}

// ─── HttpTracker: Request Completion Count ──────────────────────────────────

#[test]
fn test_http_tracker_multiple_requests() {
    let mut tracker = HttpTracker::new();

    // First request-response
    tracker.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    assert_eq!(tracker.requests_completed(), 1);

    // Second request-response
    tracker.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone");
    assert_eq!(tracker.requests_completed(), 2);

    // Third request-response
    tracker.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(tracker.requests_completed(), 3);
}

#[test]
fn test_http_tracker_pipelined_responses() {
    let mut tracker = HttpTracker::new();

    // Two complete responses in a single feed (HTTP pipelining)
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n\
                 abcHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nxy";
    tracker.feed(data);

    assert_eq!(tracker.requests_completed(), 2);
}

// ─── HttpTracker: Connection: close ─────────────────────────────────────────

#[test]
fn test_http_tracker_connection_close() {
    let mut tracker = HttpTracker::new();

    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\ndone";
    tracker.feed(response);

    assert_eq!(tracker.requests_completed(), 1);
    assert!(tracker.is_connection_close());
}

#[test]
fn test_http_tracker_no_connection_close() {
    let mut tracker = HttpTracker::new();

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    tracker.feed(response);

    assert!(!tracker.is_connection_close());
}

#[test]
fn test_http_tracker_connection_close_persists() {
    let mut tracker = HttpTracker::new();

    // First response with Connection: close
    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
    tracker.feed(response);

    assert!(tracker.is_connection_close());
    // The flag should persist even after the response completes
    assert!(tracker.is_connection_close());
}

// ─── StreamState transitions ────────────────────────────────────────────────

#[test]
fn test_stream_state_active() {
    let state = StreamState::Active { stream_id: 42 };
    assert!(state.is_active());
    assert!(!state.is_closed());
    assert_eq!(state.stream_id(), Some(42));
}

#[test]
fn test_stream_state_reopening() {
    let state = StreamState::Reopening;
    assert!(!state.is_active());
    assert!(!state.is_closed());
    assert_eq!(state.stream_id(), None);
}

#[test]
fn test_stream_state_closed() {
    let state = StreamState::Closed;
    assert!(!state.is_active());
    assert!(state.is_closed());
    assert_eq!(state.stream_id(), None);
}

#[test]
fn test_stream_state_transition_active_to_reopening_to_active() {
    // Simulate: gateway closes stream → reopen with new stream_id
    let mut state = StreamState::Active { stream_id: 1 };

    // Gateway sends FRAME_CLOSE → transition to Reopening
    state = StreamState::Reopening;
    assert_eq!(state, StreamState::Reopening);

    // New FRAME_OPEN succeeds → transition to Active with new stream_id
    state = StreamState::Active { stream_id: 2 };
    assert_eq!(state.stream_id(), Some(2));
    assert!(state.is_active());
}

#[test]
fn test_stream_state_transition_active_to_closed() {
    // Simulate: TCP connection closes → go straight to Closed
    let mut state = StreamState::Active { stream_id: 1 };
    state = StreamState::Closed;
    assert!(state.is_closed());
}

#[test]
fn test_stream_state_transition_reopening_to_closed() {
    // Simulate: gateway closed stream, TCP also dies → Closed
    let mut state = StreamState::Reopening;
    state = StreamState::Closed;
    assert!(state.is_closed());
}

#[test]
fn test_stream_state_equality() {
    assert_eq!(
        StreamState::Active { stream_id: 5 },
        StreamState::Active { stream_id: 5 }
    );
    assert_ne!(
        StreamState::Active { stream_id: 5 },
        StreamState::Active { stream_id: 6 }
    );
    assert_eq!(StreamState::Reopening, StreamState::Reopening);
    assert_eq!(StreamState::Closed, StreamState::Closed);
    assert_ne!(StreamState::Active { stream_id: 1 }, StreamState::Closed);
}

// ─── FRAME_STREAM_RESET constant ────────────────────────────────────────────

#[test]
fn test_frame_stream_reset_value() {
    assert_eq!(FRAME_STREAM_RESET, 0x0B);
}

#[test]
fn test_frame_stream_reset_wire_format() {
    // Verify the wire format: [FRAME_STREAM_RESET | stream_id(4 BE)]
    let stream_id: u32 = 42;
    let mut frame = Vec::with_capacity(5);
    frame.push(FRAME_STREAM_RESET);
    frame.extend_from_slice(&stream_id.to_be_bytes());

    assert_eq!(frame.len(), 5);
    assert_eq!(frame[0], 0x0B);
    assert_eq!(
        u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]),
        42
    );
}

// ─── HttpTracker: Edge Cases ────────────────────────────────────────────────

#[test]
fn test_http_tracker_new_is_waiting() {
    let tracker = HttpTracker::new();
    assert!(matches!(tracker.state(), HttpState::WaitingForResponse));
    assert_eq!(tracker.requests_completed(), 0);
    assert!(!tracker.is_connection_close());
}

#[test]
fn test_http_tracker_case_insensitive_headers() {
    let mut tracker = HttpTracker::new();

    // Mixed-case headers should still be parsed
    let response = b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 3\r\nCONNECTION: CLOSE\r\n\r\nabc";
    tracker.feed(response);

    assert_eq!(tracker.requests_completed(), 1);
    // Note: our parser lowercases and compares, "close" != "CLOSE" lowered = "close"
    // Actually to_ascii_lowercase converts CLOSE to close. Let me verify the logic.
    // lower.strip_prefix("connection:") gives " CLOSE", trim() gives "CLOSE",
    // but the comparison is val.trim() == "close". "CLOSE" != "close".
    // Hmm — the header line "CONNECTION: CLOSE" lowered is "connection: close",
    // strip_prefix("connection:") gives " close", trim gives "close". ✓
    assert!(tracker.is_connection_close());
}

#[test]
fn test_http_tracker_chunked_case_insensitive() {
    let mut tracker = HttpTracker::new();

    let response = b"HTTP/1.1 200 OK\r\nTRANSFER-ENCODING: CHUNKED\r\n\r\n0\r\n\r\n";
    tracker.feed(response);

    assert_eq!(tracker.requests_completed(), 1);
}
