//! Browser splash page shown while the tunnel connects.
//! See docs/BROWSER-SPLASH-PAGE-PLAN.md.

/// True only for a real browser page load (top-level navigation).
///
/// Requires GET, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document` and an
/// `Accept` that includes `text/html`. User-Agent is deliberately ignored.
pub fn is_browser_navigation(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let mut lines = text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return false;
    };
    let mut parts = request_line.split(' ');
    if parts.next() != Some("GET") || !request_line.contains(" HTTP/1.") {
        return false;
    }
    let (mut mode, mut dest, mut html) = (false, false, false);
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_ascii_lowercase();
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-fetch-mode" => mode = value == "navigate",
            "sec-fetch-dest" => dest = value == "document",
            "accept" => html = value.contains("text/html"),
            _ => {}
        }
    }
    mode && dest && html
}

/// Max bytes buffered while looking for the end of the request head.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Outcome of reading a request head. Bytes are never dropped: the caller
/// replays `bytes()` into the tunnel in every case.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadRead {
    /// Buffer contains a full head (through `\r\n\r\n`); may hold extra body bytes.
    Complete(Vec<u8>),
    /// Cap hit, timeout, EOF or read error before the head ended.
    Incomplete(Vec<u8>),
}

impl HeadRead {
    pub fn bytes(&self) -> &[u8] {
        match self {
            HeadRead::Complete(b) | HeadRead::Incomplete(b) => b,
        }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            HeadRead::Complete(b) | HeadRead::Incomplete(b) => b,
        }
    }
}

/// Read until `\r\n\r\n`, at most `max` bytes, within `timeout` overall.
///
/// The timeout is a single deadline for the whole head (not per read), so a
/// client trickling one byte at a time cannot hold the connection open.
pub async fn read_request_head<R>(
    reader: &mut R,
    max: usize,
    timeout: std::time::Duration,
) -> HeadRead
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::with_capacity(1024.min(max));
    let mut chunk = [0u8; 2048];
    // Where to resume the terminator search (terminator may straddle reads).
    let mut scanned = 0usize;

    loop {
        if buf.len() >= max {
            return HeadRead::Incomplete(buf);
        }
        let want = chunk.len().min(max - buf.len());
        match tokio::time::timeout_at(deadline, reader.read(&mut chunk[..want])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return HeadRead::Incomplete(buf),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
        let from = scanned.saturating_sub(3);
        if buf[from..].windows(4).any(|w| w == b"\r\n\r\n") {
            return HeadRead::Complete(buf);
        }
        scanned = buf.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut s = format!("{method} / HTTP/1.1\r\nHost: app.zone.ztlp\r\n");
        for (k, v) in headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str("\r\n");
        s.into_bytes()
    }

    const HTML: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    fn nav() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Accept", HTML),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ]
    }

    #[test]
    fn chrome_navigation_is_browser() {
        let mut h = nav();
        h.push(("User-Agent", "Mozilla/5.0 Chrome/120"));
        assert!(is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn firefox_navigation_is_browser() {
        let h = vec![
            ("Accept", "text/html,application/xhtml+xml"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
        ];
        assert!(is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn header_names_and_values_case_insensitive() {
        let h = vec![
            ("accept", "TEXT/HTML"),
            ("sec-fetch-mode", "Navigate"),
            ("SEC-FETCH-DEST", "Document"),
        ];
        assert!(is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn curl_is_not_browser() {
        assert!(!is_browser_navigation(&req(
            "GET",
            &[("User-Agent", "curl/8.0"), ("Accept", "*/*")]
        )));
    }

    #[test]
    fn python_requests_is_not_browser() {
        let h = [("User-Agent", "python-requests/2.31"), ("Accept", "*/*")];
        assert!(!is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn fetch_cors_is_not_browser() {
        let h = vec![
            ("Accept", HTML),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
        ];
        assert!(!is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn post_navigation_is_not_browser() {
        assert!(!is_browser_navigation(&req("POST", &nav())));
    }

    #[test]
    fn iframe_dest_is_not_browser() {
        let h = vec![
            ("Accept", HTML),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "iframe"),
        ];
        assert!(!is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn missing_accept_is_not_browser() {
        let h = vec![
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ];
        assert!(!is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn accept_without_html_is_not_browser() {
        let h = vec![
            ("Accept", "application/json"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ];
        assert!(!is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn forged_user_agent_only_is_not_browser() {
        let h = [("User-Agent", "Mozilla/5.0 Chrome/120"), ("Accept", HTML)];
        assert!(!is_browser_navigation(&req("GET", &h)));
    }

    #[test]
    fn garbage_is_not_browser() {
        assert!(!is_browser_navigation(b"\x16\x03\x01 not http"));
        assert!(!is_browser_navigation(b""));
    }

    // ---- read_request_head ----
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    const T: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn head_in_one_read() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap();
        let got = read_request_head(&mut s, MAX_HEAD_BYTES, T).await;
        assert_eq!(
            got,
            HeadRead::Complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec())
        );
    }

    #[tokio::test]
    async fn head_split_across_reads_including_inside_terminator() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        let w = tokio::spawn(async move {
            for part in [&b"GET / HTTP/1.1\r\nHost: a\r"[..], b"\n\r", b"\n"] {
                c.write_all(part).await.unwrap();
                c.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            c
        });
        let got = read_request_head(&mut s, MAX_HEAD_BYTES, T).await;
        assert_eq!(
            got,
            HeadRead::Complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec())
        );
        drop(w.await.unwrap());
    }

    #[tokio::test]
    async fn extra_body_bytes_are_kept() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        c.write_all(b"POST / HTTP/1.1\r\n\r\nBODY").await.unwrap();
        let got = read_request_head(&mut s, MAX_HEAD_BYTES, T).await;
        assert_eq!(
            got,
            HeadRead::Complete(b"POST / HTTP/1.1\r\n\r\nBODY".to_vec())
        );
    }

    #[tokio::test]
    async fn oversize_head_is_incomplete_and_bytes_kept() {
        let (mut c, mut s) = tokio::io::duplex(64 * 1024);
        let junk = vec![b'a'; 40_000];
        c.write_all(&junk).await.unwrap();
        let got = read_request_head(&mut s, 1024, T).await;
        match got {
            HeadRead::Incomplete(b) => {
                assert!(b.len() >= 1024, "must keep what it read");
                assert!(b.iter().all(|&x| x == b'a'));
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_client_times_out_with_partial_bytes() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        c.write_all(b"GET / HT").await.unwrap();
        let got = read_request_head(&mut s, MAX_HEAD_BYTES, Duration::from_millis(500)).await;
        assert_eq!(got, HeadRead::Incomplete(b"GET / HT".to_vec()));
        drop(c);
    }

    #[tokio::test]
    async fn eof_before_end_of_head_is_incomplete() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        c.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        drop(c);
        let got = read_request_head(&mut s, MAX_HEAD_BYTES, T).await;
        assert_eq!(got, HeadRead::Incomplete(b"GET / HTTP/1.1\r\n".to_vec()));
    }

    #[tokio::test]
    async fn head_then_classifier_end_to_end() {
        let (mut c, mut s) = tokio::io::duplex(4096);
        c.write_all(&req("GET", &nav())).await.unwrap();
        let got = read_request_head(&mut s, MAX_HEAD_BYTES, T).await;
        assert!(matches!(got, HeadRead::Complete(_)));
        assert!(is_browser_navigation(got.bytes()));
    }
}
