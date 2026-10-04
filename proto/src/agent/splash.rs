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

/// Messages rotated on the splash page (approved list; see plan section 7).
pub const MESSAGES: [&str; 8] = [
    "Securing your connection",
    "Zipping through the internet securely",
    "Look mom, no passwords",
    "Knocking politely on the zero-trust door",
    "Teaching the packets to whisper",
    "Checking everyone's name tag",
    "Building you a private tunnel",
    "Almost there, it is worth the wait",
];

/// Escape text for HTML element content and quoted attributes.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const TEMPLATE: &str = include_str!("splash.html");
const LOGO_PNG: &[u8] = include_bytes!("splash_logo.png");

/// MESSAGES as a JS array literal. `<` is escaped so the text can never
/// close the surrounding `<script>` element.
fn messages_js() -> String {
    let items: Vec<String> = MESSAGES
        .iter()
        .map(|m| {
            let mut q = String::from("\"");
            for c in m.chars() {
                match c {
                    '\\' => q.push_str("\\\\"),
                    '"' => q.push_str("\\\""),
                    '<' => q.push_str("\\u003c"),
                    c => q.push(c),
                }
            }
            q.push('"');
            q
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Complete HTTP/1.1 response (head + body) for the splash page.
///
/// `host` is attacker-influenced (DNS / Host header) and is HTML-escaped.
pub fn splash_response(host: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    // Substitute LOGO and MESSAGES first and HOST last, so that
    // host text can never be re-interpreted as a placeholder.
    let body = TEMPLATE
        .replace("{{LOGO}}", &STANDARD.encode(LOGO_PNG))
        .replace("{{MESSAGES}}", &messages_js())
        .replace("{{HOST}}", &escape_html(host));
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; img-src data:; \
         style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'\r\n\
         \r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
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

    // ---- splash page ----
    fn split_resp(r: &[u8]) -> (String, String) {
        let i = r
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head end");
        (
            String::from_utf8(r[..i].to_vec()).unwrap(),
            String::from_utf8(r[i + 4..].to_vec()).unwrap(),
        )
    }

    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    #[test]
    fn escape_html_escapes_all_specials() {
        assert_eq!(
            escape_html(r#"<script>"a" & 'b'</script>"#),
            "&lt;script&gt;&quot;a&quot; &amp; &#39;b&#39;&lt;/script&gt;"
        );
    }

    #[test]
    fn splash_is_200_html_with_correct_length() {
        let r = splash_response("app.zone.ztlp");
        let (head, body) = split_resp(&r);
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
        assert_eq!(
            header(&head, "content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            header(&head, "content-length")
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            body.len()
        );
    }

    #[test]
    fn splash_headers_no_store_close_nosniff() {
        let (head, _) = split_resp(&splash_response("a.ztlp"));
        assert_eq!(header(&head, "cache-control"), Some("no-store"));
        assert_eq!(header(&head, "connection"), Some("close"));
        assert_eq!(header(&head, "x-content-type-options"), Some("nosniff"));
    }

    #[test]
    fn splash_csp_locks_down_but_allows_ready_poll() {
        let (head, _) = split_resp(&splash_response("a.ztlp"));
        let csp = header(&head, "content-security-policy").expect("CSP header");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("img-src data:"), "{csp}");
        // The page polls /.ztlp/ready on its own origin; default-src 'none'
        // would block that without this.
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(!csp.contains("http"), "no external origins: {csp}");
    }

    #[test]
    fn splash_hostname_is_escaped_and_never_raw() {
        let evil = "<img src=x onerror=alert(1)>.ztlp";
        let (_, body) = split_resp(&splash_response(evil));
        assert!(!body.contains(evil));
        assert!(!body.contains("<img src=x"));
        assert!(body.contains("&lt;img src=x onerror=alert(1)&gt;.ztlp"));
    }

    #[test]
    fn splash_shows_hostname() {
        let (_, body) = split_resp(&splash_response("billing.acme.ztlp"));
        assert!(body.contains("billing.acme.ztlp"));
    }

    #[test]
    fn splash_has_logo_data_uri_and_no_external_requests() {
        let (_, body) = split_resp(&splash_response("a.ztlp"));
        assert!(body.contains("src=\"data:image/png;base64,"));
        for bad in ["http://", "https://", "src=\"//", "url(//", "@import"] {
            assert!(!body.contains(bad), "external ref {bad}");
        }
    }

    #[test]
    fn splash_polls_ready_endpoint_and_reloads() {
        let (_, body) = split_resp(&splash_response("a.ztlp"));
        assert!(body.contains("/.ztlp/ready"));
        assert!(body.contains("location.reload()"));
        assert!(body.contains("500")); // poll interval ms
    }

    #[test]
    fn splash_embeds_every_message_and_rotation() {
        let (_, body) = split_resp(&splash_response("a.ztlp"));
        for m in MESSAGES {
            // apostrophes are JSON/JS-escaped inside the script; match a stem
            let stem = m.split('\'').next().unwrap();
            assert!(body.contains(stem), "missing message {m}");
        }
        assert!(body.contains("3000")); // rotate every ~3s
    }

    #[test]
    fn splash_gives_up_after_60s_with_retry_button() {
        let (_, body) = split_resp(&splash_response("a.ztlp"));
        assert!(body.contains("60000"));
        assert!(body.to_lowercase().contains("retry"));
    }

    #[test]
    fn splash_supports_dark_and_reduced_motion() {
        let (_, body) = split_resp(&splash_response("a.ztlp"));
        assert!(body.contains("prefers-color-scheme: dark"));
        assert!(body.contains("prefers-reduced-motion"));
    }

    #[test]
    fn dump_splash_for_manual_review() {
        // Only writes when asked: SPLASH_DUMP=/path/out.html cargo test ...
        if let Ok(path) = std::env::var("SPLASH_DUMP") {
            let r = splash_response("billing.acme.ztlp");
            let (_, body) = split_resp(&r);
            std::fs::write(path, body).unwrap();
        }
    }

    #[test]
    fn splash_under_size_budget() {
        let r = splash_response("a.ztlp");
        assert!(r.len() < 60 * 1024, "splash is {} bytes", r.len());
    }
}
