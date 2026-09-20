//! Shared hermetic HTTP server for transport tests (a tiny httptest.NewServer).

use std::io::{Read, Write};

/// Binds 127.0.0.1:0 and serves every request with the handler's response,
/// one connection per request (Connection: close). Returns the base URL.
// Each test crate includes `mod common`; the live stage suites use only the
// sandbox helpers below, so these must not warn there under `-D warnings`.
#[allow(dead_code)]
pub fn spawn_http_server<F>(handler: F) -> String
where
    F: Fn(&str, &[u8]) -> (u16, String, Vec<u8>) + Send + 'static,
{
    spawn_http_server_with_head(move |path, _head, body| handler(path, body))
}

/// Renders a caught handler panic as the 500 body: a panicking wire
/// assertion must reach the test as THIS error (an HttpStatus carrying the
/// message), not kill the listener and degrade the test's later requests
/// into opaque connection errors. Takes the payload Box by VALUE — a
/// `&Box<dyn Any>` coerced to `&dyn Any` produces a trait object pointing
/// at the Box itself, and every downcast then misses.
///
/// Corollary: a test that EXPECTS an `HttpStatus { status: 500 }` must not
/// assert inside its handler — a handler panic would satisfy it with the
/// panic body. Keep handler assertions in tests whose success path is 200.
fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    let msg = if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    };
    format!("ecpay mock server handler panicked: {msg}")
}

/// Like [`spawn_http_server`], but the handler also receives the raw
/// request head (request line + headers) — for asserting which HTTP client
/// sent the request.
#[allow(dead_code)]
pub fn spawn_http_server_with_head<F>(handler: F) -> String
where
    F: Fn(&str, &str, &[u8]) -> (u16, String, Vec<u8>) + Send + 'static,
{
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 8192];
            let head_end = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break buf.len(),
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    }
                    Err(_) => break buf.len(),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]);
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or("");
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_owned();
            let mut content_length = 0usize;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = buf[head_end.min(buf.len())..].to_vec();
            while body.len() < content_length {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            let (status, content_type, resp_body) = match std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| handler(&path, &head, &body)),
            ) {
                Ok(response) => response,
                Err(panic) => (
                    500,
                    "text/plain".to_owned(),
                    panic_message(panic).into_bytes(),
                ),
            };
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&resp_body);
        }
    });
    format!("http://{addr}/")
}

/// Serves every request with a 200 whose body is close-delimited: NO
/// Content-Length and no chunked framing, the peer reads until EOF. This is
/// the one shape the other helpers cannot produce (they always append
/// Content-Length), and it is what exercises the body-cap byte counter
/// rather than the up-front Content-Length check.
#[allow(dead_code)] // each test crate includes `mod common`; not all use this variant
pub fn spawn_close_delimited_server(body: Vec<u8>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
            // Drain the request head (and its Content-Length body) so the
            // client never sees a reset while still sending.
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 8192];
            let head_end = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break buf.len(),
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    }
                    Err(_) => break buf.len(),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]);
            let mut content_length = 0usize;
            for line in head.split("\r\n").skip(1) {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut have = buf.len().saturating_sub(head_end.min(buf.len()));
            while have < content_length {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => have += n,
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
            );
            let _ = stream.write_all(&body);
            // Dropping the stream sends FIN: that is the body's only delimiter.
        }
    });
    format!("http://{addr}/")
}

/// Like [`spawn_http_server`], but the handler supplies status line and the
/// complete response headers — needed to emit a real `Location` so the
/// no-redirect policy is actually exercised (reqwest only redirects on a
/// parseable `Location`).
#[allow(dead_code)] // each test crate includes `mod common`; not all use this variant
pub fn spawn_http_server_raw<F>(handler: F) -> String
where
    F: Fn(&str, &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + 'static,
{
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 8192];
            let head_end = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break buf.len(),
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    }
                    Err(_) => break buf.len(),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]);
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or("");
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_owned();
            let mut content_length = 0usize;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = buf[head_end.min(buf.len())..].to_vec();
            while body.len() < content_length {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            let (status, headers, resp_body) = match std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| handler(&path, &body)),
            ) {
                Ok(response) => response,
                Err(panic) => (
                    500,
                    vec![("Content-Type".to_owned(), "text/plain".to_owned())],
                    panic_message(panic).into_bytes(),
                ),
            };
            let mut response = format!("HTTP/1.1 {status}\r\n");
            for (k, v) in &headers {
                response.push_str(&format!("{k}: {v}\r\n"));
            }
            response.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            ));
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&resp_body);
        }
    });
    format!("http://{addr}/")
}

/// Helpers shared by the LIVE stage suites (stage_smoke / stage_probes /
/// sandbox_*). Previously each suite carried its own copy — a date-format
/// bug would have needed five fixes.
// Each test crate includes `mod common`; only the live stage suites use
// these helpers, so the rest must not warn under `-D warnings`.
#[allow(dead_code)]
pub mod sandbox {
    /// Current Taipei time as ECPay's `yyyy/MM/dd HH:mm:ss`, std-only
    /// (Howard Hinnant's civil_from_days).
    pub fn taipei_now() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 8 * 3600; // UTC+8
        let days = secs.div_euclid(86_400);
        let tod = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{y:04}/{m:02}/{d:02} {:02}:{:02}:{:02}",
            tod / 3600,
            tod % 3600 / 60,
            tod % 60
        )
    }

    /// Today's Taipei date as `yyyy-MM-dd` (the invoice/B2B wire date format).
    pub fn taipei_today() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 8 * 3600; // UTC+8
        let days = secs.div_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}-{m:02}-{d:02}")
    }

    /// A unique merchant-side number for parallel live tests: milliseconds
    /// alone collide when parallel tests start in the same ms (live-observed
    /// `0|廠商訂單編號重覆`), so a per-process counter is appended. Keep the
    /// tag ≤ 3 chars: tag + 13 millis + 3 seq must fit MerchantTradeNo's 20.
    pub fn unique_no(tag: &str) -> String {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{tag}{n}{seq:03}")
    }

    /// The millis-only variant for SERIAL contexts (stage_probes runs with
    /// `--test-threads=1`): no counter suffix, so longer tags fit the
    /// 20-char MerchantTradeNo cap (e.g. `PROBE` + 13 millis = 18).
    pub fn unique_no_millis(tag: &str) -> String {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        format!("{tag}{n}")
    }

    /// requests-style form encoding (quote_plus): alnum + `_.-~` literal,
    /// space -> `+`, everything else uppercase %XX.
    pub fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for &c in s.as_bytes() {
            match c {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                    out.push(c as char)
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{c:02X}")),
            }
        }
        out
    }
}
