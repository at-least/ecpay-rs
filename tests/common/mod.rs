//! Shared hermetic HTTP server for transport tests (a tiny httptest.NewServer).

use std::io::{Read, Write};

/// Binds 127.0.0.1:0 and serves every request with the handler's response,
/// one connection per request (Connection: close). Returns the base URL.
pub fn spawn_http_server<F>(handler: F) -> String
where
    F: Fn(&str, &[u8]) -> (u16, String, Vec<u8>) + Send + 'static,
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
            let (status, content_type, resp_body) = handler(&path, &body);
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
            let (status, headers, resp_body) = handler(&path, &body);
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
