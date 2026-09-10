//! Full protocol-flow E2E against a LOCAL simulator of ECPay's server
//! behavior — completely offline, runs in the default `cargo test`.
//!
//! The simulator implements the three server roles our library must
//! interoperate with, verified wire-compatible with the REAL stage server by
//! `tests/stage_smoke.rs` (the real server accepts this library's CheckMacValue
//! and its own responses re-verify) and by the official vectors:
//!
//! 1. `AioCheckOut/V5`  — verifies the checkout MAC, registers the order.
//! 2. Callback delivery — after "payment", POSTs the ECPay-shaped signed
//!    form to the merchant's ReturnURL (ServerPost), expecting `1|OK`.
//! 3. `QueryTradeInfo/V5` — answers with the ECPay-shaped, SIGNED
//!    query-string response (TradeStatus/SimulatePaid/TradeAmt…).
//!
//! What this proves end-to-end with zero human steps: checkout signing →
//! server acceptance → callback reception + verification (`verify_check_mac_value`)
//! → `1|OK` handling → authoritative paid state via `order_search` MAC
//! round-trip. What it deliberately does NOT prove: the MAC algorithm's
//! parity with ECPay (that is the stage smoke's job — a simulator built on
//! this crate's own crypto cannot prove it).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use ecpay::payment::{AioCheckOutParams, ChoosePayment};
use ecpay::Ecpay;

const MERCHANT_ID: &str = "3002607";
const HASH_KEY: &str = "pwFHCqoQZGmho4w6";
const HASH_IV: &str = "EkRm7iFT261dpevs";

#[derive(Default, Clone)]
struct Order {
    total_amount: u64,
    paid: bool,
}

#[derive(Default)]
struct SimulatorState {
    orders: HashMap<String, Order>,
    /// ReturnURLs the simulator delivered callbacks to, with the raw body it
    /// sent and the merchant's reply (for asserting `1|OK` handling).
    callback_log: Vec<(String, String, String)>,
}

/// One request's parsed form.
fn parse_form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in body.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.insert(unquote(k), unquote(v));
    }
    out
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

fn sign(params: &HashMap<String, String>) -> String {
    ecpay::check_mac_value(params, HASH_KEY, HASH_IV, 1).expect("simulator MAC")
}

fn respond(stream: &mut TcpStream, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Deliver the ECPay-side payment callback to the merchant's ReturnURL over
/// a raw socket (hand-rolled POST; no blocking-reqwest dependency).
fn deliver_callback(return_url: &str, form_body: &str) -> String {
    let (host_port, path) = return_url
        .strip_prefix("http://")
        .expect("local return_url")
        .split_once('/')
        .expect("return path");
    let mut stream = TcpStream::connect(host_port).expect("connect to ReturnURL");
    let request = format!(
        "POST /{path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form_body}",
        form_body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("write callback");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

/// The simulator: AioCheckOut (MAC check + order registration),
/// QueryTradeInfo (signed response), and a test-only payment trigger that
/// marks the order paid and delivers the signed callback like ECPay's
/// ServerPost.
fn spawn_simulator(state: Arc<Mutex<SimulatorState>>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind simulator");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 16384];
            let head_end = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break buf.len(),
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                    }
                    Err(_) => break buf.len(),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]);
            let path = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();
            let cl = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if !k.trim().eq_ignore_ascii_case("content-length") {
                        return None;
                    }
                    v.trim().parse::<usize>().ok()
                })
                .unwrap_or(0);
            let mut body = buf[head_end.min(buf.len())..].to_vec();
            while body.len() < cl {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            let params = parse_form(&String::from_utf8_lossy(&body));

            if path.ends_with("/Cashier/AioCheckOut/V5") {
                let got = params.get("CheckMacValue").cloned().unwrap_or_default();
                let want = sign(&params);
                if got != want {
                    respond(
                        &mut stream,
                        "text/html",
                        "交易失敗 訊息代碼:10200073 CheckMacValue Error",
                    );
                    continue;
                }
                let trade_no = params.get("MerchantTradeNo").cloned().unwrap_or_default();
                let key = trade_no.clone();
                let amount: u64 = params
                    .get("TotalAmount")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let return_url = params.get("ReturnURL").cloned().unwrap_or_default();
                state.lock().unwrap().orders.insert(
                    key,
                    Order {
                        total_amount: amount,
                        paid: false,
                    },
                );
                state.lock().unwrap().callback_log.push((
                    format!("__return_url:{trade_no}"),
                    return_url,
                    String::new(),
                ));
                respond(&mut stream, "text/html", "<html>綠界付款頁(模擬)</html>");
                continue;
            }

            if path.ends_with("__test/mark_paid") {
                // The "consumer paid" event (or vendor-console 模擬付款):
                // flip the order to paid and deliver ECPay's ServerPost
                // callback to the ReturnURL on file.
                let trade_no = params.get("trade_no").cloned().unwrap_or_default();
                let (return_url, callback_body) = {
                    let mut st = state.lock().unwrap();
                    let Some(order) = st.orders.get_mut(&trade_no) else {
                        respond(&mut stream, "text/plain", "no such order");
                        continue;
                    };
                    order.paid = true;
                    // ECPay's callback shape (spec: 付款結果通知).
                    let callback: HashMap<String, String> = [
                        ("MerchantID", MERCHANT_ID),
                        ("MerchantTradeNo", trade_no.as_str()),
                        ("RtnCode", "1"),
                        ("RtnMsg", "Succeeded"),
                        ("TradeNo", "2301011234567890"),
                        ("TradeAmt", &order.total_amount.to_string()),
                        ("PaymentDate", "2026/09/10 12:05:00"),
                        ("PaymentType", "Credit_CreditCard"),
                        ("TradeDate", "2026/09/10 12:00:00"),
                        ("SimulatePaid", "1"),
                        ("PaymentTypeChargeFee", "0"),
                    ]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                    let mac = sign(&callback);
                    let body = callback
                        .iter()
                        .map(|(k, v)| format!("{k}={}", urlencode(v)))
                        .chain(std::iter::once(format!("CheckMacValue={mac}")))
                        .collect::<Vec<_>>()
                        .join("&");
                    let return_url = st
                        .callback_log
                        .iter()
                        .find(|(k, _, _)| k == &format!("__return_url:{trade_no}"))
                        .map(|(_, url, _)| url.clone())
                        .unwrap_or_default();
                    (return_url, body)
                };
                let reply = deliver_callback(&return_url, &callback_body);
                let reply_body = reply
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                state.lock().unwrap().callback_log.push((
                    format!("__callback:{trade_no}"),
                    callback_body,
                    reply_body,
                ));
                respond(&mut stream, "text/plain", "delivered");
                continue;
            }

            if path.ends_with("/Cashier/QueryTradeInfo/V5") {
                let got = params.get("CheckMacValue").cloned().unwrap_or_default();
                let want = sign(&params);
                if got != want {
                    respond(&mut stream, "text/plain", "CheckMacValue Error");
                    continue;
                }
                let trade_no = params.get("MerchantTradeNo").cloned().unwrap_or_default();
                let st = state.lock().unwrap();
                let order = st.orders.get(&trade_no);
                let mut response: HashMap<String, String> = HashMap::new();
                response.insert("MerchantID".into(), MERCHANT_ID.into());
                response.insert("MerchantTradeNo".into(), trade_no);
                response.insert("TradeNo".into(), "2301011234567890".into());
                response.insert(
                    "TradeAmt".into(),
                    order
                        .map(|o| o.total_amount.to_string())
                        .unwrap_or_default(),
                );
                response.insert(
                    "TradeStatus".into(),
                    match order {
                        Some(o) if o.paid => "1".into(),
                        _ => "10200047".into(), // 查無此交易(未付款)
                    },
                );
                if order.map(|o| o.paid).unwrap_or(false) {
                    response.insert("SimulatePaid".into(), "1".into());
                    response.insert("PaymentDate".into(), "2026/09/10 12:05:00".into());
                    response.insert("PaymentType".into(), "Credit_CreditCard".into());
                }
                response.insert("CheckMacValue".into(), sign(&response));
                let body = response
                    .iter()
                    .map(|(k, v)| format!("{k}={}", urlencode(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                respond(&mut stream, "text/html", &body);
                continue;
            }

            respond(&mut stream, "text/plain", "not found");
        }
    });
    format!("http://{addr}/")
}

/// The merchant side: a ReturnURL receiver that uses THIS library to verify
/// the inbound callback and answers exactly `1|OK`.
fn spawn_return_url(verified: Arc<Mutex<Vec<HashMap<String, String>>>>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind return url");
    let addr = listener.local_addr().unwrap();
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: HASH_KEY.into(),
        hash_iv: HASH_IV.into(),
        ..Default::default()
    };
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 16384];
            let head_end = loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break buf.len(),
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                    }
                    Err(_) => break buf.len(),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]);
            let cl = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if !k.trim().eq_ignore_ascii_case("content-length") {
                        return None;
                    }
                    v.trim().parse::<usize>().ok()
                })
                .unwrap_or(0);
            let mut body = buf[head_end.min(buf.len())..].to_vec();
            while body.len() < cl {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            let params = parse_form(&String::from_utf8_lossy(&body));
            let ok = client.verify_check_mac_value(&params)
                && params.get("RtnCode").map(String::as_str) == Some("1")
                && params.get("SimulatePaid").map(String::as_str) == Some("1");
            verified.lock().unwrap().push(params);
            respond(&mut stream, "text/html", if ok { "1|OK" } else { "0|ERR" });
        }
    });
    format!("http://{addr}/ecpay/return")
}

fn aio_params(trade_no: String, return_url: &str) -> AioCheckOutParams {
    AioCheckOutParams {
        merchant_trade_no: trade_no,
        merchant_trade_date: "2026/09/10 12:00:00".into(),
        total_amount: 100,
        trade_desc: "e2e".into(),
        item_name: "商品#第二項".into(),
        return_url: return_url.into(),
        choose_payment: ChoosePayment::Credit,
        ..Default::default()
    }
}

fn post_form(endpoint: &str, pairs: &[(String, String)]) -> String {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut stream = TcpStream::connect(
        endpoint
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap(),
    )
    .expect("connect");
    let path = format!(
        "/{}",
        endpoint
            .strip_prefix("http://")
            .unwrap()
            .split_once('/')
            .unwrap()
            .1
    );
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

fn body_of(response: &str) -> String {
    response.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
}

#[tokio::test]
async fn full_payment_flow_end_to_end() {
    let state = Arc::new(Mutex::new(SimulatorState::default()));
    let simulator = spawn_simulator(state.clone());
    let verified: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
    let return_url = spawn_return_url(verified.clone());
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: HASH_KEY.into(),
        hash_iv: HASH_IV.into(),
        payment_api_url: format!("{simulator}Cashier/"),
        ..Default::default()
    };
    let trade_no = format!(
        "E2E{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // 1. Checkout: the simulator must accept the library's signed params.
    let checkout = client
        .aio_check_out(&aio_params(trade_no.clone(), &return_url))
        .expect("checkout builds");
    let page = post_form(checkout.action(), checkout.params());
    assert!(
        body_of(&page).contains("綠界付款頁"),
        "the simulator must accept the checkout: {page}"
    );

    // 2. Before payment: authoritative query says unpaid (10200047), with a
    //    MAC this library verifies (Ok return).
    let unpaid = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: trade_no.clone(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("order_search");
    assert_eq!(
        unpaid.get("TradeStatus").map(String::as_str),
        Some("10200047")
    );

    // 3. Payment happens (consumer or vendor-console 模擬付款): ECPay marks
    //    paid and DELIVERS the signed callback to our ReturnURL.
    let mark = post_form(
        &format!("{simulator}Cashier/__test/mark_paid"),
        &[("trade_no".into(), trade_no.clone())],
    );
    assert_eq!(body_of(&mark), "delivered", "{mark}");

    // The merchant side verified the callback (RtnCode=1, SimulatePaid=1,
    // MAC) and answered ECPay's expected `1|OK`. Guards are scoped so no
    // std MutexGuard is alive across the awaits below (clippy awaits lint).
    let callback_seen = {
        let seen = verified.lock().unwrap();
        (
            seen.len(),
            seen.first()
                .and_then(|p| p.get("MerchantTradeNo").cloned())
                .unwrap_or_default(),
        )
    };
    assert_eq!(callback_seen.0, 1, "exactly one callback delivered");
    assert_eq!(callback_seen.1, trade_no);
    let (sent, reply) = {
        let log = state.lock().unwrap();
        log.callback_log
            .iter()
            .find(|(k, _, _)| k == &format!("__callback:{trade_no}"))
            .map(|(_, sent, reply)| (sent.clone(), reply.clone()))
            .expect("callback delivery logged")
    };
    assert!(
        sent.contains("RtnCode=1"),
        "callback carries the paid notification"
    );
    assert_eq!(reply, "1|OK", "the merchant must answer 1|OK");

    // 4. Authoritative paid state, MAC round-trip included.
    let paid = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: trade_no.clone(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("order_search after payment");
    assert_eq!(paid.get("TradeStatus").map(String::as_str), Some("1"));
    assert_eq!(paid.get("SimulatePaid").map(String::as_str), Some("1"));
    assert_eq!(paid.get("TradeAmt").map(String::as_str), Some("100"));

    // 5. Wire-level negative: a tampered checkout MAC never registers.
    let mut tampered: Vec<(String, String)> = checkout.params().to_vec();
    for (k, v) in tampered.iter_mut() {
        if k == "CheckMacValue" {
            let flipped = if v.starts_with('A') { 'B' } else { 'A' };
            v.replace_range(..1, &flipped.to_string());
        }
    }
    let page = post_form(checkout.action(), &tampered);
    assert!(
        body_of(&page).contains("10200073"),
        "the simulator must reject a tampered checkout MAC like the real server: {page}"
    );
}
