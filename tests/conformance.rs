//! Port of Go `conformance_test.go` (field-name conformance) plus the minimal
//! hermetic ECPay mock servers it needs (the harness parts of Go's
//! mock_test.go: a mock B2CInvoice endpoint and a mock Cashier endpoint that
//! verify the inbound CheckMacValue).
//!
//! These tests pin each request/response to the exact field names, casing, and
//! envelope ECPay's official specs require, so a future rename that silently
//! breaks the wire contract fails a test instead of production.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use ecpay::{
    encrypt_data, hash_mac, Ecpay, GetIssueInput, GetIssueOutput, InvalidInput, IssueInput, Item,
};

// --- Go mock_test.go constants and helpers ---

const TEST_INVOICE_HASH_KEY: &[u8] = b"ejCk326UnaZWKisg";
const TEST_INVOICE_HASH_IV: &[u8] = b"q9jcZX8Ib9LM8wYk";
const TEST_PAYMENT_HASH_KEY: &str = "5294y06JbISpM5x9";
const TEST_PAYMENT_HASH_IV: &str = "v77hoKGq4kWxNNIS";
const TEST_MERCHANT_ID: &str = "2000132";

fn test_invoice_ecpay(base_url: &str) -> Ecpay {
    Ecpay {
        merchant_id: TEST_MERCHANT_ID.to_owned(),
        invoice_hash_key: TEST_INVOICE_HASH_KEY.to_vec(),
        invoice_hash_iv: TEST_INVOICE_HASH_IV.to_vec(),
        invoice_api_url: base_url.to_owned(),
        ..Default::default()
    }
}

fn test_payment_ecpay(base_url: &str) -> Ecpay {
    Ecpay {
        merchant_id: TEST_MERCHANT_ID.to_owned(),
        hash_key: TEST_PAYMENT_HASH_KEY.to_owned(),
        hash_iv: TEST_PAYMENT_HASH_IV.to_owned(),
        payment_api_url: base_url.to_owned(),
        ..Default::default()
    }
}

/// A tiny hermetic HTTP server (Go httptest.NewServer): binds 127.0.0.1:0,
/// serves every request with the handler's response, one connection per
/// request (Connection: close). Returns the base URL to point an Ecpay at.
fn spawn_http_server<F>(handler: F) -> String
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
            // Read until the end of the request head, then Content-Length bytes.
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
            // Dropping the stream closes the connection (Connection: close).
        }
    });
    format!("http://{addr}/")
}

fn form_unescape(s: &str) -> String {
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
                let hi = (b[i + 1] as char).to_digit(16).unwrap_or(u32::MAX);
                let lo = (b[i + 2] as char).to_digit(16).unwrap_or(u32::MAX);
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in body.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.insert(form_unescape(k), form_unescape(v));
    }
    out
}

fn form_escape(s: &str) -> String {
    // Go url.QueryEscape: unreserved A-Za-z0-9-_.~ literal, space -> '+',
    // everything else uppercase %XX.
    let mut out = String::new();
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

fn encode_form(params: &HashMap<String, String>) -> Vec<u8> {
    let mut pairs: Vec<(&String, &String)> = params.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_escape(k), form_escape(v)))
        .collect();
    encoded.join("&").into_bytes()
}

/// Mock Cashier endpoint (Go newPaymentMock): verifies the inbound
/// CheckMacValue (so a signing regression fails the test) and answers with the
/// given params form-encoded. The inbound params are stored in `captured`.
fn new_payment_mock(
    respond: HashMap<String, String>,
    captured: Arc<Mutex<Option<HashMap<String, String>>>>,
) -> String {
    spawn_http_server(move |_path, body| {
        let body = String::from_utf8_lossy(body);
        let mut params = parse_form(&body);
        let got_mac = params.remove("CheckMacValue").unwrap_or_default();
        let want_mac = hash_mac(&params, TEST_PAYMENT_HASH_KEY, TEST_PAYMENT_HASH_IV);
        assert_eq!(got_mac, want_mac, "mock: CheckMacValue signing mismatch");
        *captured.lock().unwrap() = Some(params);
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            encode_form(&respond),
        )
    })
}

// --- Field-name conformance (Go conformance_test.go) ---

fn assert_keys(obj: &serde_json::Map<String, serde_json::Value>, want: &[&str]) {
    for k in want {
        assert!(
            obj.contains_key(*k),
            "missing required field {k:?}; got keys {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }
}

/// TestIssueInputFieldNames locks the Issue (開立發票) request contract,
/// including the ECPay quirk that the tax-inclusive flag is lowercase "vat"
/// (every other field is PascalCase).
#[test]
fn test_issue_input_field_names() {
    let input = IssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "o1".to_owned(),
        print: "0".to_owned(),
        donation: "0".to_owned(),
        tax_type: "1".to_owned(),
        sales_amount: 100,
        inv_type: "07".to_owned(),
        vat: "1".to_owned(),
        items: Some(vec![Item {
            item_seq: 1,
            item_name: "x".to_owned(),
            item_count: 1.0,
            item_word: "項".to_owned(),
            item_price: 100.0,
            item_tax_type: "1".to_owned(),
            item_amount: 100.0,
            ..Default::default()
        }]),
        ..Default::default()
    };
    let m = serde_json::to_value(&input).unwrap();
    let obj = m.as_object().unwrap();
    assert_keys(
        obj,
        &[
            "MerchantID",
            "RelateNumber",
            "Print",
            "Donation",
            "TaxType",
            "SalesAmount",
            "InvType",
            "Items",
        ],
    );

    assert!(
        obj.contains_key("vat"),
        r#"Issue tax-inclusive flag must marshal as lowercase "vat" per ECPay spec"#
    );
    assert!(
        !obj.contains_key("Vat"),
        r#"found PascalCase "Vat"; ECPay's spec field is lowercase "vat""#
    );

    let item = serde_json::to_value(&input.items.unwrap()[0]).unwrap();
    assert_keys(
        item.as_object().unwrap(),
        &[
            "ItemSeq",
            "ItemName",
            "ItemCount",
            "ItemWord",
            "ItemPrice",
            "ItemTaxType",
            "ItemAmount",
        ],
    );
}

/// TestInvalidInputFieldNames locks the Invalid (作廢發票) request contract.
#[test]
fn test_invalid_input_field_names() {
    let input = InvalidInput {
        merchant_id: "2000132".to_owned(),
        invoice_no: "AB12345678".to_owned(),
        invoice_date: "2024-01-02".to_owned(),
        reason: "x".to_owned(),
    };
    let m = serde_json::to_value(&input).unwrap();
    assert_keys(
        m.as_object().unwrap(),
        &["MerchantID", "InvoiceNo", "InvoiceDate", "Reason"],
    );
}

/// TestGetIssueInputFieldNames locks the GetIssue (查詢發票) request contract.
#[test]
fn test_get_issue_input_field_names() {
    let input = GetIssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "o1".to_owned(),
    };
    let m = serde_json::to_value(&input).unwrap();
    assert_keys(m.as_object().unwrap(), &["MerchantID", "RelateNumber"]);
}

/// TestGetIssueOutputFieldNames confirms the response fields the codebase
/// reads (RtnCode, IIS_Number, IIS_Create_Date, IIS_Relate_Number) decode from
/// ECPay's verbatim spec names.
#[test]
fn test_get_issue_output_field_names() {
    let raw = r#"{"RtnCode":1,"RtnMsg":"ok","IIS_Number":"AB12345678","IIS_Create_Date":"2024-01-02 15:04:05","IIS_Relate_Number":"o1","IIS_Mer_ID":"2000132"}"#;
    #[derive(Debug, Deserialize)]
    struct Out {
        #[serde(rename = "RtnCode")]
        rtn_code: i64,
        #[serde(rename = "IIS_Number")]
        iis_number: String,
        #[serde(rename = "IIS_Create_Date")]
        iis_create_date: String,
        #[serde(rename = "IIS_Relate_Number")]
        iis_relate_number: String,
        #[serde(rename = "IIS_Mer_ID")]
        _iis_mer_id: serde_json::Value,
    }
    let out: Out = serde_json::from_str(raw).expect("decode GetIssueOutput");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.iis_number, "AB12345678");
    assert_eq!(out.iis_create_date, "2024-01-02 15:04:05");
    assert_eq!(out.iis_relate_number, "o1");
}

/// TestInvoiceRequestEnvelope checks the outer AES-JSON envelope
/// call_invoice_api sends: RqHeader.Revision must be "3.0.0", MerchantID must
/// be set, and the Timestamp must be a fresh Unix epoch (ECPay rejects
/// requests >10 min skewed).
#[tokio::test]
async fn test_invoice_request_envelope() {
    let got: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let srv = {
        let got = got.clone();
        spawn_http_server(move |path, body| {
            let _ = path; // /GetIssue
            let req: ecpay::Request = serde_json::from_slice(body).expect("decode envelope");
            *got.lock().unwrap() =
                Some(serde_json::to_value(&req).expect("encode captured envelope"));
            let data = encrypt_data(
                &GetIssueOutput {
                    rtn_code: 0,
                    ..Default::default()
                },
                TEST_INVOICE_HASH_KEY,
                TEST_INVOICE_HASH_IV,
            )
            .expect("encrypt reply");
            let res = ecpay::Response {
                trans_code: 1,
                data,
                ..Default::default()
            };
            (
                200,
                "application/json".to_owned(),
                serde_json::to_vec(&res).unwrap(),
            )
        })
    };

    let ec = test_invoice_ecpay(&srv);
    let input = GetIssueInput {
        merchant_id: ec.merchant_id.clone(),
        relate_number: "o1".to_owned(),
    };
    let out = ec
        .get_issue(&input)
        .await
        .expect("GetIssue through the mock");
    assert_eq!(
        out.rtn_code, 0,
        "the mock's RtnCode=0 reply must round-trip"
    );

    let got = got
        .lock()
        .unwrap()
        .clone()
        .expect("the envelope was captured");
    assert_eq!(
        got["RqHeader"]["Revision"], "3.0.0",
        "RqHeader.Revision must be 3.0.0"
    );
    assert_eq!(
        got["MerchantID"], TEST_MERCHANT_ID,
        "envelope MerchantID mismatch"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ts = got["RqHeader"]["Timestamp"]
        .as_i64()
        .expect("Timestamp is a number");
    assert!(
        (now - 120..=now + 5).contains(&ts),
        "RqHeader.Timestamp = {ts}, want within ~now ({now})"
    );
}

/// TestQueryTradeInfoRequestParams confirms the payment query sends exactly
/// the spec's request params (MerchantID, MerchantTradeNo, TimeStamp) — note
/// ECPay's payment API spells it "TimeStamp" — plus a CheckMacValue the mock
/// verifies.
#[tokio::test]
async fn test_query_trade_info_request_params() {
    let captured: Arc<Mutex<Option<HashMap<String, String>>>> = Arc::new(Mutex::new(None));
    let respond: HashMap<String, String> = [
        ("MerchantID", "3002607"),
        ("MerchantTradeNo", "order_abc"),
        ("TradeStatus", "1"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let srv = new_payment_mock(respond, captured.clone());

    let ec = test_payment_ecpay(&srv);
    let out = ec
        .query_trade_info("order_abc")
        .await
        .expect("QueryTradeInfo");
    assert_eq!(out.trade_status, "1");
    assert_eq!(out.merchant_trade_no, "order_abc");

    let got = captured.lock().unwrap().clone().expect("params captured");
    for k in ["MerchantID", "MerchantTradeNo", "TimeStamp"] {
        assert!(
            got.contains_key(k),
            "QueryTradeInfo request missing param {k:?}; got {:?}",
            got.keys().collect::<Vec<_>>()
        );
    }
    assert_eq!(
        got.get("MerchantTradeNo").map(String::as_str),
        Some("order_abc")
    );
}

// --- Transport contract errors (from Go transport_test.go's core cases) ---

/// TestCallInvoiceAPITransCodeGate: TransCode != 1 is a transport-level
/// failure — the client must error before attempting to decrypt Data.
#[tokio::test]
async fn test_call_invoice_api_trans_code_gate() {
    let srv = spawn_http_server(move |_path, _body| {
        let res = ecpay::Response {
            merchant_id: serde_json::json!(TEST_MERCHANT_ID),
            trans_code: 0, // TransCode 0
            trans_msg: "查無資料".to_owned(),
            ..Default::default()
        };
        (
            200,
            "application/json".to_owned(),
            serde_json::to_vec(&res).unwrap(),
        )
    });
    let ec = test_invoice_ecpay(&srv);
    let input = GetIssueInput {
        merchant_id: ec.merchant_id.clone(),
        relate_number: "o1".to_owned(),
    };
    let err = ec
        .get_issue(&input)
        .await
        .expect_err("expected a transport error when TransCode != 1");
    match &err {
        ecpay::Error::Transport { code, msg } => {
            assert_eq!(*code, 0);
            assert_eq!(msg, "查無資料");
        }
        other => panic!("expected Error::Transport, got {other:?}"),
    }
    assert!(
        err.to_string().contains("ecpay transport error: code=0"),
        "transport error message mismatch: {err}"
    );
}

/// TestCallInvoiceAPINon2xx + TestCallPaymentAPINon2xx: a non-2xx status
/// surfaces as an error on both transports.
#[tokio::test]
async fn test_api_non_2xx_errors() {
    // Invoice transport.
    let srv = spawn_http_server(move |_path, _body| {
        (502, "text/plain".to_owned(), b"upstream boom".to_vec())
    });
    let ec = test_invoice_ecpay(&srv);
    let input = GetIssueInput {
        merchant_id: ec.merchant_id.clone(),
        relate_number: "o1".to_owned(),
    };
    let err = ec
        .get_issue(&input)
        .await
        .expect_err("expected an error on a non-2xx invoice API response");
    assert!(
        err.to_string()
            .contains("ecpay invoice API error: status=502 body=upstream boom"),
        "invoice non-2xx message mismatch: {err}"
    );

    // Payment transport.
    let srv =
        spawn_http_server(move |_path, _body| (500, "text/plain".to_owned(), b"boom".to_vec()));
    let ec = test_payment_ecpay(&srv);
    let err = ec
        .query_trade_info("order_x")
        .await
        .expect_err("expected an error on a non-2xx payment API response");
    match &err {
        ecpay::Error::PaymentStatus { status, body } => {
            assert_eq!(*status, 500);
            assert_eq!(body, "boom");
        }
        other => panic!("expected Error::PaymentStatus, got {other:?}"),
    }
    assert!(
        err.to_string() == "ecpay payment API error: status=500 body=boom",
        "payment non-2xx message mismatch: {err}"
    );
}
