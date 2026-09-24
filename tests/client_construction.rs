//! Construction-time contracts of the redesigned client: invalid states
//! (empty keys, wrong key/IV lengths, non-https custom URLs, missing
//! merchant) are refused at `Ecpay::new`/`Keys::new`/`BaseUrl::new`, and a
//! family that was never configured (keys or URL) refuses LOUDLY at its
//! call site — never by silently falling back to the production endpoint.

use ecpay::{BaseUrl, Ecpay, Env, Keys, Urls};

mod common;
use common::spawn_http_server;

const MERCHANT: &str = "3002607";
const KEY: &str = "pwFHCqoQZGmho4w6"; // 16 bytes
const IV: &str = "EkRm7iFT261dpevs"; // 16 bytes

fn stage_client() -> Ecpay {
    Ecpay::new(MERCHANT, Env::Stage).expect("valid constructor inputs")
}

/// An empty merchant ID is never valid on the wire — refused at
/// construction instead of signing garbage requests.
#[test]
fn new_refuses_an_empty_merchant_id() {
    let err = Ecpay::new("", Env::Stage).expect_err("empty merchant must be refused");
    assert!(matches!(err, ecpay::Error::Validation(_)), "{err:?}");
}

/// Key pairs: empty halves and wrong BYTE lengths are refused — AES needs
/// a 16/24/32-byte key and exactly a 16-byte IV, and a typo'd config must
/// fail here, not as an opaque server error.
#[test]
fn keys_new_validates_lengths_in_bytes() {
    for (key, iv, ok) in [
        (KEY, IV, true),
        ("16-byte-key-1234", IV, true),                 // 16
        ("24-byte-key-111111111111", IV, true),         // 24
        ("32-byte-key-11111111111111111111", IV, true), // 32
        ("", IV, false),
        (KEY, "", false),
        ("15-byte-key-123", IV, false),
        ("17-byte-key-12345", IV, false),
        (KEY, "15-byte-iv-1234", false),
        (KEY, "17-byte-iv-123456", false),
    ] {
        let got = Keys::new(key, iv);
        assert_eq!(
            got.is_ok(),
            ok,
            "Keys::new({key:?}, len {}): {got:?}",
            iv.len()
        );
    }
}

/// Custom base URLs are https-validated ONCE at construction (loopback
/// http stays allowed for local test doubles, exactly like the
/// request-time rule was).
#[test]
fn base_url_validates_the_scheme_once() {
    assert!(BaseUrl::new("https://payment.ecpay.com.tw/Cashier/").is_ok());
    assert!(
        BaseUrl::new("http://127.0.0.1:8080/Cashier/").is_ok(),
        "loopback http"
    );
    assert!(
        BaseUrl::new("http://localhost/Cashier/").is_ok(),
        "loopback http"
    );
    let err = BaseUrl::new("http://payment.ecpay.com.tw/Cashier/")
        .expect_err("cleartext production base must be refused");
    assert!(matches!(err, ecpay::Error::Validation(_)), "{err:?}");
    let err = BaseUrl::new("ftp://x/").expect_err("non-http scheme must be refused");
    assert!(matches!(err, ecpay::Error::Validation(_)), "{err:?}");
}

/// A client whose payment keys were never set refuses payment calls
/// loudly BEFORE any request — the construction-side half of the
/// empty-key guard family (the runtime guards remain as defense).
#[tokio::test]
async fn payment_call_without_payment_keys_is_refused_loudly() {
    let client = stage_client();
    let err = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect_err("missing payment keys must be refused");
    assert!(
        matches!(&err, ecpay::Error::Validation(m) if m.contains("payment")),
        "{err:?}"
    );
}

/// Env::Custom sets ONLY what you give it: an invoice call on a client
/// whose Custom env lacks the invoice URL refuses loudly — it must NOT
/// silently fall back to the production invoice endpoint (the old
/// empty-=-production trap).
#[tokio::test]
async fn custom_env_missing_family_url_refuses_not_falls_back_to_production() {
    let client = Ecpay::new(
        MERCHANT,
        Env::Custom(Urls {
            payment: Some(BaseUrl::new("https://unused.invalid/Cashier/").unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_invoice_keys(Keys::new("ejCk326UnaZWKisg", "q9jcZX8Ib9LM8wYk").unwrap());
    let err = client
        .issue(&ecpay::invoice::IssueInput::default())
        .await
        .expect_err("invoice URL was never configured");
    assert!(
        matches!(&err, ecpay::Error::Validation(m) if m.to_lowercase().contains("invoice")),
        "{err:?}"
    );
    // The old trap was SILENT production traffic; the refusal must not
    // route anywhere near a production host either in the error text or
    // on the wire (nothing was sent: the guard is pre-send).
    let text = err.to_string();
    assert!(!text.contains("ecpay.com.tw"), "{text}");
}

/// Zeroize scrubs the pairs AND their presence: a zeroized client refuses
/// payment calls loudly instead of signing with empty bytes (the exact
/// regression that would resurrect the empty-key oracle class through the
/// Option guards).
#[tokio::test]
async fn zeroized_client_refuses_payment_calls() {
    let mut client = stage_client().with_payment_keys(Keys::new(KEY, IV).unwrap());
    client.zeroize_signing_keys();
    let err = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect_err("a zeroized client must not sign");
    assert!(matches!(err, ecpay::Error::Validation(_)), "{err:?}");
}

/// The documented whole-pair logistics fallback: a merchant whose
/// logistics keys are the payment pair simply omits the logistics pair —
/// the fallback takes the ENTIRE payment pair (never a key from one pair
/// and an IV from another, which the old per-field fallback allowed).
/// Pinned end-to-end: a domestic MD5 form call signs and verifies against
/// a mock with only the payment pair configured.
#[tokio::test]
async fn logistics_falls_back_to_the_whole_payment_pair() {
    let server = spawn_http_server(|_path, body| {
        let sent = ecpay::parse_form(String::from_utf8_lossy(body).as_ref());
        // The reply is MAC'd with the payment pair — the same pair the
        // request was signed with via the whole-pair fallback.
        let mut reply = std::collections::HashMap::new();
        reply.insert("AllPayLogisticsID".to_string(), "3657295".to_string());
        reply.insert("RtnCode".to_string(), "300".to_string());
        let mac = ecpay::check_mac_value(&reply, KEY, IV, ecpay::EncryptType::Md5);
        // The OUTBOUND signature used the same whole payment pair: the
        // request's CheckMacValue is the payment-pair MD5 over the sent
        // fields.
        let mut sans_mac = sent.clone();
        let sent_mac = sans_mac.remove("CheckMacValue").expect("signed");
        assert_eq!(
            sent_mac,
            ecpay::check_mac_value(&sans_mac, KEY, IV, ecpay::EncryptType::Md5),
            "the request must be signed with the whole payment pair"
        );
        (
            200,
            "text/plain".into(),
            format!("1|AllPayLogisticsID=3657295&RtnCode=300&CheckMacValue={mac}").into_bytes(),
        )
    });
    let client = Ecpay::new(
        MERCHANT,
        Env::Custom(Urls {
            logistics: Some(BaseUrl::new(server).unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_payment_keys(Keys::new(KEY, IV).unwrap()); // NO logistics pair
    let out = client
        .logistics_create(&ecpay::logistics::LogisticsCreateInput {
            merchant_trade_no: "WIRE0000001".into(),
            merchant_trade_date: "2026/09/23 12:00:00".into(),
            logistics_type: "CVS".into(),
            logistics_sub_type: "FAMI".into(),
            goods_amount: 1000,
            sender_name: "陳大明".into(),
            sender_cell_phone: "0911222333".into(),
            receiver_name: "王小美".into(),
            receiver_cell_phone: "0933222111".into(),
            server_reply_url: "https://www.ecpay.com.tw/example/server-reply".into(),
            ..Default::default()
        })
        .await
        .expect("whole-pair fallback signs and verifies");
    assert_eq!(out["RtnCode"], "300");
}

/// The whole-pair fallback and a dedicated logistics pair carrying the SAME
/// key/IV must put IDENTICAL BYTES on the wire — only the setter differs.
///
/// This is what lets `tests/sandbox_logistics.rs` prove the fallback against
/// the live server without a live order of its own: its round-trip runs
/// through `fallback_sdk()`, and the dedicated path is covered by the other
/// `sdk()` tests. If that equivalence ever breaks, the live suite would go
/// on passing while silently covering only one of the two paths — so it is
/// pinned HERE, offline, with a negative control that proves the comparison
/// can fail.
#[tokio::test]
async fn fallback_and_dedicated_pairs_emit_identical_request_bytes() {
    use std::sync::{Arc, Mutex};
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let server = spawn_http_server(move |_path, body| {
        sink.lock().unwrap().push(body.to_vec());
        let mut reply = std::collections::HashMap::new();
        reply.insert("AllPayLogisticsID".to_string(), "3657295".to_string());
        reply.insert("RtnCode".to_string(), "300".to_string());
        let mac = ecpay::check_mac_value(&reply, KEY, IV, ecpay::EncryptType::Md5);
        (
            200,
            "text/plain".into(),
            format!("1|AllPayLogisticsID=3657295&RtnCode=300&CheckMacValue={mac}").into_bytes(),
        )
    });
    let urls = || Urls {
        logistics: Some(BaseUrl::new(&server).unwrap()),
        ..Default::default()
    };
    // Fixed input: every field constant, so any byte difference between the
    // three requests can only come from key selection.
    let order = || ecpay::logistics::LogisticsCreateInput {
        merchant_trade_no: "PAIRIDENTITY0001".into(),
        merchant_trade_date: "2026/09/23 12:00:00".into(),
        logistics_type: "CVS".into(),
        logistics_sub_type: "FAMI".into(),
        goods_amount: 1000,
        sender_name: "陳大明".into(),
        sender_cell_phone: "0911222333".into(),
        receiver_name: "王小美".into(),
        receiver_cell_phone: "0933222111".into(),
        server_reply_url: "https://www.ecpay.com.tw/example/server-reply".into(),
        ..Default::default()
    };

    // 1: dedicated logistics pair. 2: payment pair only (the fallback).
    // 3: negative control — a DIFFERENT pair, which must not match.
    let dedicated = Ecpay::new(MERCHANT, Env::Custom(urls()))
        .unwrap()
        .with_logistics_keys(Keys::new(KEY, IV).unwrap());
    let fallback = Ecpay::new(MERCHANT, Env::Custom(urls()))
        .unwrap()
        .with_payment_keys(Keys::new(KEY, IV).unwrap());
    let other = Ecpay::new(MERCHANT, Env::Custom(urls()))
        .unwrap()
        .with_logistics_keys(Keys::new("5294y06JbISpM5x9", "v77hoKGq4kWxNNIS").unwrap());
    dedicated
        .logistics_create(&order())
        .await
        .expect("dedicated");
    fallback.logistics_create(&order()).await.expect("fallback");
    // The mock MACs its reply with KEY/IV, so the wrong pair fails the
    // REPLY check — the request still reached the sink, which is all we
    // need for the byte comparison below.
    assert!(other.logistics_create(&order()).await.is_err());

    let bodies = seen.lock().unwrap();
    assert_eq!(bodies.len(), 3, "three requests reached the mock");
    assert_eq!(
        bodies[0],
        bodies[1],
        "whole-pair fallback must sign byte-identically to the dedicated pair\n\
         dedicated = {}\nfallback  = {}",
        String::from_utf8_lossy(&bodies[0]),
        String::from_utf8_lossy(&bodies[1]),
    );
    assert_ne!(
        bodies[0], bodies[2],
        "negative control: a different pair must produce different bytes"
    );
}

/// `Env::Stage` carries every family's stage URL — the successor of the
/// old one-shot `Ecpay::stage` constructor, now via the uniform env.
#[test]
fn stage_env_sets_every_family_url() {
    let client = stage_client();
    let urls = client.urls();
    for url in [
        urls.payment.as_ref(),
        urls.invoice.as_ref(),
        urls.credit.as_ref(),
        urls.vendor.as_ref(),
        urls.logistics.as_ref(),
        urls.ecpg.as_ref(),
        urls.ecpayment.as_ref(),
        urls.b2b_invoice.as_ref(),
    ] {
        let url = url.expect("Env::Stage configures every family");
        assert!(
            url.as_str().contains("-stage.ecpay.com.tw"),
            "{}",
            url.as_str()
        );
    }
}
