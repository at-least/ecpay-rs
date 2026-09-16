//! Transport edge cases for a money-path HTTP client: oversized bodies,
//! redirects that must NOT be followed, empty bodies, and checkout
//! determinism.

use ecpay::payment::{AioCheckOutParams, ChoosePayment, OrderSearchParams};
use ecpay::Ecpay;

mod common;
use common::spawn_http_server;

const MERCHANT_ID: &str = "3002607";
const HASH_KEY: &str = "pwFHCqoQZGmho4w6";
const HASH_IV: &str = "EkRm7iFT261dpevs";

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: HASH_KEY.into(),
        hash_iv: HASH_IV.into(),
        ..Default::default()
    }
}

/// A response body larger than the 1 MiB read cap must fail loudly (a
/// truncated MAC or form body is never accepted silently).
#[tokio::test]
async fn oversized_response_bodies_are_rejected() {
    // The mock declares Content-Length, so this exercises the up-front
    // guard; the close-delimited variant below exercises the byte counter.
    let srv = spawn_http_server(move |_path, _body| {
        let payload = vec![b'a'; (1 << 21) + 16];
        (200, "application/json".to_owned(), payload)
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let err = client
        .order_search(&OrderSearchParams {
            merchant_trade_no: "x".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect_err("a 2 MiB response must be rejected, never silently truncated");
    assert!(
        matches!(&err, ecpay::Error::Message(m) if m.contains("1 MiB safety limit")),
        "the cap must reject the body up front, got {err:?}"
    );
}

/// A 302 on a signed API POST must NOT be followed: ECPay's endpoints never
/// redirect, and following one would replay the signed payload to an
/// attacker-chosen host. The mock emits a REAL `Location` header (reqwest
/// only redirects on one, so a Location-less 302 would pass under the
/// default policy too and prove nothing).
#[tokio::test]
async fn redirects_are_not_followed() {
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit2 = hit.clone();
    let srv = common::spawn_http_server_raw(move |path, _body| {
        if path.starts_with("/target") {
            hit2.store(true, std::sync::atomic::Ordering::SeqCst);
            (
                200,
                vec![("Content-Type".to_owned(), "text/plain".to_owned())],
                b"leaked".to_vec(),
            )
        } else {
            (
                302,
                vec![
                    ("Content-Type".to_owned(), "text/plain".to_owned()),
                    ("Location".to_owned(), "/target".to_owned()),
                ],
                Vec::new(),
            )
        }
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let err = client
        .order_search(&OrderSearchParams {
            merchant_trade_no: "x".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect_err("a 302 must surface as an error, not be followed");
    match err {
        ecpay::Error::PaymentStatus { status, .. } => assert_eq!(status, 302, "{err:?}"),
        other => panic!("expected PaymentStatus(302), got {other:?}"),
    }
    assert!(
        !hit.load(std::sync::atomic::Ordering::SeqCst),
        "the redirect target must never be requested"
    );
}

/// The 1 MiB cap must ERROR on the Big5 CSV flows too — a settlement report
/// cut mid-row and returned as Ok would be silent data corruption.
#[tokio::test]
async fn oversized_balance_reports_error() {
    let srv = spawn_http_server(move |_path, _body| {
        (200, "text/plain".to_owned(), vec![b'a'; (1 << 20) + 16])
    });
    let client = Ecpay {
        vendor_api_url: srv,
        ..sdk()
    };
    let err = client
        .download_merchant_balance(&ecpay::payment::DownloadMerchantBalanceParams {
            date_type: "1".into(),
            begin_date: "2026-09-01".into(),
            end_date: "2026-09-02".into(),
            media_formated: "Y".into(),
            ..Default::default()
        })
        .await
        .expect_err("an over-cap Big5 report must be an error, never a truncated Ok");
    assert!(
        err.to_string().contains("1 MiB safety limit"),
        "got {err:?}"
    );
}

/// Empty bodies must error, never panic or produce Ok. Both 200 and 204 are
/// success statuses, so the rejection has to come from the response
/// verification: no CheckMacValue in an empty body is a
/// `CheckMacValueMismatch`, not a parse error or a silent empty map.
#[tokio::test]
async fn empty_bodies_error() {
    for status in [204u16, 200] {
        let srv =
            spawn_http_server(move |_path, _body| (status, "text/plain".to_owned(), Vec::new()));
        let client = Ecpay {
            payment_api_url: srv,
            ..sdk()
        };
        let err = client
            .order_search(&OrderSearchParams {
                merchant_trade_no: "x".into(),
                time_stamp: 1,
                platform_id: None,
            })
            .await
            .expect_err("empty body must be an error, never an Ok with no fields");
        assert!(
            matches!(err, ecpay::Error::CheckMacValueMismatch),
            "status {status}: expected CheckMacValueMismatch, got {err:?}"
        );
    }
}

/// The cap's second guard: with NO Content-Length (a close-delimited body,
/// which is also how a lying chunked body arrives) the up-front check has
/// nothing to look at, so the delivered-byte counter must reject the
/// overage — and still accept a body that sits exactly at the cap.
#[tokio::test]
async fn oversized_close_delimited_bodies_are_rejected() {
    let params = ecpay::payment::DownloadMerchantBalanceParams {
        date_type: "1".into(),
        begin_date: "2026-09-01".into(),
        end_date: "2026-09-02".into(),
        media_formated: "Y".into(),
        ..Default::default()
    };

    let srv = common::spawn_close_delimited_server(vec![b'a'; (1 << 20) + 1]);
    let client = Ecpay {
        vendor_api_url: srv,
        ..sdk()
    };
    let err = client
        .download_merchant_balance(&params)
        .await
        .expect_err("1 MiB + 1 byte without Content-Length must be rejected by the byte counter");
    // The up-front Content-Length guard appends "(N bytes)"; the counter
    // guard does not. Pin the exact counter message so this test cannot
    // pass via the other guard.
    assert!(
        matches!(&err, ecpay::Error::Message(m)
            if m == "ecpay: response body exceeds the 1 MiB safety limit"),
        "expected the byte-counter rejection, got {err:?}"
    );

    let srv = common::spawn_close_delimited_server(vec![b'a'; 1 << 20]);
    let client = Ecpay {
        vendor_api_url: srv,
        ..sdk()
    };
    let got = client
        .download_merchant_balance(&params)
        .await
        .expect("exactly 1 MiB without Content-Length is at the cap and must be accepted");
    assert_eq!(got.len(), 1 << 20);
}

/// A body of exactly 1 MiB (the cap) must still be accepted — only the
/// overflow is rejected.
#[tokio::test]
async fn exactly_one_mib_body_is_accepted() {
    let payload = vec![b'a'; 1 << 20];
    let srv =
        spawn_http_server(move |_path, _body| (200, "text/plain".to_owned(), payload.clone()));
    let client = Ecpay {
        vendor_api_url: srv,
        ..sdk()
    };
    let got = client
        .download_merchant_balance(&ecpay::payment::DownloadMerchantBalanceParams {
            date_type: "1".into(),
            begin_date: "2026-09-01".into(),
            end_date: "2026-09-02".into(),
            media_formated: "Y".into(),
            ..Default::default()
        })
        .await
        .expect("a 1 MiB body sits exactly at the cap and must be returned");
    assert_eq!(got.len(), 1 << 20);
}

/// `aio_check_out` is a pure computation: the same params must yield a
/// byte-identical signed payload across calls (retries, idempotent replay
/// into logs/tests) — no hidden timestamps inside the signing path.
#[test]
fn aio_check_out_is_deterministic() {
    let client = sdk();
    let build = || {
        client
            .aio_check_out(&AioCheckOutParams {
                merchant_trade_no: "NO20240101120000".into(),
                merchant_trade_date: "2024/01/01 12:00:00".into(),
                total_amount: 100,
                trade_desc: "desc".into(),
                item_name: "item".into(),
                return_url: "https://example.com/return".into(),
                choose_payment: ChoosePayment::Atm,
                expire_date: Some(7),
                ..Default::default()
            })
            .expect("checkout builds")
    };
    let a = build();
    let b = build();
    assert_eq!(a.params(), b.params());
    assert_eq!(a.html_form(), b.html_form());
}

/// The injected `http` client is the one that actually sends the request: a
/// client carrying a distinctive User-Agent must show up verbatim in the
/// request head at the server (with `http: None` the shared hardened client
/// is used instead — covered by every other test in this crate).
#[tokio::test]
async fn injected_http_client_is_used() {
    use common::spawn_http_server_with_head;

    let injected = reqwest::Client::builder()
        .user_agent("ecpay-test-injected-client")
        .build()
        .expect("build injected client");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen2 = seen.clone();
    let srv = spawn_http_server_with_head(move |_path, head, _body| {
        *seen2.lock().unwrap() = head.to_owned();
        // query_trade_info verifies the response CheckMacValue, so the body
        // must be correctly signed; the header assertion is the point.
        let mut respond = std::collections::HashMap::new();
        respond.insert("MerchantID".to_owned(), MERCHANT_ID.to_owned());
        respond.insert("TradeStatus".to_owned(), "1".to_owned());
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
        (
            200,
            "text/html; charset=utf-8".to_owned(),
            format!("MerchantID={MERCHANT_ID}&TradeStatus=1&CheckMacValue={mac}").into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        http: Some(injected.clone()),
        ..sdk()
    };
    client.query_trade_info("x").await.expect("decodes");
    let head = seen.lock().unwrap().clone();
    assert!(
        head.contains("ecpay-test-injected-client"),
        "the injected client's User-Agent must reach the server, head: {head}"
    );

    // The AES-JSON invoice path rides the same injected client.
    let seen3 = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen4 = seen3.clone();
    let srv = spawn_http_server_with_head(move |_path, head, _body| {
        *seen4.lock().unwrap() = head.to_owned();
        let res = ecpay::client::Response {
            trans_code: 1,
            data: ecpay::encrypt_data(
                &serde_json::json!({"RtnCode": 1}),
                b"ejCk326UnaZWKisg",
                b"q9jcZX8Ib9LM8wYk",
            )
            .unwrap(),
            ..Default::default()
        };
        (
            200,
            "application/json".to_owned(),
            serde_json::to_vec(&res).unwrap(),
        )
    });
    let client = Ecpay {
        invoice_api_url: srv,
        invoice_hash_key: "ejCk326UnaZWKisg".into(),
        invoice_hash_iv: "q9jcZX8Ib9LM8wYk".into(),
        http: Some(injected),
        ..sdk()
    };
    client
        .get_issue(&Default::default())
        .await
        .expect("envelope decodes");
    let head = seen3.lock().unwrap().clone();
    assert!(
        head.contains("ecpay-test-injected-client"),
        "the AES path must also ride the injected client, head: {head}"
    );
}

/// A 2xx body that is not an AES-JSON envelope (no `TransCode` key) must be
/// reported as such with the body attached — not decoded into a meaningless
/// `TransCode{code:0}` (every `Response` field is serde-defaulted) nor as a
/// bare JSON parse error that drops the body. Same gate as the AES-JSON
/// (logistics v2 / ECPG / B2B) path.
#[tokio::test]
async fn invoice_2xx_non_envelope_bodies_are_reported_with_the_body() {
    for (content_type, body) in [
        ("application/json", "{}"),
        ("application/json", r#"{"RtnCode":1,"Data":"x"}"#),
        ("text/html; charset=utf-8", "<html>Server Error</html>"),
    ] {
        let srv = spawn_http_server(move |_path, _body| {
            (200, content_type.to_owned(), body.as_bytes().to_vec())
        });
        let client = Ecpay {
            invoice_api_url: srv,
            invoice_hash_key: "ejCk326UnaZWKisg".into(),
            invoice_hash_iv: "q9jcZX8Ib9LM8wYk".into(),
            ..sdk()
        };
        let err = client
            .get_issue(&Default::default())
            .await
            .expect_err("a non-envelope body must not decode");
        match &err {
            ecpay::Error::Message(msg) => {
                assert!(msg.contains("not an AES-JSON envelope"), "{msg}");
                // The body is quoted (Debug-escaped) so it survives a log line.
                assert!(
                    msg.contains(&format!("{body:?}")),
                    "the body must be carried: {msg}"
                );
            }
            other => panic!("expected Error::Message for body {body:?}, got {other:?}"),
        }
    }
}

/// A non-2xx body is kept in full on the error FIELD (programmatic access)
/// but its DISPLAY rendering is bounded: a hostile or misbehaving endpoint
/// answering a megabyte of HTML cannot flood a log line through a
/// `PaymentStatus`/`InvoiceStatus` message.
#[tokio::test]
async fn status_error_display_is_bounded_but_the_field_keeps_the_body() {
    let big = "x".repeat(100_000);
    let srv = spawn_http_server(move |_path, _body| {
        (500, "text/html".to_owned(), big.clone().into_bytes())
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let err = client
        .query_trade_info("order_x")
        .await
        .expect_err("a non-2xx payment reply must surface as an error");
    match &err {
        ecpay::Error::PaymentStatus { status, body } => {
            assert_eq!(*status, 500);
            assert_eq!(body.len(), 100_000, "the field keeps the full body");
        }
        other => panic!("expected Error::PaymentStatus, got {other:?}"),
    }
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("ecpay payment API error: status=500 body="),
        "{rendered}"
    );
    assert!(
        rendered.contains("… (truncated; 100000 bytes total)"),
        "the display must be truncated: {}",
        rendered.len()
    );
    assert!(
        rendered.len() < 600,
        "the rendered message must stay small: {}",
        rendered.len()
    );
}

/// The callback boundary (`decrypt_ecpg_callback`, `decrypt_logistics_callback`,
/// `decrypt_temp_trade_established`) decrypts attacker-tampered CBC ciphertext
/// on public endpoints, and the AES envelope authenticates no `Data`. A
/// padding oracle — any distinguishable difference between a payload that
/// failed padding and one that failed a later stage — lets an attacker forge
/// payload encryption (CBC-R) without the key. Every payload-content-dependent
/// failure must therefore collapse into ONE fixed message. Base64/length/key
/// errors stay distinct: they depend only on inputs the attacker already
/// knows (their own ciphertext's shape), so they carry no plaintext signal.
#[test]
fn callback_payload_failures_are_indistinguishable() {
    use base64::Engine;
    let client = Ecpay {
        hash_key: "0123456789abcdef".into(),
        hash_iv: "0123456789abcdef".into(),
        ..Default::default()
    };
    let key = b"0123456789abcdef";
    let iv = b"0123456789abcdef";
    let envelope = |data: &str| format!(r#"{{"TransCode":1,"TransMsg":"","Data":"{data}"}}"#);

    // (1) Valid padding, valid UTF-8, not JSON.
    let not_json = ecpay::encrypt(b"not json payload!!!", key, iv).unwrap();
    // (2) Valid padding, not UTF-8.
    let not_utf8 = ecpay::encrypt(&[0xFF; 19], key, iv).unwrap();
    // (3) Invalid padding: flip the last ciphertext byte of (1) until decrypt
    //     reports a padding failure (nearly every flip does; loop so the test
    //     is deterministic).
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&not_json)
        .unwrap();
    let mut bad_padding = String::new();
    for flip in 1..=255u8 {
        let mut r = raw.clone();
        *r.last_mut().unwrap() ^= flip;
        let ct = base64::engine::general_purpose::STANDARD.encode(&r);
        if let Err(e) = ecpay::decrypt(&ct, key, iv) {
            if e.to_string().contains("padding") {
                bad_padding = ct;
                break;
            }
        }
    }
    assert!(!bad_padding.is_empty(), "no flip produced invalid padding");
    // (4) Valid padding, valid UTF-8, malformed URL escape (%zz).
    let bad_escape = ecpay::encrypt(b"percent %zz tail!!!!!", key, iv).unwrap();

    let errs: Vec<String> = [&not_json, &not_utf8, &bad_padding, &bad_escape]
        .iter()
        .map(|data| {
            client
                .decrypt_ecpg_callback::<serde_json::Value>(&envelope(data))
                .expect_err("all four payloads must fail")
                .to_string()
        })
        .collect();
    for e in &errs {
        assert_eq!(e, &errs[0], "padding oracle: payload failures differ");
        let low = e.to_lowercase();
        for word in ["padding", "utf", "json", "escape"] {
            assert!(!low.contains(word), "leaky message {e:?} mentions {word}");
        }
    }
    // The logistics callback and the temp-trade form callback must route
    // through the same boundary.
    for e in [
        client
            .decrypt_logistics_callback::<serde_json::Value>(&envelope(&not_utf8))
            .expect_err("must fail")
            .to_string(),
        client
            .decrypt_temp_trade_established::<serde_json::Value>(&envelope(&bad_padding))
            .expect_err("must fail")
            .to_string(),
    ] {
        assert_eq!(e, errs[0], "callback decoders must share one uniform error");
    }
}
