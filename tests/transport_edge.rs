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
        (
            200,
            "text/html; charset=utf-8".to_owned(),
            b"MerchantID=3002607&TradeStatus=1".to_vec(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        http: Some(injected.clone()),
        ..sdk()
    };
    // query_trade_info does not verify a response CheckMacValue, so the
    // 2-field body decodes cleanly; the header assertion is the point.
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
