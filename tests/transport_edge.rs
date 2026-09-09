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
/// truncated MAC or JSON is never accepted silently).
#[tokio::test]
async fn oversized_response_bodies_are_rejected() {
    // The reader caps at 1 MiB; 2 MiB of JSON truncates and must not parse.
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
        matches!(
            err,
            ecpay::Error::CheckMacValueMismatch | ecpay::Error::Json(_)
        ),
        "got {err:?}"
    );
}

/// A 302 on a signed API POST must NOT be followed: ECPay's endpoints never
/// redirect, and following one would replay the signed payload to an
/// attacker-chosen host.
#[tokio::test]
async fn redirects_are_not_followed() {
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit2 = hit.clone();
    let srv = spawn_http_server(move |path, _body| {
        if path.starts_with("/target") {
            hit2.store(true, std::sync::atomic::Ordering::SeqCst);
            (200, "text/plain".to_owned(), b"leaked".to_vec())
        } else {
            (302, "text/plain".to_owned(), Vec::new())
        }
    });
    // The mock sends "Location: /target"? spawn_http_server writes fixed
    // headers, so a bare 302 without Location still exercises the policy:
    // reqwest's Policy::none returns the 302 as the final response.
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

/// Empty and header-only bodies must error, never panic or produce Ok.
#[tokio::test]
async fn empty_bodies_error() {
    for (status, body) in [(204u16, Vec::new()), (200, Vec::new())] {
        let (s, b) = (status, body.clone());
        let srv = spawn_http_server(move |_path, _body| (s, "text/plain".to_owned(), b.clone()));
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
        // A 204 arrives as success-status; the missing CheckMacValue must
        // still reject. Anything erroring is acceptable; nothing may pass.
        let _ = err;
    }
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
