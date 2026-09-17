//! Live ECPG (站內付 2.0) tests against the two real stage domains — the
//! dual-domain family (ecpg `Merchant/*` vs ecpayment `1.0.0/*`) that was
//! previously live-covered only by the MANUAL probes in `tests/
//! stage_probes.rs` (raw crypto primitives) and one typed probe in
//! `tests/ecpg_wire.rs`. These use the real `Ecpay` methods end to end
//! (envelope build, encrypt_checked guard, TransCode gate, typed decode).
//!
//! Like the other sandbox suites every test is `#[ignore]`d (offline by
//! default; run with `-- --ignored --test-threads=1` — the ECPG stage has
//! been observed slow). Scope is deliberately mutation-free: token creation
//! and not-found queries; no payment is ever driven.

use ecpay::ecpg::{
    AtmInfo, BarcodeInfo, CardInfo, ConsumerInfo, CreatePaymentWithCardIdInput, CvsInfo,
    EcpgDoActionInput, EcpgTradeRefInput, GetTokenbyTradeInput, OrderInfo,
};
use ecpay::Ecpay;

/// Official public stage ECPG account (same as tests/stage_probes.rs):
/// ECPG signs with the PAYMENT HashKey/HashIV.
const MERCHANT_ID: &str = "3002607";
const KEY: &str = "pwFHCqoQZGmho4w6";
const IV: &str = "EkRm7iFT261dpevs";

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: KEY.into(),
        hash_iv: IV.into(),
        ecpg_api_url: "https://ecpg-stage.ecpay.com.tw/Merchant/".into(),
        ecpayment_api_url: "https://ecpayment-stage.ecpay.com.tw/1.0.0/".into(),
        ..Default::default()
    }
}

fn unique_no(tag: &str) -> String {
    // Milliseconds alone collide when parallel tests start in the same ms
    // (live-observed: `0|廠商訂單編號重覆`) — a per-process counter makes
    // every number unique. tag + 13 millis + 3 seq = 19 ≤ 20 chars.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{tag}{n}{seq:03}")
}

fn taipei_now() -> String {
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
        (tod % 3600) / 60,
        tod % 60
    )
}

/// The full field set mirrors example/Payment/Ecpg/CreateAllOrder/
/// GetToken.php (the same shape the manual probe proved). ConsumerInfo is
/// load-bearing: without Email/Phone the stage answers RtnCode ≠ 1 with no
/// message.
fn token_input() -> GetTokenbyTradeInput {
    GetTokenbyTradeInput {
        merchant_id: MERCHANT_ID.into(),
        remember_card: Some(1),
        payment_ui_type: Some(2),
        choose_payment_list: "0".into(),
        order_info: Some(OrderInfo {
            merchant_trade_date: taipei_now(),
            merchant_trade_no: unique_no("SBX"),
            total_amount: 100,
            return_url: "https://www.ecpay.com.tw/example/receive".into(),
            trade_desc: "ecpay-rs sandbox".into(),
            item_name: "商品 x1".into(),
        }),
        card_info: Some(CardInfo {
            redeem: Some(0),
            // RememberCard=1 makes OrderResultURL required (5100010).
            order_result_url: Some("https://www.ecpay.com.tw/example/receive".into()),
            credit_installment: Some("3,6,12".into()),
            flexible_installment: Some(30),
        }),
        atm_info: Some(AtmInfo {
            expire_date: Some(3),
        }),
        // Stage names these one by one with 5100010 when ChoosePaymentList
        // leaves them out — even a credit-only list ("0") needs them all
        // (live: "The parameter [CVSInfo] cannot be empty").
        cvs_info: Some(CvsInfo {
            store_expire_date: Some(10080),
        }),
        barcode_info: Some(BarcodeInfo {
            store_expire_date: Some(7),
        }),
        consumer_info: Some(ConsumerInfo {
            merchant_member_id: Some(unique_no("member")),
            email: "customer@email.com".into(),
            phone: "0912345678".into(),
            name: Some("沙盒測試".into()),
            country_code: Some("158".into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --test-threads=1 --nocapture"]
async fn get_token_by_trade_issues_a_real_token() {
    let out = sdk()
        .get_token_by_trade(&token_input())
        .await
        .expect("typed GetTokenbyTrade round-trips (TransCode gate)");
    println!("token out = {out:?}");
    assert_eq!(out.rtn_code, 1, "RtnMsg={:?}", out.rtn_msg);
    assert!(!out.token.is_empty(), "a token was issued");
    assert!(
        !out.token_expire_date.is_empty(),
        "TokenExpireDate rides along"
    );
}

/// The opaque-rejection contract documented on ConsumerInfo: a missing
/// Email/Phone is answered RtnCode ≠ 1 with (possibly) an EMPTY RtnMsg —
/// only the code is assertable.
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --test-threads=1 --nocapture"]
async fn get_token_by_trade_without_consumer_info_fails_opaquely() {
    let mut input = token_input();
    input.consumer_info = None;
    let out = sdk()
        .get_token_by_trade(&input)
        .await
        .expect("the envelope still decodes (TransCode=1)");
    println!("no-consumer out = {out:?}");
    assert_ne!(out.rtn_code, 1, "missing ConsumerInfo must be rejected");
    assert!(out.token.is_empty(), "no token on a rejected request");
}

/// The query family lives on the SECOND domain (`ecpayment`), and its
/// not-found answer is the in-band business shape `RtnCode 10000185` as a
/// JSON INTEGER (a string would silently break callers comparing to i64).
/// Server message copy drifts — RtnMsg is asserted non-empty, not verbatim.
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --test-threads=1 --nocapture"]
async fn query_family_not_found_is_an_in_band_integer_rtncode() {
    let client = sdk();
    // Data MerchantID is REQUIRED on all three query endpoints (stage
    // answers 10200051 MerchantID Error without it — the methods refuse
    // locally now, so Some() is the only reachable shape here).
    let query = || EcpgTradeRefInput {
        platform_id: None,
        merchant_id: Some(MERCHANT_ID.into()),
        merchant_trade_no: unique_no("SBX"), // never created
    };
    for out in [
        client.ecpg_query_trade(&query()).await,
        client.ecpg_query_payment_info(&query()).await,
        client.ecpg_query_credit_trade(&query()).await,
    ] {
        let out = out.expect("the envelope decodes (TransCode=1)");
        println!("query not-found = {out}");
        assert!(
            out["RtnCode"].is_i64(),
            "RtnCode must be a JSON integer, got {}",
            out["RtnCode"]
        );
        assert_eq!(out["RtnCode"], 10000185, "{out}");
        assert!(
            out["RtnMsg"].as_str().is_some_and(|m| !m.is_empty()),
            "{out}"
        );
    }
}

/// `Credit/DoAction` is the mutation endpoint on the ecpayment domain; with
/// the crate's required Data MerchantID set and a never-created trade it
/// answers the same in-band not-found shape — pinning the domain routing
/// and the integer RtnCode at zero mutation risk.
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --test-threads=1 --nocapture"]
async fn do_action_not_found_is_in_band_on_the_ecpayment_domain() {
    let out = sdk()
        .ecpg_do_action(&EcpgDoActionInput {
            platform_id: None,
            merchant_id: Some(MERCHANT_ID.into()), // required (10200051 without)
            merchant_trade_no: unique_no("SBX"),
            trade_no: unique_no("T"),
            action: "R".into(),
            total_amount: 100,
        })
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!("do-action not-found = {out}");
    assert!(
        out["RtnCode"].is_i64(),
        "RtnCode must be a JSON integer, got {}",
        out["RtnCode"]
    );
    assert_eq!(out["RtnCode"], 10000185, "{out}");
}

/// One more ecpg-domain method beyond GetTokenbyTrade, so the `Merchant/*`
/// family is not single-endpoint-covered: CreatePaymentWithCardID with a
/// never-issued BindCardID answers an in-band business error (TransCode
/// gate passes; the error is the expected answer, any code).
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --test-threads=1 --nocapture"]
async fn create_payment_with_unknown_bind_card_id_is_rejected_in_band() {
    let out = sdk()
        .create_payment_with_card_id(&CreatePaymentWithCardIdInput {
            merchant_id: MERCHANT_ID.into(),
            bind_card_id: unique_no("BIND"),
            order_info: Some(OrderInfo {
                merchant_trade_date: taipei_now(),
                merchant_trade_no: unique_no("SBX"),
                total_amount: 100,
                return_url: "https://www.ecpay.com.tw/example/receive".into(),
                trade_desc: "ecpay-rs sandbox".into(),
                item_name: "商品 x1".into(),
            }),
            consumer_info: Some(ConsumerInfo {
                email: "customer@email.com".into(),
                phone: "0912345678".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!("unknown bind card = {out}");
    assert!(
        out["RtnCode"].as_i64().is_some_and(|c| c != 1),
        "an unknown BindCardID must be a business-level rejection: {out}"
    );
}
