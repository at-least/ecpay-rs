//! Live ECPG (站內付 2.0) tests against the two real stage domains — the
//! dual-domain family (ecpg `Merchant/*` vs ecpayment `1.0.0/*`) that was
//! previously live-covered only by the MANUAL probes in `tests/
//! stage_probes.rs` (raw envelopes plus one typed query probe) and one typed
//! probe in `tests/ecpg_wire.rs`. These use the real `Ecpay` methods end to
//! end (envelope build, encrypt_checked guard, TransCode gate, typed decode).
//!
//! Like the other sandbox suites every test is `#[ignore]`d (offline by
//! default; run with `-- --ignored`; `unique_no` carries a per-process
//! counter so the default parallelism is safe). Scope: token issuance,
//! parameter-validation and not-found answers — no payment is ever driven.

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
    // (the logistics suite hit `0|廠商訂單編號重覆` that way; ECPG answers
    // AES-JSON, not the `0|` form protocol) — a per-process counter makes
    // every number unique. MerchantTradeNo is capped at 20 chars: "SBX" +
    // 13 millis + 3 seq = 19. Longer tags are only used for
    // MerchantMemberID / BindCardID.
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
/// GetToken.php (the same shape the manual probe proved). `RememberCard=1`
/// makes `ConsumerInfo` (with `MerchantMemberID`) required — see
/// `missing_consumer_info_is_named_by_stage_only_with_remember_card`.
fn token_input() -> GetTokenbyTradeInput {
    GetTokenbyTradeInput {
        merchant_id: MERCHANT_ID.into(),
        remember_card: Some(1),
        payment_ui_type: Some(2),
        // "0" = ALL payment methods per the spec (guides/02 §8 種付款方式);
        // the sub-objects below follow the official CreateAllOrder example
        // minus UnionPayInfo (stage issues the token without it).
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
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --nocapture"]
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

/// The ConsumerInfo contract documented on `ConsumerInfo`: with
/// `RememberCard=1` a missing ConsumerInfo is a NAMED parameter-validation
/// error (5100010, the message names the parameter — it is not an opaque
/// `RtnCode != 1`); with `RememberCard=0` the whole object may be omitted
/// and a token is still issued. Message copy drifts, so the code is pinned
/// and the message is only searched for the parameter name.
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --nocapture"]
async fn missing_consumer_info_is_named_by_stage_only_with_remember_card() {
    let client = sdk();

    let mut input = token_input();
    input.consumer_info = None;
    let out = client
        .get_token_by_trade(&input)
        .await
        .expect("the envelope still decodes (TransCode=1)");
    println!("RememberCard=1, no ConsumerInfo = {out:?}");
    assert_eq!(out.rtn_code, 5100010, "named parameter error: {out:?}");
    assert!(
        out.rtn_msg.contains("ConsumerInfo"),
        "the message names the parameter: {out:?}"
    );
    assert!(out.token.is_empty(), "no token on a rejected request");

    let mut input = token_input();
    input.remember_card = Some(0);
    input.consumer_info = None;
    let out = client
        .get_token_by_trade(&input)
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!("RememberCard=0, no ConsumerInfo = {out:?}");
    assert_eq!(out.rtn_code, 1, "RtnMsg={:?}", out.rtn_msg);
    assert!(
        !out.token.is_empty(),
        "ConsumerInfo is not required without RememberCard"
    );
}

/// The query family lives on the SECOND domain (`ecpayment`), and its
/// not-found answer is the in-band business shape `RtnCode 10000185` as a
/// JSON INTEGER (a string would silently break callers comparing to i64).
/// Server message copy drifts — RtnMsg is asserted non-empty, not verbatim.
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --nocapture"]
async fn query_family_not_found_is_an_in_band_integer_rtncode() {
    let client = sdk();
    // Data MerchantID is REQUIRED on all three query endpoints (stage
    // answers 5000220 "The parameter [MerchantID] is required." without it
    // — pinned by the raw-envelope probe in tests/stage_probes.rs; the
    // typed methods refuse an empty value locally).
    let query = || EcpgTradeRefInput {
        platform_id: None,
        merchant_id: MERCHANT_ID.into(),
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
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --nocapture"]
async fn do_action_not_found_is_in_band_on_the_ecpayment_domain() {
    let out = sdk()
        .ecpg_do_action(&EcpgDoActionInput {
            platform_id: None,
            merchant_id: MERCHANT_ID.into(), // required (5000220 without)
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
/// never-issued BindCardID answers the in-band not-found code 5100088
/// ("The BindCard does not exist."). That answer is only reachable with
/// `MerchantMemberID` supplied — without it stage stops at parameter
/// validation (5100010 "The parameter [MerchantMemberID] cannot be empty")
/// before any card lookup. Both shapes are pinned so the not-found arm
/// cannot silently turn vacuous again.
#[tokio::test]
#[ignore = "hits the live ECPG stage server (public test account); run with: cargo test --test sandbox_ecpg -- --ignored --nocapture"]
async fn create_payment_with_unknown_bind_card_id_is_rejected_in_band() {
    let client = sdk();
    let request = |merchant_member_id: Option<String>| CreatePaymentWithCardIdInput {
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
            merchant_member_id,
            email: "customer@email.com".into(),
            phone: "0912345678".into(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let out = client
        .create_payment_with_card_id(&request(None))
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!("unknown bind card, no MerchantMemberID = {out}");
    assert_eq!(
        out["RtnCode"], 5100010,
        "parameter validation stops the request before the card lookup: {out}"
    );
    assert!(
        out["RtnMsg"]
            .as_str()
            .is_some_and(|m| m.contains("MerchantMemberID")),
        "the message names the parameter: {out}"
    );

    let out = client
        .create_payment_with_card_id(&request(Some(unique_no("member"))))
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!("unknown bind card = {out}");
    assert_eq!(
        out["RtnCode"], 5100088,
        "an unknown BindCardID must reach the card lookup: {out}"
    );
    assert!(
        out["RtnMsg"]
            .as_str()
            .is_some_and(|m| m.contains("BindCard")),
        "the message names the card: {out}"
    );
}
