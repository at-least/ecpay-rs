//! Smoke tests against ECPay's REAL stage (sandbox) server, using the public
//! test account every official doc and ECPay's own AI-skill publish
//! (MerchantID 3002607 / stage HashKey/HashIV).
//!
//! These tests are `#[ignore]`d: the default `cargo test` stays offline.
//! Run them explicitly:
//!
//! ```text
//! cargo test --test stage_smoke -- --ignored --nocapture
//! ```
//!
//! What they prove (and nothing less): the stage server accepts this
//! library's CheckMacValue signing and returns responses this library can
//! parse and re-verify end-to-end. They do NOT prove payment flows (that
//! needs the stage vendor console's 模擬付款 or a browser checkout).

use std::time::{SystemTime, UNIX_EPOCH};

use ecpay::payment::{
    action, AioCheckOutParams, ChoosePayment, CreditDoActionParams, OrderSearchParams,
    OrderSearchPeriodParams, SearchSingleTransactionParams,
};
use ecpay::Ecpay;

const STAGE_MERCHANT_ID: &str = "3002607";
const STAGE_HASH_KEY: &str = "pwFHCqoQZGmho4w6";
const STAGE_HASH_IV: &str = "EkRm7iFT261dpevs";
const STAGE_PAYMENT_URL: &str = "https://payment-stage.ecpay.com.tw/Cashier/";
const STAGE_CREDIT_URL: &str = "https://payment-stage.ecpay.com.tw/CreditDetail/";
const STAGE_VENDOR_URL: &str = "https://vendor-stage.ecpay.com.tw/PaymentMedia/";

fn stage() -> Ecpay {
    Ecpay {
        merchant_id: STAGE_MERCHANT_ID.into(),
        hash_key: STAGE_HASH_KEY.into(),
        hash_iv: STAGE_HASH_IV.into(),
        payment_api_url: STAGE_PAYMENT_URL.into(),
        credit_api_url: STAGE_CREDIT_URL.into(),
        vendor_api_url: STAGE_VENDOR_URL.into(),
        ..Default::default()
    }
}

/// Current Taipei time as ECPay's `yyyy/MM/dd HH:mm:ss`, std-only.
fn taipei_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 8 * 3600; // UTC+8
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
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

fn unique_trade_no(tag: &str) -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{tag}{n}")
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn stage_order_search_round_trips_the_mac() {
    let client = stage();
    // A trade number that does not exist: the server should still answer a
    // SIGNED query-string response whose CheckMacValue this library
    // verifies — order_search returning Ok is itself the end-to-end proof
    // (it errors on any MAC mismatch).
    let result = client
        .order_search(&OrderSearchParams {
            merchant_trade_no: unique_trade_no("SMOKE"),
            time_stamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            platform_id: None,
        })
        .await
        .expect("order_search must succeed end-to-end (MAC verified)");
    println!("order_search => {result:?}");
    // QueryTradeInfo has no RtnCode: a missing trade surfaces as
    // TradeStatus=10200047. Ok(_) already proves the response MAC verified.
    assert_eq!(
        result.get("TradeStatus").map(String::as_str),
        Some("10200047"),
        "a nonexistent trade must decode into the spec's TradeStatus=10200047"
    );
    assert_ne!(
        result.get("TradeAmt").map(String::as_str),
        Some("1"),
        "sanity"
    );
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn stage_accepts_the_checkout_params() {
    let client = stage();
    let checkout = client
        .aio_check_out(&AioCheckOutParams {
            merchant_trade_no: unique_trade_no("SMOKE"),
            merchant_trade_date: taipei_now(),
            total_amount: 1000,
            trade_desc: "ecpay-rs stage smoke".into(),
            item_name: "測試商品#第二項".into(),
            return_url: "https://example.com/ecpay/return".into(),
            choose_payment: ChoosePayment::All,
            ignore_payment: Some("WebATM#BARCODE".into()),
            need_extra_paid_info: Some("N".into()),
            ..Default::default()
        })
        .expect("aio_check_out validation");

    // POST the signed params to the stage checkout endpoint the way the
    // browser would. A rejected signature yields ECPay's error text; a
    // successful order yields the cashier page.
    let body = form_post(checkout.action(), checkout.params()).await;
    println!("AioCheckOut/V5 status=200 bytes={}", body.len());
    // Observed stage behavior: a valid signature renders the full cashier
    // page (選擇付款方式…); a tampered one renders the 交易失敗 page with
    // 訊息代碼 10200073 (CheckMacValue Error).
    assert!(
        body.contains("選擇付款方式"),
        "the stage server did not render the cashier page — it likely rejected the request"
    );
    assert!(
        !body.contains("10200073") && !body.contains("CheckMacValue Error"),
        "the stage server rejected the CheckMacValue — signing diverges from the real server"
    );
}

/// Negative control: the same params with one flipped hex char in the MAC
/// must hit the stage's 10200073 CheckMacValue-Error failure page. Without
/// this, a stage that ignored CheckMacValue entirely would pass the positive
/// test vacuously.
#[tokio::test]
#[ignore = "hits the real stage server"]
async fn stage_rejects_a_tampered_checkout_mac() {
    let client = stage();
    let checkout = client
        .aio_check_out(&AioCheckOutParams {
            merchant_trade_no: unique_trade_no("SMOKE"),
            merchant_trade_date: taipei_now(),
            total_amount: 1000,
            trade_desc: "ecpay-rs stage smoke".into(),
            item_name: "測試商品".into(),
            return_url: "https://example.com/ecpay/return".into(),
            choose_payment: ChoosePayment::All,
            ..Default::default()
        })
        .expect("aio_check_out validation");
    let mut tampered: Vec<(String, String)> = checkout.params().to_vec();
    for (k, v) in tampered.iter_mut() {
        if k == "CheckMacValue" {
            let flipped = if v.starts_with('A') { "B" } else { "A" };
            v.replace_range(..1, flipped);
        }
    }
    let action = checkout.action().to_owned();
    let body = form_post(&action, &tampered).await;
    println!("tampered bytes={}", body.len());
    assert!(
        body.contains("10200073") || body.contains("CheckMacValue Error"),
        "expected the stage's CheckMacValue-Error page for a tampered MAC"
    );
    assert!(
        !body.contains("選擇付款方式"),
        "a tampered MAC must not reach the cashier page"
    );
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn stage_period_query_and_credit_action_answer() {
    let client = stage();

    let period = client
        .order_search_period(&OrderSearchPeriodParams {
            merchant_trade_no: unique_trade_no("SMOKE"),
            time_stamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        })
        .await
        .expect("order_search_period transport");
    println!("order_search_period => {period}");

    let do_action = client
        .credit_do_action(&CreditDoActionParams {
            merchant_trade_no: unique_trade_no("SMOKE"),
            trade_no: unique_trade_no("NO"),
            action: action::CLOSE.into(),
            total_amount: 100,
            platform_id: None,
        })
        .await
        .expect("credit_do_action transport");
    println!("credit_do_action => {do_action:?}");
    assert!(!do_action.is_empty(), "DoAction must answer form fields");
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn stage_single_transaction_and_balance_endpoints_answer() {
    let client = stage();

    let single = client
        .search_single_transaction(&SearchSingleTransactionParams {
            credit_refund_id: 0,
            credit_amount: 0,
            credit_check_code: 0,
        })
        .await
        .expect("search_single_transaction transport");
    println!("search_single_transaction => {single}");

    let balance = client
        .download_merchant_balance(&ecpay::payment::DownloadMerchantBalanceParams {
            date_type: "1".into(),
            begin_date: "2026-09-01".into(),
            end_date: "2026-09-02".into(),
            media_formated: "Y".into(),
            ..Default::default()
        })
        .await
        .expect("download_merchant_balance transport");
    println!(
        "download_merchant_balance (first 200) => {}",
        balance.chars().take(200).collect::<String>()
    );

    let _ = client; // vendor endpoint answered; content depends on stage data
}

async fn form_post(endpoint: &str, pairs: &[(String, String)]) -> String {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = reqwest::Client::new()
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .expect("POST to stage");
    let status = resp.status();
    let text = resp.text().await.expect("stage body");
    assert!(status.is_success(), "stage returned {status}");
    text
}

fn urlencode(s: &str) -> String {
    // requests-style form encoding (quote_plus): alnum + '_.-~' literal,
    // space -> '+', everything else uppercase %XX.
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
