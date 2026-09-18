//! Live B2B e-invoice tests against the ECPay stage server. The public test
//! account 2000132 IS B2B-enabled (proven by the stage probes, commit
//! ed87553: `RtnCode=1 發票開立成功`), so a full issue → query → void
//! lifecycle runs unattended. Like `tests/sandbox.rs` every test is
//! `#[ignore]`d (run with `-- --ignored`): this needs outbound network,
//! and every run consumes one stage 字軌 number.

use ecpay::invoice_b2b::{GetIssueInput, InvalidInput, IssueB2bInput};
use ecpay::Ecpay;
mod common;
use common::sandbox::{taipei_today, unique_no};

const MERCHANT_ID: &str = "2000132";
const B2B_KEY: &str = "ejCk326UnaZWKisg";
const B2B_IV: &str = "q9jcZX8Ib9LM8wYk";

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        // Inert placeholders: this suite only calls invoice-family APIs
        // (invoice_hash_key below); the payment pair is never used. Keep the
        // struct shape explicit so an AIO call added here fails loudly at a
        // wrong-key MAC rather than silently.
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        invoice_hash_key: B2B_KEY.to_owned(),
        invoice_hash_iv: B2B_IV.to_owned(),
        b2b_invoice_api_url: "https://einvoice-stage.ecpay.com.tw/B2BInvoice/".into(),
        b2b_rq_id: "701b3264-a538-437e-ad45-2505eb7dde39".into(),
        ..Default::default()
    }
}

fn sample_issue(relate_number: String) -> IssueB2bInput {
    IssueB2bInput {
        merchant_id: MERCHANT_ID.into(),
        relate_number,
        customer_identifier: "23165448".into(),
        customer_email: "test-buyer@ecpay.com.tw".into(),
        inv_type: "07".into(),
        tax_type: "1".into(),
        items: vec![ecpay::invoice_b2b::B2bItem {
            item_seq: 1,
            item_name: "測試商品01".into(),
            item_count: 3.0,
            item_price: 10.0,
            item_tax_type: "1".into(),
            item_amount: 30.0,
            ..Default::default()
        }],
        sales_amount: 30,
        tax_amount: 2, // round(30 * 0.05)
        total_amount: 32,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_b2b -- --ignored --nocapture"]
async fn b2b_issue_then_get_then_invalid_roundtrip() {
    let client = sdk();

    // Sample the date ONCE and use it for every leg: B2B Issue takes no
    // caller date and B2bIssueOutput returns none, so re-reading the local
    // clock per leg let a run straddling Taipei midnight query/void with a
    // different date than the invoice was recorded under (6070004). One
    // sample narrows that window to test-start → server receipt.
    let issue_date = taipei_today();

    // 1. 開立 — the wire contract proven by the probes: RtnCode=1 + 發票號.
    //    unique_no (tag + millis + per-process seq) instead of bare millis:
    //    the shared helper exists because millis alone collided live.
    let relate_number = unique_no("B2B");
    let issue = client
        .issue_b2b(&sample_issue(relate_number.clone()))
        .await
        .expect("B2B Issue envelope round-trips (TransCode gate)");
    println!("issue = {issue:?}");
    assert_eq!(issue.rtn_code, 1, "RtnMsg={:?}", issue.rtn_msg);
    assert!(!issue.invoice_number.is_empty(), "invoice number minted");

    // 2. 查詢 — GET the issued invoice back. Server-truth (2026-09): B2B
    // GetIssue wraps the record in `RtnData` and its RtnCode is the STRING
    // "1" (unlike Issue's integer); the record mixes PascalCase with
    // snake_case keys (`Buyer_Address`, `Invalid_Status`, lowercase `items`).
    let got = client
        .get_issue_b2b(&GetIssueInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_category: 0,
            invoice_number: issue.invoice_number.clone(),
            invoice_date: issue_date.clone(),
        })
        .await
        .expect("GetIssue decodes");
    println!("get_issue = {got:?}");
    assert_eq!(got["RtnCode"], "1", "issue is queryable: {got}");
    assert_eq!(
        got["RtnData"]["RelateNumber"], relate_number,
        "the record is nested under RtnData"
    );

    // 3. 作廢 — void it so the lifecycle closes.
    let voided = client
        .invalid_b2b(&InvalidInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_number: issue.invoice_number.clone(),
            invoice_date: issue_date,
            reason: "sandbox test".into(), // ≤20 chars (2103005 otherwise)
        })
        .await
        .expect("Invalid decodes");
    println!("invalid = {voided:?}");
    assert_eq!(voided["RtnCode"], 1, "void succeeds: {voided}");
}

/// `Invalid.Reason` is capped at 20 characters and the cap is checked
/// BEFORE the invoice lookup: an over-long reason is `2103005 發票作廢原因
/// 格式錯誤` even for an invoice that does not exist, while a short one on
/// the same unknown invoice is `6070004 發票號碼或日期錯誤` (captured
/// 2026-09). Stateless — nothing is issued.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_b2b -- --ignored --nocapture"]
async fn b2b_invalid_reason_length_is_checked_before_the_lookup() {
    let client = sdk();
    let unknown = InvalidInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_number: "ZZ00000000".into(),
        invoice_date: taipei_today(),
        reason: "一二三四五六七八九十一二三四五六七八九十一".into(), // 21 chars
    };
    let long = client.invalid_b2b(&unknown).await.expect("decodes");
    assert_eq!(long["RtnCode"], 2103005, "{long}");
    let short = client
        .invalid_b2b(&InvalidInput {
            reason: "short".into(),
            ..unknown
        })
        .await
        .expect("decodes");
    assert_eq!(short["RtnCode"], 6070004, "{short}");
}

/// GetIssue on a fabricated number: the lookup-key contract (InvoiceNumber
/// + InvoiceDate) — the answer must be an in-band business rejection whose
/// RtnCode is a STRING (the type quirk the roundtrip pins for success).
/// Stateless — nothing is issued.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_b2b -- --ignored --nocapture"]
async fn b2b_get_issue_not_found_is_an_in_band_string_rtncode() {
    let got = sdk()
        .get_issue_b2b(&GetIssueInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_category: 0,
            invoice_number: "ZZ00000000".into(),
            invoice_date: taipei_today(),
        })
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!("get_issue not-found = {got:?}");
    assert!(
        got["RtnCode"].is_string(),
        "B2B GetIssue's RtnCode is the STRING type quirk, got {}",
        got["RtnCode"]
    );
    assert_ne!(got["RtnCode"], "1", "a fabricated number must not be found");
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_b2b -- --ignored --nocapture"]
async fn b2b_get_invoice_word_setting_answers() {
    // 民國年 for 2026 is 115; term/use/category follow the official example's
    // shape (InvoiceCategory=2 is the B2B value in the PHP example).
    // Live-captured 2026-09: the shared stage account answers RtnCode=1
    // "查詢成功" with a NON-empty InvoiceInfo array (dozens of real 字軌
    // records for year 115) — assert that shape, not just "it answered".
    let out = sdk()
        .get_invoice_word_setting_b2b(&ecpay::invoice_b2b::GetInvoiceWordSettingInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_year: "115".into(),
            invoice_term: 0,
            use_status: 0,
            invoice_category: 2,
        })
        .await
        .expect("the envelope decodes (TransCode=1)");
    println!(
        "word setting => {} records",
        out["InvoiceInfo"].as_array().map_or(0, Vec::len)
    );
    assert_eq!(
        out["RtnCode"],
        serde_json::json!(1),
        "query must succeed: {out}"
    );
    let records = out["InvoiceInfo"].as_array().cloned().unwrap_or_default();
    assert!(
        !records.is_empty(),
        "the shared stage account has real 字軌 records for year 115: {out}"
    );
    for record in &records {
        assert!(
            record["InvType"].is_string(),
            "each record carries InvType: {record}"
        );
        assert!(
            record["InvoiceHeader"].is_string() && record["InvoiceStart"].is_string(),
            "each record carries its 字軌 header and start number: {record}"
        );
    }
}
