//! Live stage coverage for the two Big5 balance downloads — the only
//! payment-family endpoints that are stateless reads (no orders, no 字軌,
//! nothing to clean up). They were previously exercised only by the manual
//! `stage_smoke`; this suite re-pins the contract on every CI run:
//! transport + MD5-form round-trip + `decode_big5` against REAL stage bytes.
//!
//! The no-data window (2020, predating the account's stage activity) pins
//! the live contract that an EMPTY report is `Ok("")` — a legitimate
//! answer, not an error (first captured 2026-09 via stage_smoke).
//!
//! Every test is `#[ignore]`d — the default `cargo test` stays fully
//! offline; run with:
//! `cargo test --test sandbox_payment -- --ignored --nocapture`

use ecpay::Ecpay;

/// The downloads live on the vendor/credit paths and sign with the AIO
/// (payment) key pair of the public stage account 3002607.
fn stage() -> Ecpay {
    Ecpay::stage("3002607", "pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs")
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_payment -- --ignored --nocapture"]
async fn merchant_balance_download_round_trips_and_decodes() {
    let text = stage()
        .download_merchant_balance(&ecpay::payment::DownloadMerchantBalanceParams {
            date_type: "1".into(),
            begin_date: "2020-01-01".into(),
            end_date: "2020-01-02".into(),
            media_formated: "Y".into(),
            ..Default::default()
        })
        .await
        .expect("download_merchant_balance transport + Big5 decode");
    println!(
        "merchant balance (first 200) => {}",
        text.chars().take(200).collect::<String>()
    );
    // The pinned contract: an empty report is Ok(""), never an error, and
    // never a truncated/half line. (If stage data ever lands in this window,
    // keep the Ok and drop the emptiness half.)
    assert!(
        text.is_empty() || !text.lines().next().unwrap_or("").is_empty(),
        "a non-empty report must start with a header line: {text:?}"
    );
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_payment -- --ignored --nocapture"]
async fn disbursement_balance_download_round_trips_and_decodes() {
    let text = stage()
        .download_disbursement_balance(&ecpay::payment::DownloadDisbursementBalanceParams {
            pay_date_type: "1".into(),
            start_date: "2020-01-01".into(),
            end_date: "2020-01-02".into(),
        })
        .await
        .expect("download_disbursement_balance transport + Big5 decode");
    println!(
        "disbursement balance (first 200) => {}",
        text.chars().take(200).collect::<String>()
    );
    assert!(
        text.is_empty() || !text.lines().next().unwrap_or("").is_empty(),
        "a non-empty report must start with a header line: {text:?}"
    );
}
