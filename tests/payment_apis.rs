//! Transport tests for the payment-SDK APIs: hermetic mock endpoints for the
//! Cashier / CreditDetail / vendor bases, plus the documented invoice-field
//! case-preservation divergence test.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ecpay::payment::{action, AioCheckOutParams, ChoosePayment, InvoiceExtend};
use ecpay::Ecpay;

mod common;
use common::spawn_http_server;

const MERCHANT_ID: &str = "3002607";
const HASH_KEY: &str = "pwFHCqoQZGmho4w6";
const HASH_IV: &str = "EkRm7iFT261dpevs";

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.to_owned(),
        hash_key: HASH_KEY.to_owned(),
        hash_iv: HASH_IV.to_owned(),
        ..Default::default()
    }
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
async fn order_search_verifies_the_response_mac() {
    let srv = spawn_http_server(move |_path, _body| {
        // Sign exactly the map the client will reconstruct from the body
        // (duplicate keys resolve last-wins).
        let respond = map(&[
            ("MerchantID", MERCHANT_ID),
            ("MerchantTradeNo", "order_abc"),
            ("TradeAmt", "100"),
            ("TradeStatus", "1"),
            ("PaymentDate", "2024/01/02 03:04:05"),
            ("EmptyField", ""),
            ("Dup", "last"),
        ]);
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            respond
                .iter()
                .map(|(k, v)| format!("{k}={}", v.replace(' ', "+")))
                .chain(std::iter::once(format!("CheckMacValue={mac}")))
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let got = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("order_search");

    // CheckMacValue is stripped; blanks kept; duplicate keys last-wins
    // (dict(parse_qsl(...)) semantics).
    assert_eq!(got.get("TradeStatus").map(String::as_str), Some("1"));
    assert_eq!(got.get("EmptyField").map(String::as_str), Some(""));
    assert_eq!(got.get("Dup").map(String::as_str), Some("last"));
    assert!(!got.contains_key("CheckMacValue"));
}

#[tokio::test]
async fn order_search_rejects_a_tampered_response_mac() {
    let srv = spawn_http_server(move |_path, _body| {
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            "MerchantTradeNo=order_abc&TradeStatus=1&CheckMacValue=DEADBEEF"
                .to_owned()
                .into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let err = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect_err("a wrong CheckMacValue must fail");
    assert!(matches!(err, ecpay::Error::CheckMacValueMismatch), "{err}");

    // A response without CheckMacValue fails the same way.
    let srv = spawn_http_server(move |_path, _body| {
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            "MerchantTradeNo=order_abc&TradeStatus=1"
                .to_owned()
                .into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let err = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect_err("a missing CheckMacValue must fail");
    assert!(matches!(err, ecpay::Error::CheckMacValueMismatch), "{err}");
}

#[tokio::test]
async fn order_search_request_is_signed_and_routed() {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured2 = captured.clone();
    let srv = spawn_http_server(move |path, body| {
        let body = String::from_utf8_lossy(body).into_owned();
        assert!(
            body.contains("MerchantID=3002607")
                && body.contains("MerchantTradeNo=order_abc")
                && body.contains("TimeStamp=1700000000"),
            "the request must carry the spec params + MAC: {body}"
        );
        // Reply with the same fields the request carried (plus a status), so
        // the client's recomputed MAC can only match if it signs the
        // RESPONSE fields exactly like the SDK does.
        let respond = map(&[
            ("MerchantID", MERCHANT_ID),
            ("MerchantTradeNo", "order_abc"),
            ("TradeStatus", "0"),
        ]);
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
        *captured2.lock().unwrap() = Some(format!("{path}|{body}"));
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            format!(
                "MerchantID={MERCHANT_ID}&MerchantTradeNo=order_abc&TradeStatus=0&CheckMacValue={mac}"
            )
            .into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv.clone(),
        ..sdk()
    };
    client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("order_search");
    let got = captured.lock().unwrap().clone().expect("captured");
    assert!(
        got.starts_with("/QueryTradeInfo/V5|"),
        "endpoint path: {got}"
    );
    for key in [
        "MerchantID",
        "MerchantTradeNo",
        "TimeStamp",
        "CheckMacValue",
    ] {
        assert!(got.contains(key), "request must carry {key}: {got}");
    }
}

#[tokio::test]
async fn json_apis_parse_their_replies() {
    // QueryCreditCardPeriodInfo returns a JSON array.
    let srv = spawn_http_server(move |_path, _body| {
        (
            200,
            "application/json".to_owned(),
            r#"[{"ArtNo":"NN00000001","ProcessDate":"2024-01-01"}]"#
                .to_owned()
                .into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let got = client
        .order_search_period(&ecpay::payment::OrderSearchPeriodParams {
            merchant_trade_no: "period_1".into(),
            time_stamp: 1,
        })
        .await
        .expect("order_search_period");
    assert_eq!(got[0]["ArtNo"], "NN00000001");

    // CreditDetail/QueryTrade/V2 returns a JSON object.
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured2 = captured.clone();
    let srv = spawn_http_server(move |path, _body| {
        *captured2.lock().unwrap() = Some(path.to_owned());
        (
            200,
            "application/json".to_owned(),
            br#"{"RtnCode":1,"RtnMsg":"Succeeded","CreditAmount":100}"#.to_vec(),
        )
    });
    let client = Ecpay {
        credit_api_url: srv,
        ..sdk()
    };
    let got = client
        .search_single_transaction(&ecpay::payment::SearchSingleTransactionParams {
            credit_refund_id: 123,
            credit_amount: 100,
            credit_check_code: 4567,
        })
        .await
        .expect("search_single_transaction");
    assert_eq!(got["RtnCode"], 1);
    assert_eq!(got["CreditAmount"], 100);
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some("/QueryTrade/V2"),
        "CreditDetail routes under credit_api_url"
    );
}

#[tokio::test]
async fn big5_endpoints_decode_the_reply() {
    // The TradeNoAio / FundingReconDetail replies are Big5 CSV text.
    let (text, _, _) = encoding_rs::BIG5.decode(b"\xb4\xfa\xb8\xd5"); // 測試
    assert_eq!(text, "測試", "sanity: fixture bytes are Big5 for 測試");
    let bytes: &[&[u8]] = &[b"\xb4\xfa\xb8\xd5,100,\r\n"];
    let srv = spawn_http_server(move |path, _body| {
        assert!(
            path == "/TradeNoAio" || path == "/FundingReconDetail",
            "{path}"
        );
        (200, "text/plain".to_owned(), bytes[0].to_vec())
    });
    let client = Ecpay {
        vendor_api_url: srv.clone(),
        credit_api_url: srv,
        ..sdk()
    };
    let got = client
        .download_merchant_balance(&ecpay::payment::DownloadMerchantBalanceParams {
            date_type: "1".into(),
            begin_date: "2024-01-01".into(),
            end_date: "2024-01-02".into(),
            media_formated: "Y".into(),
            ..Default::default()
        })
        .await
        .expect("download_merchant_balance");
    assert_eq!(got, "測試,100,\r\n");

    let got = client
        .download_disbursement_balance(&ecpay::payment::DownloadDisbursementBalanceParams {
            pay_date_type: "1".into(),
            start_date: "2024-01-01".into(),
            end_date: "2024-01-02".into(),
        })
        .await
        .expect("download_disbursement_balance");
    assert_eq!(got, "測試,100,\r\n");
}

#[tokio::test]
async fn action_apis_route_and_parse() {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured2 = captured.clone();
    let srv = spawn_http_server(move |path, _body| {
        *captured2.lock().unwrap() = Some(path.to_owned());
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            "RtnCode=1&RtnMsg=OK".to_owned().into_bytes(),
        )
    });
    let client = Ecpay {
        credit_api_url: srv.clone(),
        payment_api_url: srv,
        ..sdk()
    };

    let got = client
        .credit_do_action(&ecpay::payment::CreditDoActionParams {
            merchant_trade_no: "no1".into(),
            trade_no: "2308150001".into(),
            action: action::CLOSE.into(),
            total_amount: 100,
            platform_id: None,
        })
        .await
        .expect("credit_do_action");
    assert_eq!(got.get("RtnCode").map(String::as_str), Some("1"));
    assert_eq!(captured.lock().unwrap().as_deref(), Some("/DoAction"));

    let got = client
        .credit_card_period_action(&ecpay::payment::CreditCardPeriodActionParams {
            merchant_trade_no: "no1".into(),
            action: "ModifyStatus".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect("credit_card_period_action");
    assert_eq!(got.get("RtnMsg").map(String::as_str), Some("OK"));
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some("/CreditCardPeriodAction")
    );
}

/// The documented invoice-field divergence: the official SDK lowercases the
/// urlencoded free-text fields, corrupting ASCII letter case in customer
/// data (`"AB市"` arrives as `"ab市"`). Ours preserves the case; hex case is
/// irrelevant after the server's url-decode.
#[test]
fn invoice_free_text_fields_preserve_letter_case() {
    let client = sdk();
    let out = client
        .aio_check_out(&AioCheckOutParams {
            merchant_trade_no: "NO20240101120000".into(),
            merchant_trade_date: "2024/01/01 12:00:00".into(),
            total_amount: 2000,
            trade_desc: "訂單測試".into(),
            item_name: "商品".into(),
            return_url: "https://www.example.com/return".into(),
            choose_payment: ChoosePayment::Credit,
            invoice: Some(InvoiceExtend {
                relate_number: "R1".into(),
                customer_name: Some("AB市".into()),
                customer_addr: Some("台北市".into()),
                customer_phone: Some("0912345678".into()),
                tax_type: ecpay::payment::tax_type::DUTIABLE.into(),
                donation: ecpay::payment::donation::NO.into(),
                print: ecpay::payment::print_mark::NO.into(),
                invoice_item_name: "Widget#小物".into(),
                invoice_item_count: "1#2".into(),
                invoice_item_word: "個#個".into(),
                invoice_item_price: "10#20".into(),
                delay_day: 0,
                inv_type: ecpay::payment::inv_type::GENERAL.into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .expect("checkout builds");
    let get = |key: &str| {
        out.params()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    let name = get("CustomerName");
    assert!(
        name.contains("AB"),
        "letter case must survive: {name} (the official SDK would send {name:?} lowercased)"
    );
    assert_eq!(name, "AB%E5%B8%82", "uppercase hex escapes, ~ .NET style");
}
