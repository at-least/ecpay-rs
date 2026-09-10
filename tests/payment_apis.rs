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
async fn query_payment_info_verifies_the_response_mac() {
    let srv = spawn_http_server(move |_path, _body| {
        let respond = map(&[
            ("MerchantID", MERCHANT_ID),
            ("MerchantTradeNo", "order_abc"),
            ("TradeAmt", "100"),
            ("PaymentType", "ATM_TAISHIN"),
            ("BankCode", "812"),
            ("vAccount", "3141592653589793"),
            ("ExpireDate", "2024/01/05"),
        ]);
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            respond
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
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
        .query_payment_info(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("query_payment_info");

    assert_eq!(got.get("BankCode").map(String::as_str), Some("812"));
    assert_eq!(
        got.get("vAccount").map(String::as_str),
        Some("3141592653589793")
    );
    assert!(!got.contains_key("CheckMacValue"));
}

/// Regression test for a real bug found while comparing this crate against
/// the official `ECPay/SDK_PHP` repo and probing the live stage server:
/// ECPay's "trade not found" reply for `QueryPaymentInfo` echoes back
/// `MerchantID=""` (confirmed live against stage, 2026-09), unlike
/// `QueryTradeInfo/V5`'s equivalent reply which happens to echo the real
/// MerchantID. The shared response-verification helper used to reuse
/// `generate_check_value` — which forces `MerchantID` to the client's
/// configured ID before hashing, correct for signing OUR outbound requests
/// but wrong for verifying a response, since it must be hashed exactly as
/// the server sent it. That produced a false-positive
/// `CheckMacValueMismatch` on an honestly-signed response whenever a
/// response field didn't echo the client's own MerchantID.
#[tokio::test]
async fn query_payment_info_accepts_a_response_with_blank_merchant_id() {
    let respond = map(&[
        ("MerchantID", ""),
        ("MerchantTradeNo", ""),
        ("RtnCode", "10200047"),
        ("RtnMsg", "Cant not find the trade data."),
    ]);
    let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
    let srv = spawn_http_server(move |_path, _body| {
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            respond
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
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
        .query_payment_info(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_missing".into(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("a correctly-signed response must verify even with a blank MerchantID field");
    assert_eq!(got.get("RtnCode").map(String::as_str), Some("10200047"));
}

#[tokio::test]
async fn query_payment_info_request_is_signed_and_routed() {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured2 = captured.clone();
    let srv = spawn_http_server(move |path, body| {
        let body = String::from_utf8_lossy(body).into_owned();
        *captured2.lock().unwrap() = Some(format!("{path}|{body}"));
        let respond = map(&[("MerchantID", MERCHANT_ID), ("RtnCode", "10200047")]);
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            format!("MerchantID={MERCHANT_ID}&RtnCode=10200047&CheckMacValue={mac}").into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    client
        .query_payment_info(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1_700_000_000,
            platform_id: None,
        })
        .await
        .expect("query_payment_info");
    let got = captured.lock().unwrap().clone().expect("captured");
    assert!(
        got.starts_with("/QueryPaymentInfo|"),
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

/// `call_payment_api` parses the reply like Go's `url.ParseQuery`: the FIRST
/// value wins on a duplicate key (opposite of `parse_qsl`'s last-wins on
/// the Python-flavored endpoints), a `;` is rejected, and a malformed escape
/// is an error rather than a literal.
#[tokio::test]
async fn query_trade_info_parses_like_go_parse_query() {
    let serve = |body: &'static str| {
        spawn_http_server(move |_path, _body| {
            (
                200,
                "application/x-www-form-urlencoded".to_owned(),
                body.as_bytes().to_vec(),
            )
        })
    };

    let client = Ecpay {
        payment_api_url: serve(
            "MerchantTradeNo=first&MerchantTradeNo=second&TradeStatus=1&TradeDesc=a%20b%2Bc",
        ),
        ..sdk()
    };
    let out = client
        .query_trade_info("x")
        .await
        .expect("query_trade_info");
    assert_eq!(out.merchant_trade_no, "first", "first value wins");
    assert_eq!(out.trade_status, "1");

    let client = Ecpay {
        payment_api_url: serve("MerchantTradeNo=a;TradeStatus=1"),
        ..sdk()
    };
    let err = client
        .query_trade_info("x")
        .await
        .expect_err("a semicolon separator is rejected");
    assert!(matches!(err, ecpay::Error::SemicolonInQuery), "{err:?}");

    let client = Ecpay {
        payment_api_url: serve("MerchantTradeNo=%zz&TradeStatus=1"),
        ..sdk()
    };
    let err = client
        .query_trade_info("x")
        .await
        .expect_err("a malformed escape is rejected");
    match err {
        ecpay::Error::UrlEscape(esc) => assert_eq!(esc, "%zz"),
        other => panic!("expected Error::UrlEscape, got {other:?}"),
    }
}

/// The Python-flavored endpoints decode with `parse_qsl` leniency: a
/// malformed escape stays literal, `a=b=c` splits on the first `=`, and a
/// key without `=` keeps a blank value.
#[tokio::test]
async fn credit_do_action_parses_like_python_parse_qsl() {
    let srv = spawn_http_server(move |_path, _body| {
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            b"RtnCode=1&RtnMsg=%zz+ok&Extra=a=b&Flag".to_vec(),
        )
    });
    let client = Ecpay {
        credit_api_url: srv,
        ..sdk()
    };
    let got = client
        .credit_do_action(&ecpay::payment::CreditDoActionParams {
            merchant_trade_no: "no1".into(),
            trade_no: "2308150001".into(),
            action: action::REFUND.into(),
            total_amount: 100,
            platform_id: None,
        })
        .await
        .expect("credit_do_action");
    assert_eq!(got.get("RtnMsg").map(String::as_str), Some("%zz ok"));
    assert_eq!(got.get("Extra").map(String::as_str), Some("a=b"));
    assert_eq!(got.get("Flag").map(String::as_str), Some(""));
}

/// A response MAC in lowercase hex still verifies (ECPay sends uppercase;
/// the case of a received value is not worth failing on).
#[tokio::test]
async fn order_search_accepts_a_lowercase_response_mac() {
    let srv = spawn_http_server(move |_path, _body| {
        let respond = map(&[("MerchantID", MERCHANT_ID), ("TradeStatus", "1")]);
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1)
            .unwrap()
            .to_lowercase();
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            format!("MerchantID={MERCHANT_ID}&TradeStatus=1&CheckMacValue={mac}").into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    let got = client
        .order_search(&ecpay::payment::OrderSearchParams {
            merchant_trade_no: "order_abc".into(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .expect("a lowercase MAC verifies");
    assert_eq!(got.get("TradeStatus").map(String::as_str), Some("1"));
}

/// `PlatformID` follows the filter stage: `Some("")` is dropped from the
/// signed request, `Some(id)` is sent.
#[tokio::test]
async fn platform_id_is_sent_only_when_non_empty() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured2 = captured.clone();
    let srv = spawn_http_server(move |_path, body| {
        captured2
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(body).into_owned());
        let respond = map(&[("MerchantID", MERCHANT_ID), ("TradeStatus", "1")]);
        let mac = ecpay::check_mac_value(&respond, HASH_KEY, HASH_IV, 1).unwrap();
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            format!("MerchantID={MERCHANT_ID}&TradeStatus=1&CheckMacValue={mac}").into_bytes(),
        )
    });
    let client = Ecpay {
        payment_api_url: srv,
        ..sdk()
    };
    for platform_id in [None, Some(String::new()), Some("3002599".to_owned())] {
        client
            .order_search(&ecpay::payment::OrderSearchParams {
                merchant_trade_no: "order_abc".into(),
                time_stamp: 1,
                platform_id,
            })
            .await
            .expect("order_search");
    }
    let bodies = captured.lock().unwrap().clone();
    assert_eq!(bodies.len(), 3);
    assert!(!bodies[0].contains("PlatformID"), "{}", bodies[0]);
    assert!(
        !bodies[1].contains("PlatformID"),
        "Some(\"\") is dropped: {}",
        bodies[1]
    );
    assert!(bodies[2].contains("PlatformID=3002599"), "{}", bodies[2]);
}

/// `generate_check_value` signs with the CLIENT's MerchantID regardless of
/// what the params carry (the official SDK's behavior), and honors the
/// params' EncryptType.
#[test]
fn generate_check_value_forces_the_merchant_id() {
    let client = sdk();
    let mut params = map(&[("MerchantTradeNo", "x"), ("MerchantID", "9999999")]);
    let got = client.generate_check_value(&params).unwrap();
    params.insert("MerchantID".into(), MERCHANT_ID.into());
    let want = ecpay::check_mac_value(&params, HASH_KEY, HASH_IV, 1).unwrap();
    assert_eq!(got, want, "signed as the configured merchant");
    assert_ne!(
        got,
        ecpay::check_mac_value(
            &map(&[("MerchantTradeNo", "x"), ("MerchantID", "9999999")]),
            HASH_KEY,
            HASH_IV,
            1
        )
        .unwrap(),
        "not as the caller's MerchantID"
    );

    let md5 = client
        .generate_check_value(&map(&[("MerchantTradeNo", "x"), ("EncryptType", "0")]))
        .unwrap();
    assert_eq!(md5.len(), 32, "EncryptType=0 selects MD5");
    let err = client
        .generate_check_value(&map(&[("EncryptType", "2")]))
        .expect_err("unknown EncryptType");
    assert!(
        matches!(err, ecpay::Error::UnsupportedEncryptType(2)),
        "{err:?}"
    );
}

/// The server-side APIs validate their params BEFORE any network I/O, with
/// the official SDK's messages. The client points at a closed port so a
/// validation miss surfaces as a connection error instead of a real request
/// (the control case at the end proves the port is closed).
#[tokio::test]
async fn server_side_apis_validate_before_sending() {
    use ecpay::payment::*;
    let unreachable = "http://127.0.0.1:1/".to_owned();
    let client = Ecpay {
        payment_api_url: unreachable.clone(),
        credit_api_url: unreachable.clone(),
        vendor_api_url: unreachable,
        ..sdk()
    };
    let validation = |err: ecpay::Error| match err {
        ecpay::Error::Validation(m) => m,
        other => panic!("expected a validation error before any I/O, got {other:?}"),
    };

    let search = |merchant_trade_no: &str, platform_id: Option<&str>| OrderSearchParams {
        merchant_trade_no: merchant_trade_no.into(),
        time_stamp: 1,
        platform_id: platform_id.map(str::to_owned),
    };
    let e = client.order_search(&search("", None)).await.unwrap_err();
    assert_eq!(validation(e), "MerchantTradeNo content is required.");
    let e = client
        .order_search(&search(&"x".repeat(21), None))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "MerchantTradeNo max langth is 20.");
    let e = client
        .order_search(&search("x", Some(&"p".repeat(11))))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "PlatformID max langth is 10.");
    let e = client
        .query_payment_info(&search("", None))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "MerchantTradeNo content is required.");

    let e = client
        .order_search_period(&OrderSearchPeriodParams {
            merchant_trade_no: String::new(),
            time_stamp: 1,
        })
        .await
        .unwrap_err();
    assert_eq!(validation(e), "MerchantTradeNo content is required.");

    let do_action = |trade_no: &str, act: &str| CreditDoActionParams {
        merchant_trade_no: "no1".into(),
        trade_no: trade_no.into(),
        action: act.into(),
        total_amount: 100,
        platform_id: None,
    };
    let e = client
        .credit_do_action(&do_action("", "C"))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "TradeNo content is required.");
    let e = client
        .credit_do_action(&do_action("t", "CC"))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "Action max langth is 1.");
    let e = client
        .credit_do_action(&do_action("t", ""))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "Action content is required.");

    let balance =
        |date_type: &str, media: &str, payment_type: Option<&str>| DownloadMerchantBalanceParams {
            date_type: date_type.into(),
            begin_date: "2024-01-01".into(),
            end_date: "2024-01-02".into(),
            media_formated: media.into(),
            payment_type: payment_type.map(str::to_owned),
            ..Default::default()
        };
    let e = client
        .download_merchant_balance(&balance("", "Y", None))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "DateType content is required.");
    let e = client
        .download_merchant_balance(&balance("1", "", None))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "MediaFormated content is required.");
    let e = client
        .download_merchant_balance(&balance("1", "Y", Some("ABC")))
        .await
        .unwrap_err();
    assert_eq!(validation(e), "PaymentType max langth is 2.");

    let e = client
        .download_disbursement_balance(&DownloadDisbursementBalanceParams {
            pay_date_type: String::new(),
            start_date: "2024-01-01".into(),
            end_date: "2024-01-02".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(validation(e), "PayDateType content is required.");
    let e = client
        .download_disbursement_balance(&DownloadDisbursementBalanceParams {
            pay_date_type: "1".into(),
            start_date: "2024-01-01".into(),
            end_date: "2024-01-020".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(validation(e), "EndDate max langth is 10.");

    let e = client
        .credit_card_period_action(&CreditCardPeriodActionParams {
            merchant_trade_no: "no1".into(),
            action: String::new(),
            time_stamp: 1,
            platform_id: None,
        })
        .await
        .unwrap_err();
    assert_eq!(validation(e), "Action content is required.");

    // Control: valid params reach the (closed) socket and fail as HTTP.
    let e = client.order_search(&search("x", None)).await.unwrap_err();
    assert!(
        matches!(e, ecpay::Error::Http(_)),
        "valid params must hit the network: {e:?}"
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
