//! Hermetic wire tests for the logistics families: the MD5-signed form calls,
//! the `1|`-prefixed response parsing, the AES-JSON v2 envelope, and the
//! callback helpers — all against a local forged server, no network.

use std::collections::HashMap;

use ecpay::crypto::check_mac_value;
use ecpay::logistics::{
    AllInOneCancelC2cInput, AllInOneCreateTestDataInput, AllInOnePrintTradeDocumentInput,
    AllInOneQueryInput, AllInOneRedirectInput, AllInOneReturnCvsInput, AllInOneReturnHomeInput,
    AllInOneUpdateShipmentInfoInput, AllInOneUpdateStoreInfoInput, CancelC2cInput,
    CrossBorderCreateInput, CrossBorderCreateTestDataInput, CrossBorderMapInput,
    CrossBorderRefInput, DomesticQueryInput, GetStoreListInput, LogisticsCreateInput, MapInput,
    PrintC2c, ReturnCvsInput, ReturnHomeInput, UpdateShipmentInfoInput, UpdateStoreInfoInput,
    UpdateTempTradeInput,
};
use ecpay::Ecpay;

mod common;
use common::spawn_http_server;

const MERCHANT_ID: &str = "2000132";
const LOGISTICS_KEY: &str = "5294y06JbISpM5x9";
const LOGISTICS_IV: &str = "v77hoKGq4kWxNNIS";

fn logistics_sdk(api_url: String) -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        logistics_api_url: api_url,
        logistics_hash_key: LOGISTICS_KEY.to_owned(),
        logistics_hash_iv: LOGISTICS_IV.to_owned(),
        ..Default::default()
    }
}

fn sample_create() -> LogisticsCreateInput {
    LogisticsCreateInput {
        merchant_trade_no: "WIRE0000001".into(),
        merchant_trade_date: "2026/09/11 12:00:00".into(),
        logistics_type: "CVS".into(),
        logistics_sub_type: "FAMI".into(),
        goods_amount: 1000,
        goods_name: "綠界 SDK 範例商品".into(),
        sender_name: "陳大明".into(),
        sender_cell_phone: "0911222333".into(),
        receiver_name: "王小美".into(),
        receiver_cell_phone: "0933222111".into(),
        receiver_store_id: Some("006598".into()),
        server_reply_url: "https://www.ecpay.com.tw/example/server-reply".into(),
        ..Default::default()
    }
}

fn md5(fields: &HashMap<String, String>) -> String {
    check_mac_value(fields, LOGISTICS_KEY, LOGISTICS_IV, 0).expect("md5 cmv")
}

#[tokio::test]
async fn domestic_create_signs_md5_and_parses_the_pipe_response() {
    let server = spawn_http_server(|path, body| {
        assert!(path.ends_with("/Express/Create"), "{path}");
        let body = String::from_utf8_lossy(body).into_owned();
        let sent = parse_form(&body);
        // MD5 signature over the sent fields (minus CheckMacValue itself).
        let mut sans_mac = sent.clone();
        let mac = sans_mac.remove("CheckMacValue").expect("signed");
        assert_eq!(md5(&sent.clone()), mac, "request CheckMacValue must be MD5");
        assert_eq!(sent["MerchantID"], MERCHANT_ID);
        assert_eq!(sent["LogisticsSubType"], "FAMI");
        // Forge the live-observed response shape: `1|` + signed query.
        let mut reply = HashMap::new();
        reply.insert("AllPayLogisticsID".to_string(), "3657295".to_string());
        reply.insert("RtnCode".to_string(), "300".to_string());
        reply.insert("RtnMsg".to_string(), "訂單處理中".to_string());
        let reply_mac = md5(&reply);
        let query = format!(
            "AllPayLogisticsID=3657295&RtnCode=300&RtnMsg=%E8%A8%82%E5%96%AE%E8%99%95%E7%90%86%E4%B8%AD&CheckMacValue={reply_mac}"
        );
        (200, "text/plain".into(), format!("1|{query}").into_bytes())
    });
    let out = logistics_sdk(server)
        .logistics_create(&sample_create())
        .await
        .expect("create parses");
    assert_eq!(out["_status_prefix"], "1");
    assert_eq!(out["AllPayLogisticsID"], "3657295");
    assert_eq!(out["RtnCode"], "300");
    assert_eq!(out["RtnMsg"], "訂單處理中");
    assert!(
        !out.contains_key("CheckMacValue"),
        "verified MAC is stripped"
    );
}

#[tokio::test]
async fn domestic_query_v2_parses_a_bare_signed_query_without_prefix() {
    let server = spawn_http_server(|path, body| {
        assert!(
            path.ends_with("/Helper/QueryLogisticsTradeInfo/V2"),
            "{path}"
        );
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        assert_eq!(sent["AllPayLogisticsID"], "3657295");
        assert!(sent.contains_key("TimeStamp"), "TimeStamp rides along");
        let mut reply = HashMap::new();
        reply.insert("RtnCode".to_string(), "300".to_string());
        reply.insert("LogisticsStatus".to_string(), "203".to_string());
        let mac = md5(&reply);
        (
            200,
            "text/plain".into(),
            format!("RtnCode=300&LogisticsStatus=203&CheckMacValue={mac}").into_bytes(),
        )
    });
    let out = logistics_sdk(server)
        .logistics_query_logistics_trade_info(&DomesticQueryInput {
            all_pay_logistics_id: "3657295".into(),
            time_stamp: None,
        })
        .await
        .expect("query parses");
    assert_eq!(out["LogisticsStatus"], "203");
    assert!(!out.contains_key("_status_prefix"));
}

#[tokio::test]
async fn tampered_response_mac_is_rejected() {
    let server = spawn_http_server(|_path, _body| {
        (
            200,
            "text/plain".into(),
            b"1|RtnCode=300&CheckMacValue=DEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_vec(),
        )
    });
    let err = logistics_sdk(server)
        .logistics_create(&sample_create())
        .await
        .expect_err("tampered MAC must fail");
    assert!(
        matches!(err, ecpay::Error::CheckMacValueMismatch),
        "{err:?}"
    );
}

#[tokio::test]
async fn response_without_mac_is_rejected_not_swallowed() {
    let server = spawn_http_server(|_path, _body| {
        (
            200,
            "text/html".into(),
            b"<html>Server Error</html>".to_vec(),
        )
    });
    let err = logistics_sdk(server)
        .logistics_create(&sample_create())
        .await
        .expect_err("HTML error page must fail");
    // The raw body must be surfaced for diagnosis, not swallowed into a
    // generic MAC mismatch.
    match err {
        ecpay::Error::Message(m) => assert!(m.contains("Server Error"), "{m}"),
        other => panic!("expected Message with the raw body, got {other:?}"),
    }
}

/// A status-prefixed rejection (`0|<message>`) is the domestic form
/// protocol's own error shape, and stage sends it on HTTP 200 (`0|TimeStamp
/// Is Expired`) as well as on HTTP 500 (`0|找不到訂單`, `0|CheckMacValue
/// 驗證錯誤` — captured live 2026-09). It must surface as the same
/// `Error::Message` either way, carrying the message verbatim.
#[tokio::test]
async fn status_prefixed_rejections_share_one_shape_on_any_http_status() {
    for status in [200u16, 500] {
        let server = spawn_http_server(move |_path, _body| {
            (
                status,
                "text/html; charset=utf-8".into(),
                "0|找不到訂單".as_bytes().to_vec(),
            )
        });
        let err = logistics_sdk(server)
            .logistics_query_logistics_trade_info(&DomesticQueryInput {
                all_pay_logistics_id: "1".into(),
                time_stamp: None,
            })
            .await
            .expect_err("a 0| rejection must fail");
        match &err {
            ecpay::Error::Message(m) => {
                assert!(m.contains("找不到訂單"), "status {status}: {m}");
                assert!(
                    !m.contains("Some("),
                    "status {status}: the message must not leak Debug formatting: {m}"
                );
            }
            other => panic!("status {status}: expected Error::Message, got {other:?}"),
        }
    }
}

/// A real envelope whose TransCode is literally 0 (ECPay's 查無資料 shape)
/// IS an envelope — the gate keys on the presence of the `TransCode` key,
/// not its value — so it surfaces as `Error::TransCode{code:0}` on a 2xx
/// and on a non-2xx status alike. On non-2xx the HTTP status is not
/// surfaced separately: the TransMsg is the useful signal (before the
/// key-presence gate, a 500 carrying such a body came back as a bare
/// `InvoiceStatus`). This pins that choice.
#[tokio::test]
async fn transcode_zero_envelope_is_an_envelope_on_any_status() {
    for status in [200u16, 500] {
        let server = spawn_http_server(move |_path, _body| {
            (
                status,
                "application/json".into(),
                serde_json::json!({
                    "MerchantID": MERCHANT_ID,
                    "TransCode": 0,
                    "TransMsg": "查無資料",
                    "Data": "",
                })
                .to_string()
                .into_bytes(),
            )
        });
        let err = logistics_sdk(server)
            .allinone_query_logistics_trade_info(&AllInOneQueryInput {
                merchant_id: MERCHANT_ID.into(),
                logistics_id: "1".into(),
            })
            .await
            .expect_err("TransCode 0 is a gate failure");
        match err {
            ecpay::Error::TransCode { code, msg } => {
                assert_eq!(code, 0, "status {status}");
                assert_eq!(msg, "查無資料", "status {status}");
            }
            other => panic!("status {status}: expected Error::TransCode, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn http_500_with_a_valid_envelope_surfaces_the_business_error() {
    // Server-truth (captured live on stage, 2026-09): v2 business errors can
    // arrive as HTTP 500 with a VALID envelope whose Data decrypts to the
    // RtnCode/RtnMsg. The client must surface that, not a bare HTTP error.
    let server = spawn_http_server(|_path, _body| {
        let reply = serde_json::json!({"RtnCode": 10100048, "RtnMsg": "查無此訂單"});
        (
            500,
            "application/json".into(),
            serde_json::json!({
                "MerchantID": MERCHANT_ID,
                "RpHeader": {"Timestamp": 1},
                "TransCode": 1,
                "TransMsg": "Success",
                "Data": ecpay::crypto::encrypt_data(&reply, LOGISTICS_KEY.as_bytes(), LOGISTICS_IV.as_bytes()).unwrap(),
            })
            .to_string()
            .into_bytes(),
        )
    });
    let out = logistics_sdk(server)
        .allinone_query_logistics_trade_info(&AllInOneQueryInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1".into(),
        })
        .await
        .expect("a valid envelope on HTTP 500 must still decode");
    assert_eq!(out["RtnCode"], 10100048, "business error decoded: {out}");
}

#[tokio::test]
async fn gateway_json_without_transcode_is_not_mistaken_for_an_envelope() {
    // A proxy/gateway JSON body on a non-2xx carries no TransCode — the
    // client must keep the HTTP status and body instead of decoding it into
    // a meaningless TransCode{code:0}.
    let server = spawn_http_server(|_path, _body| {
        (
            502,
            "application/json".into(),
            br#"{"error": "bad gateway"}"#.to_vec(),
        )
    });
    let err = logistics_sdk(server)
        .allinone_query_logistics_trade_info(&AllInOneQueryInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1".into(),
        })
        .await
        .expect_err("gateway 502 must surface as InvoiceStatus");
    match err {
        ecpay::Error::InvoiceStatus { status, body } => {
            assert_eq!(status, 502);
            assert!(body.contains("bad gateway"), "{body}");
        }
        other => panic!("expected InvoiceStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn aes_json_2xx_non_envelope_is_reported_with_the_body() {
    // The same gateway-style bodies on a 2xx have no HTTP status worth
    // keeping: the AES-JSON path shares `decode_envelope` with the B2C API
    // and the callbacks, so they are reported as "not an envelope" with the
    // Debug-quoted body — not decoded into TransCode{code:0}.
    for body in [
        r#"{"error": "bad gateway"}"#,
        "<html>Service Unavailable</html>",
    ] {
        let server = spawn_http_server(move |_path, _body| {
            (200, "application/json".into(), body.as_bytes().to_vec())
        });
        let err = logistics_sdk(server)
            .allinone_query_logistics_trade_info(&AllInOneQueryInput {
                merchant_id: MERCHANT_ID.into(),
                logistics_id: "1".into(),
            })
            .await
            .expect_err("a 2xx non-envelope must not decode");
        match &err {
            ecpay::Error::Message(m) => {
                assert!(m.contains("not an AES-JSON envelope"), "{m}");
                assert!(
                    m.contains(&format!("{body:?}")),
                    "the body must be carried: {m}"
                );
            }
            other => panic!("body {body:?}: expected Error::Message, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn allinone_v2_envelope_carries_timestamp_and_revision_only() {
    let server = spawn_http_server(|path, body| {
        assert!(
            path.ends_with("/Express/v2/QueryLogisticsTradeInfo"),
            "{path}"
        );
        let env: serde_json::Value = serde_json::from_slice(body).unwrap();
        let mut keys: Vec<_> = env.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["Data", "MerchantID", "RqHeader"],
            "no PlatformID on the v2 envelope"
        );
        let rq = &env["RqHeader"];
        let mut rq_keys: Vec<_> = rq.as_object().unwrap().keys().cloned().collect();
        rq_keys.sort();
        assert_eq!(rq_keys, ["Revision", "Timestamp"]);
        assert_eq!(rq["Revision"], "1.0.0");
        let data: serde_json::Value = ecpay::crypto::decrypt_data(
            env["Data"].as_str().unwrap(),
            LOGISTICS_KEY.as_bytes(),
            LOGISTICS_IV.as_bytes(),
        )
        .unwrap();
        assert_eq!(data["MerchantID"], MERCHANT_ID);
        assert_eq!(data["LogisticsID"], "1769853");
        let reply = serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"});
        (
            200,
            "application/json".into(),
            serde_json::json!({
                "MerchantID": MERCHANT_ID,
                "RpHeader": {"Timestamp": 1}, // ECPay's own typo, verbatim
                "TransCode": 1,
                "TransMsg": "Success!",
                "Data": ecpay::crypto::encrypt_data(&reply, LOGISTICS_KEY.as_bytes(), LOGISTICS_IV.as_bytes()).unwrap(),
            })
            .to_string()
            .into_bytes(),
        )
    });
    let out = logistics_sdk(server)
        .allinone_query_logistics_trade_info(&AllInOneQueryInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
        })
        .await
        .expect("v2 query decodes");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn crossborder_map_form_is_the_one_unsigned_form() {
    let form = logistics_sdk("https://logistics-stage.ecpay.com.tw/".into())
        .crossborder_map_form(&CrossBorderMapInput {
            merchant_trade_no: "WIRE0000001".into(),
            logistics_type: "CB".into(),
            logistics_sub_type: "UNIMARTCBCVS".into(),
            destination: "SG".into(),
            server_reply_url: "https://example.com/reply".into(),
        })
        .unwrap();
    assert!(form.action().ends_with("/CrossBorder/Map"));
    assert!(
        !form.pairs().iter().any(|(k, _)| k == "CheckMacValue"),
        "CrossBorder/Map is posted without a CheckMacValue"
    );
}

#[tokio::test]
async fn domestic_forms_carry_the_md5_mac() {
    let sdk = logistics_sdk("https://logistics-stage.ecpay.com.tw/".into());
    let create_form = sdk
        .logistics_create_form(&LogisticsCreateInput {
            client_reply_url: Some("https://example.com/client".into()),
            ..sample_create()
        })
        .unwrap();
    assert!(create_form.action().ends_with("/Express/Create"));
    assert!(create_form
        .pairs()
        .iter()
        .any(|(k, _)| k == "CheckMacValue"));

    let map_form = sdk
        .logistics_map_form(&MapInput {
            merchant_trade_no: "WIRE0000001".into(),
            logistics_type: "CVS".into(),
            logistics_sub_type: "FAMI".into(),
            is_collection: "N".into(),
            server_reply_url: "https://example.com/reply".into(),
        })
        .unwrap();
    assert!(map_form.action().ends_with("/Express/map"));

    let test_data_form = sdk
        .logistics_create_test_data_form("FAMI", "https://example.com/client")
        .unwrap();
    assert!(test_data_form.action().ends_with("/Express/CreateTestData"));

    let print_form = sdk.logistics_print_trade_document_form("1717876").unwrap();
    assert!(print_form.action().ends_with("/helper/printTradeDocument"));

    let c2c_form = sdk
        .logistics_print_c2c_form(PrintC2c::UniMart, "1717812", "C9680734", Some("4551"))
        .unwrap();
    assert!(c2c_form
        .action()
        .ends_with("/Express/PrintUniMartC2COrderInfo"));
    let html = c2c_form.html_form();
    assert!(
        html.contains("action=") && html.contains("submit()"),
        "{html}"
    );
}

#[tokio::test]
async fn get_store_list_posts_md5_and_parses_json() {
    let server = spawn_http_server(|path, body| {
        assert!(path.ends_with("/Helper/GetStoreList"), "{path}");
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        assert_eq!(sent["CvsType"], "FAMI");
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        (
            200,
            "application/json".into(),
            br#"{"RtnCode": 1, "Stores": [{"StoreID": "006598"}]}"#.to_vec(),
        )
    });
    let out = logistics_sdk(server)
        .logistics_get_store_list(&GetStoreListInput {
            cvs_type: "FAMI".into(),
        })
        .await
        .expect("store list");
    assert_eq!(out["Stores"][0]["StoreID"], "006598");
}

#[tokio::test]
async fn c2c_form_api_posts_the_c2c_field_set() {
    let server = spawn_http_server(|path, body| {
        assert!(path.ends_with("/Express/CancelC2COrder"), "{path}");
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        assert_eq!(sent["CVSPaymentNo"], "C9681067");
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        let mut reply = HashMap::new();
        reply.insert("RtnCode".to_string(), "1".to_string());
        reply.insert("RtnMsg".to_string(), "OK".to_string());
        let mac = md5(&reply);
        (
            200,
            "text/plain".into(),
            format!("1|RtnCode=1&RtnMsg=OK&CheckMacValue={mac}").into_bytes(),
        )
    });
    let out = logistics_sdk(server)
        .logistics_cancel_c2c_order(&CancelC2cInput {
            all_pay_logistics_id: "1718552".into(),
            cvs_payment_no: "C9681067".into(),
            cvs_validation_no: "2448".into(),
        })
        .await
        .expect("cancel c2c");
    assert_eq!(out["RtnCode"], "1");
}

#[tokio::test]
async fn return_cvs_sends_the_service_type_field() {
    let server = spawn_http_server(|path, body| {
        assert!(
            path.ends_with("/express/ReturnCVS"),
            "path must keep the official lowercase `express`: {path}"
        );
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        assert_eq!(sent["ServiceType"], "4");
        assert_eq!(sent["GoodsAmount"], "1000");
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        let mut reply = HashMap::new();
        reply.insert("RtnCode".to_string(), "300".to_string());
        reply.insert("AllPayLogisticsID".to_string(), "1718600".to_string());
        let mac = md5(&reply);
        (
            200,
            "text/plain".into(),
            format!("1|RtnCode=300&AllPayLogisticsID=1718600&CheckMacValue={mac}").into_bytes(),
        )
    });
    let out = logistics_sdk(server)
        .logistics_return_cvs(&ReturnCvsInput {
            goods_amount: 1000,
            service_type: "4".into(),
            sender_name: "陳大明".into(),
            sender_cell_phone: None,
            server_reply_url: "https://example.com/reply".into(),
        })
        .await
        .expect("return cvs");
    assert_eq!(out["AllPayLogisticsID"], "1718600");
}

#[tokio::test]
async fn logistics_callback_helpers_roundtrip() {
    let sdk = logistics_sdk("https://logistics-stage.ecpay.com.tw/".into());

    // v2 狀態通知 callback: forge what ECPay posts, decrypt, then build the reply.
    let notify = serde_json::json!({
        "MerchantID": MERCHANT_ID,
        "RqHeader": {"Timestamp": 1},
        "TransCode": 1,
        "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({"LogisticsID": "1769853", "LogisticsStatus": "203"}),
            LOGISTICS_KEY.as_bytes(),
            LOGISTICS_IV.as_bytes(),
        )
        .unwrap(),
    });
    let decoded: serde_json::Value = sdk
        .decrypt_logistics_callback(&notify.to_string())
        .expect("notify decrypts");
    assert_eq!(decoded["LogisticsStatus"], "203");

    let reply = sdk.logistics_notify_reply().expect("reply builds");
    let reply_env: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply_env["TransCode"], "1");
    let reply_data: serde_json::Value = ecpay::crypto::decrypt_data(
        reply_env["Data"].as_str().unwrap(),
        LOGISTICS_KEY.as_bytes(),
        LOGISTICS_IV.as_bytes(),
    )
    .unwrap();
    assert_eq!(reply_data["RtnCode"], "1");

    // TempTradeEstablished: form POST's ResultData field is the AES envelope,
    // urlencoded like any form value (+ for spaces is not enough — %XX for
    // everything the encoder escapes).
    let established = serde_json::json!({
        "MerchantID": MERCHANT_ID,
        "RqHeader": {"Timestamp": 1},
        "TransCode": 1,
        "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({"TempLogisticsID": "2264"}),
            LOGISTICS_KEY.as_bytes(),
            LOGISTICS_IV.as_bytes(),
        )
        .unwrap(),
    });
    let decoded: serde_json::Value = sdk
        .decrypt_temp_trade_established(&urlencode(&established.to_string()))
        .expect("established decrypts");
    assert_eq!(decoded["TempLogisticsID"], "2264");
}

fn urlencode(s: &str) -> String {
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

#[test]
fn verify_logistics_check_mac_value_is_md5_keyed() {
    let sdk = logistics_sdk("https://logistics-stage.ecpay.com.tw/".into());
    let mut params: HashMap<String, String> = [
        ("MerchantID", MERCHANT_ID),
        ("AllPayLogisticsID", "1718552"),
        ("RtnCode", "300"),
        ("RtnMsg", "訂單處理中"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    let mac = check_mac_value(&params, LOGISTICS_KEY, LOGISTICS_IV, 0).unwrap();
    params.insert("CheckMacValue".to_owned(), mac);
    assert!(sdk.verify_logistics_check_mac_value(&params));
    // A SHA-256 signature (the payment default) must NOT verify.
    let sha = ecpay::crypto::hash_mac(
        &params
            .iter()
            .filter(|(k, _)| *k != "CheckMacValue")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        LOGISTICS_KEY,
        LOGISTICS_IV,
    );
    let mut params = params.clone();
    params.insert("CheckMacValue".to_owned(), sha);
    assert!(!sdk.verify_logistics_check_mac_value(&params));
    // A LogisticsCreateInput serde-renames sanity: CreateTestData input Data
    // keys are ECPay verbatim.
    let input = AllInOneCreateTestDataInput {
        merchant_id: MERCHANT_ID.into(),
        logistics_sub_type: "FAMI".into(),
    };
    let json = serde_json::to_value(&input).unwrap();
    assert!(json.get("MerchantID").is_some() && json.get("LogisticsSubType").is_some());
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in body.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(urldecode(k), urldecode(v));
        }
    }
    out
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = (b[i + 1] as char)
                    .to_digit(16)
                    .and_then(|h| (b[i + 2] as char).to_digit(16).map(|l| h * 16 + l));
                match hex {
                    Some(v) => {
                        out.push(v as u8);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- Untested-endpoint sweep, part 1: domestic MD5-form family. Each test
// pins the exact posted key set (a serde rename typo or a stray field breaks
// the set), the MD5 signature, and the `1|`-prefixed response parsing. ---

fn pipe_reply(fields: &[(&str, &str)]) -> (u16, String, Vec<u8>) {
    let map: HashMap<String, String> = fields
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mac = md5(&map);
    let query: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .chain(std::iter::once(format!("CheckMacValue={mac}")))
        .collect();
    (
        200,
        "text/plain".into(),
        format!("1|{}", query.join("&")).into_bytes(),
    )
}

#[tokio::test]
async fn update_shipment_info_posts_the_exact_field_set() {
    let server = spawn_http_server(|path, body| {
        assert!(path.ends_with("/Helper/UpdateShipmentInfo"), "{path}");
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        let mut keys: Vec<_> = sent.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys.remove(keys.iter().position(|k| k == "CheckMacValue").unwrap()),
            "CheckMacValue"
        );
        assert_eq!(
            keys,
            [
                "AllPayLogisticsID",
                "MerchantID",
                "ReceiverStoreID",
                "ShipmentDate"
            ],
            "exact field set"
        );
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        pipe_reply(&[("RtnCode", "1"), ("RtnMsg", "OK")])
    });
    let out = logistics_sdk(server)
        .logistics_update_shipment_info(&UpdateShipmentInfoInput {
            all_pay_logistics_id: "1718552".into(),
            shipment_date: "2026/09/12".into(),
            receiver_store_id: Some("991182".into()),
        })
        .await
        .expect("update shipment info");
    assert_eq!(out["RtnCode"], "1");
}

#[tokio::test]
async fn update_store_info_posts_the_c2c_field_set() {
    let server = spawn_http_server(|path, body| {
        assert!(path.ends_with("/Express/UpdateStoreInfo"), "{path}");
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        let mut keys: Vec<_> = sent.keys().cloned().collect();
        keys.sort();
        let mac = keys.remove(keys.iter().position(|k| k == "CheckMacValue").unwrap());
        assert_eq!(mac, "CheckMacValue");
        assert_eq!(
            keys,
            [
                "AllPayLogisticsID",
                "CVSPaymentNo",
                "CVSValidationNo",
                "MerchantID",
                "ReceiverStoreID",
                "StoreType",
            ],
            "exact C2C field set"
        );
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        pipe_reply(&[("RtnCode", "1"), ("RtnMsg", "OK")])
    });
    let out = logistics_sdk(server)
        .logistics_update_store_info(&UpdateStoreInfoInput {
            all_pay_logistics_id: "1718552".into(),
            cvs_payment_no: "C9681067".into(),
            cvs_validation_no: "2448".into(),
            store_type: "01".into(),
            receiver_store_id: "006598".into(),
        })
        .await
        .expect("update store info");
    assert_eq!(out["RtnCode"], "1");
}

#[tokio::test]
async fn return_unimart_cvs_keeps_the_official_lowercase_path() {
    let server = spawn_http_server(|path, body| {
        assert!(
            path.ends_with("/express/ReturnUniMartCVS"),
            "official lowercase `express`: {path}"
        );
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        let mut keys: Vec<_> = sent.keys().cloned().collect();
        keys.sort();
        keys.retain(|k| k != "CheckMacValue");
        assert_eq!(
            keys,
            [
                "GoodsAmount",
                "MerchantID",
                "SenderName",
                "ServerReplyURL",
                "ServiceType"
            ],
            "SenderCellPhone absent when None"
        );
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        pipe_reply(&[("RtnCode", "300"), ("AllPayLogisticsID", "1718601")])
    });
    let out = logistics_sdk(server)
        .logistics_return_unimart_cvs(&ReturnCvsInput {
            goods_amount: 550,
            service_type: "4".into(),
            sender_name: "陳大明".into(),
            sender_cell_phone: None,
            server_reply_url: "https://example.com/reply".into(),
        })
        .await
        .expect("return unimart cvs");
    assert_eq!(out["AllPayLogisticsID"], "1718601");
}

#[tokio::test]
async fn return_home_posts_the_home_return_field_set() {
    let server = spawn_http_server(|path, body| {
        assert!(path.ends_with("/Express/ReturnHome"), "{path}");
        let sent = parse_form(String::from_utf8_lossy(body).as_ref());
        let mut keys: Vec<_> = sent.keys().cloned().collect();
        keys.sort();
        keys.retain(|k| k != "CheckMacValue");
        assert_eq!(
            keys,
            [
                "AllPayLogisticsID",
                "Distance",
                "GoodsAmount",
                "MerchantID",
                "ServerReplyURL",
                "Temperature",
            ],
            "Specification absent when None"
        );
        assert_eq!(md5(&sent), sent["CheckMacValue"]);
        pipe_reply(&[("RtnCode", "300"), ("AllPayLogisticsID", "1718602")])
    });
    let out = logistics_sdk(server)
        .logistics_return_home(&ReturnHomeInput {
            all_pay_logistics_id: "1718552".into(),
            goods_amount: 1200,
            temperature: "0001".into(),
            distance: "00".into(),
            specification: None,
            server_reply_url: "https://example.com/reply".into(),
        })
        .await
        .expect("return home");
    assert_eq!(out["AllPayLogisticsID"], "1718602");
}

// --- Part 2: the AllInOne v2 AES-JSON family. Every request must ride the
// {MerchantID, RqHeader{Timestamp, Revision}, Data} envelope, carry
// MerchantID inside Data too, and hit the exact Express/v2/... action path.
// Key-set pins catch serde-rename drift on the ten endpoints that never had
// any coverage. ---

fn assert_v2_envelope_and_decrypt(
    path: &str,
    body: &[u8],
    expected_suffix: &str,
) -> serde_json::Value {
    assert!(
        path.ends_with(expected_suffix),
        "{path} must end with {expected_suffix}"
    );
    let env: serde_json::Value = serde_json::from_slice(body).expect("v2 envelope is JSON");
    assert_eq!(env["MerchantID"], MERCHANT_ID, "envelope MerchantID");
    let rq = env["RqHeader"].as_object().expect("RqHeader object");
    let mut rq_keys: Vec<_> = rq.keys().map(|k| k.as_str()).collect();
    rq_keys.sort();
    assert_eq!(rq_keys, ["Revision", "Timestamp"], "v2 RqHeader keys");
    assert_eq!(env["RqHeader"]["Revision"], "1.0.0");
    ecpay::crypto::decrypt_data(
        env["Data"].as_str().expect("Data is a string"),
        LOGISTICS_KEY.as_bytes(),
        LOGISTICS_IV.as_bytes(),
    )
    .expect("Data decrypts with the logistics keys")
}

fn v2_ok_reply(data: &serde_json::Value) -> (u16, String, Vec<u8>) {
    (
        200,
        "application/json".into(),
        serde_json::json!({
            "MerchantID": MERCHANT_ID,
            "RpHeader": {"Timestamp": 1},
            "TransCode": 1,
            "TransMsg": "Success",
            "Data": ecpay::crypto::encrypt_data(data, LOGISTICS_KEY.as_bytes(), LOGISTICS_IV.as_bytes()).unwrap(),
        })
        .to_string()
        .into_bytes(),
    )
}

fn assert_data_key_set(data: &serde_json::Value, want: &[&str]) {
    let mut got: Vec<String> = data
        .as_object()
        .expect("Data is an object")
        .keys()
        .cloned()
        .collect();
    got.sort();
    assert_eq!(got, want, "exact Data key set");
    assert_eq!(data["MerchantID"], MERCHANT_ID, "Data MerchantID rides too");
}

/// Same pin for the two inputs that intentionally carry NO Data-level
/// MerchantID (UpdateTempTrade, CrossBorder Create) — the envelope alone
/// identifies the merchant.
fn assert_data_key_set_without_merchant_id(data: &serde_json::Value, want: &[&str]) {
    let mut got: Vec<String> = data
        .as_object()
        .expect("Data is an object")
        .keys()
        .cloned()
        .collect();
    got.sort();
    assert_eq!(got, want, "exact Data key set");
    assert!(
        !data.as_object().unwrap().contains_key("MerchantID"),
        "no Data-level MerchantID on this endpoint"
    );
}

#[tokio::test]
async fn allinone_cancel_c2c_order_rides_the_v2_envelope() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/Express/v2/CancelC2COrder");
        assert_data_key_set(
            &data,
            &[
                "CVSPaymentNo",
                "CVSValidationNo",
                "LogisticsID",
                "MerchantID",
            ],
        );
        assert_eq!(data["CVSPaymentNo"], "C9681067");
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .allinone_cancel_c2c_order(&AllInOneCancelC2cInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
            cvs_payment_no: "C9681067".into(),
            cvs_validation_no: "2448".into(),
        })
        .await
        .expect("allinone cancel c2c");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn allinone_return_cvs_family_hits_each_sub_type_path() {
    // One shared input, three sub-type paths: CVS / HILIFE / UNIMART. The
    // per-path split lives in the ACTION, not in extra fields — pin all
    // three.
    for expected in [
        "/Express/v2/ReturnCVS",
        "/Express/v2/ReturnHilifeCVS",
        "/Express/v2/ReturnUniMartCVS",
    ] {
        let expected = expected.to_owned();
        let want = expected.clone();
        let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hit2 = hit.clone();
        let server = spawn_http_server(move |path, body| {
            let data = assert_v2_envelope_and_decrypt(path, body, &want);
            assert_data_key_set(
                &data,
                &[
                    "GoodsAmount",
                    "LogisticsID",
                    "MerchantID",
                    "SenderName",
                    "SenderPhone",
                    "ServerReplyURL",
                    "ServiceType",
                ],
            );
            assert_eq!(data["ServiceType"], "4");
            hit2.store(true, std::sync::atomic::Ordering::SeqCst);
            v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
        });
        let input = AllInOneReturnCvsInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
            goods_amount: 550,
            service_type: "4".into(),
            sender_name: "陳大明".into(),
            sender_phone: Some("0911222333".into()),
            server_reply_url: "https://example.com/reply".into(),
        };
        let sdk = logistics_sdk(server);
        let out = match expected.as_str() {
            "/Express/v2/ReturnCVS" => sdk.allinone_return_cvs(&input).await,
            "/Express/v2/ReturnHilifeCVS" => sdk.allinone_return_hilife_cvs(&input).await,
            _ => sdk.allinone_return_unimart_cvs(&input).await,
        }
        .unwrap_or_else(|e| panic!("{expected} failed: {e:?}"));
        assert_eq!(out["RtnCode"], 1);
        assert!(hit.load(std::sync::atomic::Ordering::SeqCst));
    }
}

#[tokio::test]
async fn allinone_return_home_omits_unset_specification() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/Express/v2/ReturnHome");
        assert_data_key_set(
            &data,
            &[
                "Distance",
                "GoodsAmount",
                "LogisticsID",
                "MerchantID",
                "ServerReplyURL",
                "Temperature",
            ],
        );
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .allinone_return_home(&AllInOneReturnHomeInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
            goods_amount: 1200,
            temperature: "0001".into(),
            distance: "00".into(),
            specification: None,
            server_reply_url: "https://example.com/reply".into(),
        })
        .await
        .expect("allinone return home");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn allinone_update_temp_trade_posts_the_temp_field_set() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/Express/v2/UpdateTempTrade");
        // Unlike the other AllInOne inputs, UpdateTempTradeInput carries NO
        // Data-level MerchantID (only the envelope does) — pinned as-is.
        assert_data_key_set_without_merchant_id(
            &data,
            &[
                "Distance",
                "GoodsAmount",
                "ReceiverCellPhone",
                "ReceiverName",
                "SenderCellPhone",
                "SenderName",
                "Specification",
                "TempLogisticsID",
                "Temperature",
            ],
        );
        assert_eq!(data["TempLogisticsID"], "2264");
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .allinone_update_temp_trade(&UpdateTempTradeInput {
            temp_logistics_id: "2264".into(),
            sender_name: Some("陳大明".into()),
            sender_cell_phone: Some("0911222333".into()),
            receiver_name: Some("王小美".into()),
            receiver_cell_phone: Some("0933222111".into()),
            goods_amount: Some(1000),
            temperature: Some("0001".into()),
            distance: Some("00".into()),
            specification: Some("A".into()),
            ..Default::default()
        })
        .await
        .expect("allinone update temp trade");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn allinone_update_shipment_info_rides_the_v2_envelope() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/Express/v2/UpdateShipmentInfo");
        assert_data_key_set(&data, &["LogisticsID", "MerchantID", "ShipmentDate"]);
        assert_eq!(data["ShipmentDate"], "2026/09/12");
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .allinone_update_shipment_info(&AllInOneUpdateShipmentInfoInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
            shipment_date: "2026/09/12".into(),
        })
        .await
        .expect("allinone update shipment info");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn allinone_update_store_info_rides_the_v2_envelope() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/Express/v2/UpdateStoreInfo");
        assert_data_key_set(
            &data,
            &[
                "CVSPaymentNo",
                "CVSValidationNo",
                "LogisticsID",
                "MerchantID",
                "ReceiverStoreID",
                "StoreType",
            ],
        );
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .allinone_update_store_info(&AllInOneUpdateStoreInfoInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
            cvs_payment_no: "C9681067".into(),
            cvs_validation_no: "2448".into(),
            store_type: "01".into(),
            receiver_store_id: "006598".into(),
        })
        .await
        .expect("allinone update store info");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn allinone_create_test_data_rides_the_v2_envelope() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/Express/v2/CreateTestData");
        assert_data_key_set(&data, &["LogisticsSubType", "MerchantID"]);
        assert_eq!(data["LogisticsSubType"], "FAMI");
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .allinone_create_test_data(&AllInOneCreateTestDataInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_sub_type: "FAMI".into(),
        })
        .await
        .expect("allinone create test data");
    assert_eq!(out["RtnCode"], 1);
}

/// The two raw-response v2 endpoints (stage-truth: they answer text/html
/// auto-submit forms, NOT an AES envelope) must surface the body verbatim —
/// while the REQUEST is still a proper AES envelope with the right Data.
#[tokio::test]
async fn raw_html_v2_endpoints_surface_the_html_verbatim() {
    for expected in [
        "/Express/v2/PrintTradeDocument",
        "/Express/v2/RedirectToLogisticsSelection",
    ] {
        let expected = expected.to_owned();
        let want = expected.clone();
        let is_print = expected == "/Express/v2/PrintTradeDocument";
        let server = spawn_http_server(move |path, body| {
            let data = assert_v2_envelope_and_decrypt(path, body, &want);
            if is_print {
                assert_data_key_set(&data, &["LogisticsID", "LogisticsSubType", "MerchantID"]);
                assert_eq!(
                    data["LogisticsID"],
                    serde_json::json!(["1717876", "1717877"]),
                    "LogisticsID rides as a JSON array"
                );
            } else {
                // Official PHP example: NO Data-level MerchantID on this
                // endpoint (it rides the envelope only).
                assert_data_key_set_without_merchant_id(
                    &data,
                    &[
                        "ClientReplyURL",
                        "GoodsAmount",
                        "GoodsName",
                        "SenderAddress",
                        "SenderName",
                        "SenderZipCode",
                        "ServerReplyURL",
                        "TempLogisticsID",
                        "Temperature",
                    ],
                );
                assert_eq!(data["TempLogisticsID"], "2264");
            }
            (
                200,
                "text/html".into(),
                b"<html><body>print page</body></html>".to_vec(),
            )
        });
        let sdk = logistics_sdk(server);
        let out = if is_print {
            sdk.allinone_print_trade_document(&AllInOnePrintTradeDocumentInput {
                merchant_id: MERCHANT_ID.into(),
                logistics_ids: vec!["1717876".into(), "1717877".into()],
                logistics_sub_type: "FAMI".into(),
            })
            .await
        } else {
            sdk.allinone_redirect_to_logistics_selection(&AllInOneRedirectInput {
                temp_logistics_id: "2264".into(),
                goods_amount: 100,
                goods_name: "範例商品".into(),
                sender_name: "陳大明".into(),
                sender_zip_code: "11560".into(),
                sender_address: "台北市南港區三重路19-2號6樓".into(),
                temperature: Some("0001".into()),
                server_reply_url: "https://example.com/reply".into(),
                client_reply_url: "https://example.com/client".into(),
            })
            .await
        }
        .unwrap_or_else(|e| panic!("{expected} failed: {e:?}"));
        assert_eq!(
            out, "<html><body>print page</body></html>",
            "raw HTML verbatim"
        );
    }
}

// --- Part 3: CrossBorder — never covered at all (the stage account lacks
// the service, TransCode 128), so hermetic pins are the only coverage these
// three get. ---

#[tokio::test]
async fn crossborder_create_posts_the_full_field_set_with_finite_f64_weight() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/CrossBorder/Create");
        // Official PHP example (CreateUnimartCvsOrder.php): MerchantID rides
        // as the FIRST field of Data, not only the envelope.
        assert_data_key_set(
            &data,
            &[
                "GoodsAmount",
                "GoodsEnglishName",
                "GoodsWeight",
                "LogisticsSubType",
                "LogisticsType",
                "MerchantID",
                "MerchantTradeDate",
                "MerchantTradeNo",
                "ReceiverCellPhone",
                "ReceiverCountry",
                "ReceiverEmail",
                "ReceiverName",
                "ReceiverStoreID",
                "SenderAddress",
                "SenderCellPhone",
                "SenderEmail",
                "SenderName",
                "ServerReplyURL",
            ],
        );
        assert_eq!(data["GoodsWeight"], 1.5, "finite_f64 shortest round-trip");
        assert_eq!(data["ReceiverCountry"], "SG");
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .crossborder_create(&CrossBorderCreateInput {
            merchant_id: MERCHANT_ID.into(),
            merchant_trade_date: "2026/09/12 12:00:00".into(),
            merchant_trade_no: "CBWIRE000001".into(),
            logistics_type: "CB".into(),
            logistics_sub_type: "UNIMARTCBCVS".into(),
            goods_amount: 2000,
            goods_weight: 1.5,
            goods_english_name: "Test Goods".into(),
            receiver_country: "SG".into(),
            receiver_name: "Tan Mei Mei".into(),
            receiver_cell_phone: "+6591234567".into(),
            receiver_store_id: Some("711_1".into()),
            receiver_email: "receiver@email.com".into(),
            sender_name: "Chen Ta Ming".into(),
            sender_cell_phone: "+886911222333".into(),
            sender_address: "Taipei".into(),
            sender_email: "sender@email.com".into(),
            server_reply_url: "https://example.com/reply".into(),
            ..Default::default()
        })
        .await
        .expect("crossborder create");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn crossborder_create_test_data_rides_the_v2_envelope() {
    let server = spawn_http_server(|path, body| {
        let data = assert_v2_envelope_and_decrypt(path, body, "/CrossBorder/CreateTestData");
        assert_data_key_set(
            &data,
            &["Country", "LogisticsSubType", "LogisticsType", "MerchantID"],
        );
        assert_eq!(data["Country"], "SG");
        v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
    });
    let out = logistics_sdk(server)
        .crossborder_create_test_data(&CrossBorderCreateTestDataInput {
            merchant_id: MERCHANT_ID.into(),
            country: "SG".into(),
            logistics_type: "CB".into(),
            logistics_sub_type: "UNIMARTCBCVS".into(),
        })
        .await
        .expect("crossborder create test data");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn crossborder_query_and_print_share_the_ref_input_shape() {
    for expected in ["/CrossBorder/QueryLogisticsTradeInfo", "/CrossBorder/Print"] {
        let expected = expected.to_owned();
        let want = expected.clone();
        let server = spawn_http_server(move |path, body| {
            let data = assert_v2_envelope_and_decrypt(path, body, &want);
            assert_data_key_set(&data, &["LogisticsID", "MerchantID"]);
            assert_eq!(data["LogisticsID"], "1769853");
            v2_ok_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "OK"}))
        });
        let sdk = logistics_sdk(server);
        let input = CrossBorderRefInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1769853".into(),
        };
        let out = if expected == "/CrossBorder/QueryLogisticsTradeInfo" {
            sdk.crossborder_query_logistics_trade_info(&input).await
        } else {
            sdk.crossborder_print(&input).await
        }
        .unwrap_or_else(|e| panic!("{expected} failed: {e:?}"));
        assert_eq!(out["RtnCode"], 1);
    }
}
