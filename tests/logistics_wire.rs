//! Hermetic wire tests for the logistics families: the MD5-signed form calls,
//! the `1|`-prefixed response parsing, the AES-JSON v2 envelope, and the
//! callback helpers — all against a local forged server, no network.

use std::collections::HashMap;

use ecpay::crypto::check_mac_value;
use ecpay::logistics::{
    AllInOneCreateTestDataInput, AllInOneQueryInput, CancelC2cInput, CrossBorderMapInput,
    DomesticQueryInput, GetStoreListInput, LogisticsCreateInput, MapInput, PrintC2c,
    ReturnCvsInput,
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
        logistics_hash_key: LOGISTICS_KEY.as_bytes().to_vec(),
        logistics_hash_iv: LOGISTICS_IV.as_bytes().to_vec(),
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
    assert!(
        matches!(err, ecpay::Error::CheckMacValueMismatch),
        "{err:?}"
    );
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
