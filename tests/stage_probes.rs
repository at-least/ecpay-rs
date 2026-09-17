//! Staging probes for the three services the official PHP SDK (`ECPay/SDK_PHP`)
//! covers — first captured here before this crate implemented them (all three
//! are typed modules now):
//!
//! 1. ECPG 站內付 2.0 (AES-JSON, `ecpg-stage` + `ecpayment-stage` domains)
//! 2. 國內物流 Domestic logistics (form POST + CheckMacValue **MD5**,
//!    `logistics-stage/Express/Create`)
//! 3. B2B 電子發票 (AES-JSON, `RqHeader` 帶 `RqID` + `Revision`)
//!
//! The early probes build their requests with this crate's own public crypto
//! helpers (`encrypt_data` / `check_mac_value`) against the official public
//! stage test accounts and print the RAW server answer; what each one asserts
//! is stated in its own doc — from transport/protocol facts only (HTTP 200,
//! TransCode gating) up to business codes. The later ECPG probes go through
//! the typed `Ecpay` methods or raw envelopes and pin the answers the crate's
//! guards and docs quote, including shapes the typed methods can no longer
//! send. The point throughout is what the stage server actually accepts from
//! our wire format, independent of any language-SDK quirk.
//!
//! Run (serial — the logistics/B2B probes create REAL stage-side records:
//! logistics orders and B2B invoices that consume 字軌 numbers, never
//! cancelled — stage test data is shared and disposable):
//!
//! ```bash
//! cargo test --test stage_probes -- --ignored --test-threads=1 --nocapture
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ecpay::Ecpay;
use serde_json::{json, Value};
mod common;
use common::sandbox::{taipei_now, unique_no_millis as unique_no, urlencode};

// Official public stage test accounts (developers.ecpay.com.tw / SDK_PHP examples).
const ECPG_MERCHANT: &str = "3002607";
const ECPG_KEY: &str = "pwFHCqoQZGmho4w6";
const ECPG_IV: &str = "EkRm7iFT261dpevs";

const LOGISTICS_MERCHANT: &str = "2000132";
const LOGISTICS_KEY: &str = "5294y06JbISpM5x9";
const LOGISTICS_IV: &str = "v77hoKGq4kWxNNIS";

const B2B_MERCHANT: &str = "2000132";
const B2B_KEY: &str = "ejCk326UnaZWKisg";
const B2B_IV: &str = "q9jcZX8Ib9LM8wYk";

/// Posts the AES-JSON envelope `{MerchantID, RqHeader, Data}` where Data is
/// `encrypt_data(payload)` — the wire format every `PostWithAesJsonResponseService`
/// example in the PHP SDK produces. `rq_header` is hand-rolled per service:
/// ECPG sends `{Timestamp}` only, B2B adds `RqID` + `Revision`.
async fn aes_post(
    endpoint: &str,
    merchant_id: &str,
    rq_header: Value,
    payload: Value,
    key: &str,
    iv: &str,
) -> (u16, String) {
    let data = ecpay::crypto::encrypt_data(&payload, key.as_bytes(), iv.as_bytes())
        .expect("encrypt Data payload");
    let envelope = json!({
        "MerchantID": merchant_id,
        "RqHeader": rq_header,
        "Data": data,
    });
    let resp = reqwest::Client::new()
        .post(endpoint)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(envelope.to_string())
        .send()
        .await
        .expect("POST to stage");
    let status = resp.status().as_u16();
    let body = resp.text().await.expect("stage body");
    (status, body)
}

/// Decrypts the `Data` field of an AES-JSON response envelope, printing the
/// TransCode gate and the decrypted payload. Returns the decrypted Value if
/// the TransCode gate passed.
fn unwrap_aes_response(body: &str, key: &str, iv: &str) -> Option<Value> {
    let res: Value = serde_json::from_str(body).expect("response is JSON");
    let trans_code = res["TransCode"].as_i64().unwrap_or(-1);
    println!("  TransCode={} TransMsg={:?}", trans_code, res["TransMsg"]);
    if trans_code != 1 {
        return None;
    }
    let data = res["Data"].as_str().unwrap_or_default();
    match ecpay::crypto::decrypt_data::<Value>(data, key.as_bytes(), iv.as_bytes()) {
        Ok(v) => Some(v),
        Err(e) => {
            println!("  Data DECRYPT FAILED: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn ecpg_get_token_by_trade_accepts_our_aes_envelope() {
    let trade_no = unique_no("PROBE");
    // Field set mirrors example/Payment/Ecpg/CreateAllOrder/GetToken.php.
    // ConsumerInfo is required with RememberCard=1 — stage names it (5100010
    // "The parameter [ConsumerInfo] cannot be empty"; tests/sandbox_ecpg.rs).
    let payload = json!({
        "MerchantID": ECPG_MERCHANT,
        "RememberCard": 1,
        "PaymentUIType": 2,
        "ChoosePaymentList": "0",
        "OrderInfo": {
            "MerchantTradeDate": taipei_now(),
            "MerchantTradeNo": trade_no,
            "TotalAmount": "100",
            "ReturnURL": "https://www.ecpay.com.tw/example/receive",
            "TradeDesc": "ecpay-rs probe",
            "ItemName": "Probe",
        },
        "CardInfo": {
            "Redeem": 0,
            "OrderResultURL": "https://www.ecpay.com.tw/example/receive",
            "CreditInstallment": "3,6,12",
            "FlexibleInstallment": 30,
        },
        "ATMInfo": { "ExpireDate": 3 },
        "CVSInfo": { "StoreExpireDate": 10080 },
        "BarcodeInfo": { "StoreExpireDate": 7 },
        "ConsumerInfo": {
            "MerchantMemberID": "probe000001",
            "Email": "customer@email.com",
            "Phone": "0912345678",
            "Name": "Probe",
            "CountryCode": "158",
        },
    });
    // ECPG's RqHeader carries ONLY Timestamp (unlike B2C invoice's Revision 3.0.0).
    let (status, body) = aes_post(
        "https://ecpg-stage.ecpay.com.tw/Merchant/GetTokenbyTrade",
        ECPG_MERCHANT,
        json!({ "Timestamp": unix_now() }),
        payload,
        ECPG_KEY,
        ECPG_IV,
    )
    .await;
    println!("GetTokenbyTrade status={status} body={body}");
    assert_eq!(status, 200, "stage must answer HTTP 200");
    // Protocol acceptance is the assertion; a TransCode≠1 means our envelope
    // does NOT speak ECPG and the probe (and later implementation) must change.
    let data =
        unwrap_aes_response(&body, ECPG_KEY, ECPG_IV).expect("TransCode==1 and Data decrypts");
    println!(
        "  Data keys = {:?}",
        data.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    println!("  Data = {data}");
    assert!(
        data["Token"].as_str().is_some_and(|t| !t.is_empty()),
        "a token was issued: the crate's AES envelope speaks ECPG verbatim"
    );
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn ecpg_query_trade_on_ecpayment_domain_answers() {
    // The dual-domain rule: queries live on ecpayment-stage /1.0.0/, NOT ecpg.
    let (status, body) = aes_post(
        "https://ecpayment-stage.ecpay.com.tw/1.0.0/Cashier/QueryTrade",
        ECPG_MERCHANT,
        json!({ "Timestamp": unix_now() }),
        json!({
            "MerchantID": ECPG_MERCHANT,
            "MerchantTradeNo": unique_no("PROBE"), // never created → business error expected
        }),
        ECPG_KEY,
        ECPG_IV,
    )
    .await;
    println!("QueryTrade status={status} body={body}");
    assert_eq!(status, 200, "stage must answer HTTP 200");
    let data =
        unwrap_aes_response(&body, ECPG_KEY, ECPG_IV).expect("TransCode==1 and Data decrypts");
    println!("  Data = {data}");
    println!(
        "  RtnCode={} RtnMsg={:?} (order-not-found is the EXPECTED business answer)",
        data["RtnCode"], data["RtnMsg"]
    );
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn ecpg_rejects_a_wrong_aes_key() {
    // Error-path conformance: a corrupted key must not yield TransCode==1.
    let (status, body) = aes_post(
        "https://ecpg-stage.ecpay.com.tw/Merchant/GetTokenbyTrade",
        ECPG_MERCHANT,
        json!({ "Timestamp": unix_now() }),
        json!({ "MerchantID": ECPG_MERCHANT, "TotalAmount": "100" }),
        "XXXXXXXXXXXXXXXX", // wrong key on purpose
        ECPG_IV,
    )
    .await;
    println!("wrong-key status={status} body={body}");
    // ECPay answers HTTP 200 at this gate with a JSON envelope (observed:
    // TransCode=110). Require the answer to actually come from ECPay (HTTP 200
    // JSON) so a proxy/captive-portal HTML page can't silently "pass".
    assert_eq!(status, 200, "stage answers 200 even for a decrypt failure");
    match serde_json::from_str::<Value>(&body) {
        Err(_) => println!("  non-JSON answer — rejected before the AES gate"),
        Ok(res) => {
            let trans_code = res["TransCode"].as_i64().unwrap_or(-1);
            println!("  TransCode={} TransMsg={:?}", trans_code, res["TransMsg"]);
            assert!(
                trans_code != 1,
                "a wrong AES key must be rejected (HTTP {status}, TransCode {trans_code})"
            );
        }
    }
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn logistics_domestic_create_with_md5_cmv_answers() {
    // Field set mirrors example/Logistics/Domestic/CreateCvs.php: form POST,
    // CheckMacValue MD5 (EncryptType=0), merchant 2000132 (OTP 帳號).
    let mut m = HashMap::new();
    m.insert("MerchantID".to_owned(), LOGISTICS_MERCHANT.to_owned());
    m.insert("MerchantTradeNo".to_owned(), unique_no("PROBE"));
    m.insert("MerchantTradeDate".to_owned(), taipei_now());
    m.insert("LogisticsType".to_owned(), "CVS".into());
    m.insert("LogisticsSubType".to_owned(), "FAMI".into());
    m.insert("GoodsAmount".to_owned(), "1000".into());
    m.insert("GoodsName".to_owned(), "綠界 SDK 範例商品".into());
    m.insert("SenderName".to_owned(), "陳大明".into());
    m.insert("SenderCellPhone".to_owned(), "0911222333".into());
    m.insert("ReceiverName".to_owned(), "王小美".into());
    m.insert("ReceiverCellPhone".to_owned(), "0933222111".into());
    m.insert(
        "ServerReplyURL".to_owned(),
        "https://www.ecpay.com.tw/example/server-reply".into(),
    );
    m.insert("ReceiverStoreID".to_owned(), "006598".into()); // store from the official example
    let mac = ecpay::crypto::check_mac_value(&m, LOGISTICS_KEY, LOGISTICS_IV, 0).expect("MD5 CMV");
    m.insert("CheckMacValue".to_owned(), mac);

    let endpoint = "https://logistics-stage.ecpay.com.tw/Express/Create";
    let body = form_post(endpoint, &m).await;
    println!("Express/Create raw body = {body:?}");

    // Server-truth response format: `<status>|<urlencoded query>` — the leading
    // `1|` status segment is NOT part of the signed data. Split it off before
    // parsing/verifying, or the first key silently gains a `1|` prefix and the
    // CMV never matches.
    let (status_prefix, query) = body.split_once('|').expect("response starts with `1|`");
    assert_eq!(status_prefix, "1", "status segment of the pipe response");
    let fields = parse_query(query);
    let sent = fields
        .get("CheckMacValue")
        .expect("response carries a CheckMacValue");
    let ours = ecpay::crypto::check_mac_value(&fields, LOGISTICS_KEY, LOGISTICS_IV, 0)
        .expect("MD5 CMV over response fields");
    assert_eq!(
        ours, *sent,
        "response CMV signs the query AFTER the `1|` prefix"
    );
    println!("  response CheckMacValue verified byte-exact (MD5 over the query part)");
    println!("  parsed = {fields:?}");
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn b2b_invoice_issue_reaches_the_service() {
    // Field set mirrors example/Invoice/B2B/Issue.php. B2B's RqHeader adds
    // RqID (fixed GUID in the official example, which itself reuses it —
    // confirmed NOT an idempotency key: this probe ran twice with the same
    // RqID and minted distinct invoices LP30000931 and LP30000933)
    // + Revision "1.0.0".
    // NOTE: every run issues a REAL stage invoice and consumes a 字軌 number
    // (logistics probes likewise create real stage orders; we do not cancel
    // them — stage data is disposable test data shared by all developers).
    let payload = json!({
        "MerchantID": B2B_MERCHANT,
        "RelateNumber": unique_no("PROBE"),
        "CustomerIdentifier": "23165448",
        "CustomerEmail": "test-buyer@ecpay.com.tw",
        "InvType": "07",
        "TaxType": "1",
        "Items": [{
            "ItemSeq": 1,
            "ItemName": "測試商品01",
            "ItemCount": 3,
            "ItemPrice": 10,
            "ItemTaxType": "1",
            "ItemAmount": 30,
        }],
        "SalesAmount": 30,
        "TaxAmount": 2, // round(30 * 0.05)
        "TotalAmount": 32,
    });
    let (status, body) = aes_post(
        "https://einvoice-stage.ecpay.com.tw/B2BInvoice/Issue",
        B2B_MERCHANT,
        json!({
            "Timestamp": unix_now(),
            "RqID": "701b3264-a538-437e-ad45-2505eb7dde39",
            "Revision": "1.0.0",
        }),
        payload,
        B2B_KEY,
        B2B_IV,
    )
    .await;
    println!("B2B Issue status={status} body={body}");
    assert_eq!(status, 200, "stage must answer HTTP 200");
    // The public stage account 2000132 IS B2B-enabled: issuance must succeed.
    let data = unwrap_aes_response(&body, B2B_KEY, B2B_IV).expect("TransCode==1 and Data decrypts");
    println!("  Data = {data}");
    assert_eq!(
        data["RtnCode"].as_i64(),
        Some(1),
        "B2B Issue must succeed (RtnMsg={:?})",
        data["RtnMsg"]
    );
    assert!(
        data["InvoiceNumber"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "an invoice number was issued"
    );
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn allinone_v2_print_and_redirect_response_shapes() {
    // Captures the two AesStr-style v2 responses whose decrypted shape is
    // not yet pinned (PHP echoes `$response['body']`): print a REAL test
    // order (minted via CreateTestData) and run the store-selection redirect
    // (TempLogisticsID "0" mints a temp trade). Creates real stage-side
    // records, like the other logistics probes.
    let client = Ecpay {
        merchant_id: "2000132".into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        logistics_api_url: "https://logistics-stage.ecpay.com.tw/".into(),
        logistics_hash_key: "5294y06JbISpM5x9".into(),
        logistics_hash_iv: "v77hoKGq4kWxNNIS".into(),
        ..Default::default()
    };

    let created = client
        .allinone_create_test_data(&ecpay::logistics::AllInOneCreateTestDataInput {
            merchant_id: "2000132".into(),
            logistics_sub_type: "FAMI".into(),
        })
        .await
        .expect("create test data");
    let logistics_id = created["LogisticsID"].as_str().unwrap().to_string();
    println!("create_test_data LogisticsID = {logistics_id}");

    match client
        .allinone_print_trade_document(&ecpay::logistics::AllInOnePrintTradeDocumentInput {
            merchant_id: "2000132".into(),
            logistics_ids: vec![logistics_id],
            logistics_sub_type: "FAMI".into(),
        })
        .await
    {
        Ok(html) => {
            println!("PrintTradeDocument HTML len = {}", html.len());
            assert!(
                html.contains("<form"),
                "browser form expected: {}",
                &html[..html.len().min(300)]
            );
        }
        Err(e) => panic!("PrintTradeDocument should answer the HTML form: {e:?}"),
    }

    match client
        .allinone_redirect_to_logistics_selection(&ecpay::logistics::AllInOneRedirectInput {
            temp_logistics_id: "0".into(),
            goods_amount: 100,
            goods_name: "範例商品".into(),
            sender_name: "陳大明".into(),
            sender_zip_code: "11560".into(),
            sender_address: "台北市南港區三重路19-2號6樓".into(),
            server_reply_url: "https://www.ecpay.com.tw/example/server-reply".into(),
            client_reply_url: "https://www.ecpay.com.tw/example/client-reply".into(),
            temperature: None,
        })
        .await
    {
        Ok(html) => {
            println!("Redirect HTML len = {}", html.len());
            assert!(
                html.contains("LogisticsSelection"),
                "selection form expected: {}",
                &html[..html.len().min(300)]
            );
        }
        Err(e) => panic!("RedirectToLogisticsSelection should answer the HTML form: {e:?}"),
    }
}

#[tokio::test]
#[ignore = "hits the real stage server"]
async fn ecpg_query_family_error_shapes() {
    // The ecpayment-domain queries can only be captured on error paths
    // without a browser-completed payment; pin what stage answers for an
    // unknown MerchantTradeNo (TransCode gate + Data field sets).
    let client = Ecpay {
        merchant_id: "3002607".into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        ecpg_api_url: "https://ecpg-stage.ecpay.com.tw/Merchant/".into(),
        ecpayment_api_url: "https://ecpayment-stage.ecpay.com.tw/1.0.0/".into(),
        ..Default::default()
    };
    let unknown = format!("NOSUCH{}", unix_now());
    let trade_ref = ecpay::ecpg::EcpgTradeRefInput {
        merchant_id: "3002607".into(),
        merchant_trade_no: unknown.clone(),
        ..Default::default()
    };

    // The three queries share one not-found shape: the envelope is
    // TransCode=1 and Data decrypts to `{RtnCode: 10000185, RtnMsg: "Cant
    // not find the trade data"}` with an INTEGER RtnCode (captured 2026-09;
    // the typed docs on each method state this).
    for name in ["QueryTrade", "QueryPaymentInfo", "CreditDetail/QueryTrade"] {
        let r: Result<Value, _> = match name {
            "QueryTrade" => client.ecpg_query_trade(&trade_ref).await,
            "QueryPaymentInfo" => client.ecpg_query_payment_info(&trade_ref).await,
            _ => client.ecpg_query_credit_trade(&trade_ref).await,
        };
        let v = r.unwrap_or_else(|e| panic!("{name}: envelope must decode, got {e:?}"));
        println!("{name} (unknown trade) = {v}");
        assert_eq!(v["RtnCode"], 10000185, "{name}: {v}");
        assert_eq!(v["RtnMsg"], "Cant not find the trade data", "{name}: {v}");
    }

    let media = client
        .ecpg_query_trade_media(&ecpay::ecpg::QueryTradeMediaInput {
            merchant_id: "3002607".into(),
            date_type: "2".into(),
            begin_date: "2026-09-01".into(),
            end_date: "2026-09-11".into(),
            payment_type: Some("01".into()),
        })
        .await;
    println!("QueryTradeMedia (empty range) = {media:?}");

    let period = client
        .ecpg_credit_card_period_action(&ecpay::ecpg::EcpgPeriodActionInput {
            // 釐清必要性:只帶 MerchantID、不帶 PlatformID。
            platform_id: None,
            merchant_id: "3002607".into(),
            merchant_trade_no: unknown.clone(),
            action: "ReAuth".into(),
        })
        .await
        .expect("CreditCardPeriodAction: Data MerchantID alone must be accepted");
    println!("CreditCardPeriodAction (merchant_id only) = {period}");
    // 不存在的訂單, with MerchantID/MerchantTradeNo echoed back — the shape
    // the method docs promise once Data carries MerchantID.
    assert_eq!(period["RtnCode"], 90100150, "{period}");
    assert_eq!(period["MerchantID"], "3002607", "{period}");
    assert_eq!(period["MerchantTradeNo"], unknown, "{period}");

    let do_action = client
        .ecpg_do_action(&ecpay::ecpg::EcpgDoActionInput {
            platform_id: None,
            merchant_id: "3002607".into(),
            merchant_trade_no: unknown,
            trade_no: "NOSUCHTREADNO0001".into(),
            action: "R".into(),
            total_amount: 100,
        })
        .await
        .expect("DoAction: Data MerchantID alone must be accepted");
    println!("DoAction (merchant_id only) = {do_action}");
    assert_eq!(do_action["RtnCode"], 10000185, "{do_action}");
}

/// The Data-level `MerchantID` contract on BOTH ECPG domains, captured with
/// raw envelopes: the typed methods refuse an omitted or mismatched value
/// locally, so this probe is the only place those bytes ever reach stage.
/// Pinned so the codes quoted in the crate's guards and docs stay
/// reproducible (2026-09: all five ecpayment endpoints answer 5000220 /
/// 5000261, the ecpg-domain `Merchant/GetTokenbyTrade` answers 5100080 /
/// 5100074 — all with a message naming the parameter; nothing here is an
/// opaque `RtnCode != 1`).
#[tokio::test]
#[ignore = "hits the real stage server"]
async fn ecpg_data_merchant_id_omitted_or_mismatched_is_named_by_stage() {
    let rq = || json!({ "Timestamp": unix_now() });
    let trade_no = unique_no("NOSUCH");
    let ecpayment = "https://ecpayment-stage.ecpay.com.tw/1.0.0/";

    // ecpayment domain, all five endpoints, two shapes each: Data WITHOUT
    // MerchantID, then Data with a MerchantID that is NOT the envelope's.
    let ecpayment_data: [(&str, Value); 5] = [
        ("Cashier/QueryTrade", json!({ "MerchantTradeNo": trade_no })),
        (
            "Cashier/QueryPaymentInfo",
            json!({ "MerchantTradeNo": trade_no }),
        ),
        (
            "CreditDetail/QueryTrade",
            json!({ "MerchantTradeNo": trade_no }),
        ),
        (
            "Cashier/CreditCardPeriodAction",
            json!({ "MerchantTradeNo": trade_no, "Action": "ReAuth" }),
        ),
        (
            "Credit/DoAction",
            json!({
                "MerchantTradeNo": trade_no,
                "TradeNo": "NOSUCHTREADNO0001",
                "Action": "R",
                "TotalAmount": 100,
            }),
        ),
    ];
    for (path, base) in &ecpayment_data {
        let endpoint = format!("{ecpayment}{path}");
        let (status, body) = aes_post(
            &endpoint,
            ECPG_MERCHANT,
            rq(),
            base.clone(),
            ECPG_KEY,
            ECPG_IV,
        )
        .await;
        assert_eq!(status, 200, "{path}: {body}");
        let v = unwrap_aes_response(&body, ECPG_KEY, ECPG_IV)
            .unwrap_or_else(|| panic!("{path}: envelope must decode: {body}"));
        println!("{path} (Data MerchantID omitted) = {v}");
        assert_eq!(v["RtnCode"], 5000220, "{path}: {v}");
        assert!(
            v["RtnMsg"]
                .as_str()
                .is_some_and(|m| m.contains("[MerchantID] is required")),
            "{path}: {v}"
        );

        let mut mismatched = base.clone();
        mismatched["MerchantID"] = json!(LOGISTICS_MERCHANT);
        let (status, body) = aes_post(
            &endpoint,
            ECPG_MERCHANT,
            rq(),
            mismatched,
            ECPG_KEY,
            ECPG_IV,
        )
        .await;
        assert_eq!(status, 200, "{path}: {body}");
        let v = unwrap_aes_response(&body, ECPG_KEY, ECPG_IV)
            .unwrap_or_else(|| panic!("{path}: envelope must decode: {body}"));
        println!("{path} (Data MerchantID mismatched) = {v}");
        assert_eq!(v["RtnCode"], 5000261, "{path}: {v}");
        assert!(
            v["RtnMsg"]
                .as_str()
                .is_some_and(|m| m.contains("[MerchantID] does not match")),
            "{path}: {v}"
        );
    }

    // ecpg domain (Merchant/GetTokenbyTrade): the same two shapes. Neither
    // issues a token, so this adds no stage-side trade.
    let token_payload = |merchant_id: Option<&str>| {
        let mut p = json!({
            "RememberCard": 1,
            "PaymentUIType": 2,
            "ChoosePaymentList": "0",
            "OrderInfo": {
                "MerchantTradeDate": taipei_now(),
                "MerchantTradeNo": unique_no("PROBE"),
                "TotalAmount": "100",
                "ReturnURL": "https://www.ecpay.com.tw/example/receive",
                "TradeDesc": "ecpay-rs probe",
                "ItemName": "Probe",
            },
            "CardInfo": {
                "Redeem": 0,
                "OrderResultURL": "https://www.ecpay.com.tw/example/receive",
                "CreditInstallment": "3,6,12",
                "FlexibleInstallment": 30,
            },
            "ATMInfo": { "ExpireDate": 3 },
            "CVSInfo": { "StoreExpireDate": 10080 },
            "BarcodeInfo": { "StoreExpireDate": 7 },
            "ConsumerInfo": {
                "MerchantMemberID": "probe000001",
                "Email": "customer@email.com",
                "Phone": "0912345678",
                "Name": "Probe",
                "CountryCode": "158",
            },
        });
        if let Some(mid) = merchant_id {
            p["MerchantID"] = json!(mid);
        }
        p
    };
    for (label, mid, code, needle) in [
        ("omitted", None, 5100080, "[MerchantID]"),
        (
            "mismatched",
            Some(LOGISTICS_MERCHANT),
            5100074,
            "MerchantID",
        ),
    ] {
        let (status, body) = aes_post(
            "https://ecpg-stage.ecpay.com.tw/Merchant/GetTokenbyTrade",
            ECPG_MERCHANT,
            rq(),
            token_payload(mid),
            ECPG_KEY,
            ECPG_IV,
        )
        .await;
        assert_eq!(status, 200, "GetTokenbyTrade {label}: {body}");
        let v = unwrap_aes_response(&body, ECPG_KEY, ECPG_IV)
            .unwrap_or_else(|| panic!("GetTokenbyTrade {label}: envelope must decode: {body}"));
        println!("Merchant/GetTokenbyTrade (Data MerchantID {label}) = {v}");
        assert_eq!(v["RtnCode"], code, "GetTokenbyTrade {label}: {v}");
        assert!(
            v["RtnMsg"].as_str().is_some_and(|m| m.contains(needle)),
            "GetTokenbyTrade {label}: {v}"
        );
        assert!(
            v["Token"].as_str().is_none_or(str::is_empty),
            "GetTokenbyTrade {label}: no token may be issued: {v}"
        );
    }
}

// --- helpers (kept local so the probe file survives on its own) ---

async fn form_post(endpoint: &str, params: &HashMap<String, String>) -> String {
    let body = params
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

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(unquote_plus(k), unquote_plus(v));
        }
    }
    out
}

fn unquote_plus(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Server-truth probes (2026-09): do the AIO payment COMMAND endpoints
/// answer with a CheckMacValue the client could verify, like the query
/// endpoints do? Live answers DIVERGE per endpoint, which is why these are
/// two pins, not one assumption:
///
/// * `CreditDetail/DoAction` (credit_do_action): **UNSIGNED** — the
///   not-found reply (`RtnCode=0&RtnMsg=訂單不存在`, plus a duplicated
///   `Merchant=` quirk) carries no CheckMacValue at all, so response
///   verification cannot be adopted there (a `post_cmv_verified`-style gate
///   would reject the normal not-found path).
/// * `Cashier/CreditCardPeriodAction` (credit_card_period_action):
///   **SIGNED** — the equivalent not-found reply carries a CheckMacValue
///   that verifies with the payment keys over the fields AS RECEIVED (the
///   reply echoes EMPTY MerchantID/MerchantTradeNo, the same
///   hash-as-received requirement QueryPaymentInfo's not-found answer
///   pinned). This is the evidence `credit_card_period_action`'s response
///   verification rests on.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test stage_probes -- --ignored --test-threads=1 --nocapture"]
async fn aio_do_action_responses_are_unsigned_query_strings() {
    let client = command_probe_client();
    let mut params: HashMap<String, String> = [
        ("MerchantTradeNo", unique_no("PROBE")),
        ("TradeNo", unique_no("NO")),
        ("Action", "C".to_owned()),
        ("TotalAmount", "100".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    params.insert("MerchantID".to_owned(), ECPG_MERCHANT.into());
    let mac = client.generate_check_value(&params).expect("sign");
    params.insert("CheckMacValue".to_owned(), mac);
    let body = form_post(
        "https://payment-stage.ecpay.com.tw/CreditDetail/DoAction",
        &params,
    )
    .await;
    println!("CreditDetail/DoAction raw => {body}");
    let fields = parse_query(&body);
    assert!(
        !fields.is_empty() && fields.contains_key("RtnCode"),
        "expected the in-band RtnCode business answer, got: {body}"
    );
    assert!(
        !fields.contains_key("CheckMacValue"),
        "the response is now CheckMacValue-SIGNED — server behavior changed; \
         adopt post_cmv_verified-style verification in credit_do_action and \
         update this pin"
    );
    println!("CreditDetail/DoAction: confirmed unsigned (no CheckMacValue)");
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test stage_probes -- --ignored --test-threads=1 --nocapture"]
async fn aio_credit_card_period_action_responses_are_signed_and_verify() {
    let client = command_probe_client();
    let mut params: HashMap<String, String> = [
        ("MerchantTradeNo", unique_no("PROBE")),
        ("Action", "Stop".to_owned()),
        ("TimeStamp", unix_now().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    params.insert("MerchantID".to_owned(), ECPG_MERCHANT.into());
    let mac = client.generate_check_value(&params).expect("sign");
    params.insert("CheckMacValue".to_owned(), mac);
    let body = form_post(
        "https://payment-stage.ecpay.com.tw/Cashier/CreditCardPeriodAction",
        &params,
    )
    .await;
    println!("Cashier/CreditCardPeriodAction raw => {body}");
    let fields = parse_query(&body);
    assert!(
        fields.contains_key("RtnCode"),
        "expected the in-band RtnCode business answer, got: {body}"
    );
    assert!(
        fields.contains_key("CheckMacValue"),
        "the response no longer carries CheckMacValue — server behavior \
         changed; drop credit_card_period_action's response verification and \
         update this pin"
    );
    assert!(
        client.verify_check_mac_value(&fields),
        "the not-found answer's CheckMacValue must verify over the fields as \
         received (empty echoed MerchantID/MerchantTradeNo included)"
    );
    println!("Cashier/CreditCardPeriodAction: CheckMacValue present and verifies");
}

fn command_probe_client() -> Ecpay {
    Ecpay {
        merchant_id: ECPG_MERCHANT.into(),
        hash_key: ECPG_KEY.into(),
        hash_iv: ECPG_IV.into(),
        payment_api_url: "https://payment-stage.ecpay.com.tw/Cashier/".into(),
        credit_api_url: "https://payment-stage.ecpay.com.tw/CreditDetail/".into(),
        ..Default::default()
    }
}
