//! Staging probes for the three services the official PHP SDK (`ECPay/SDK_PHP`)
//! covers that this crate does NOT implement yet:
//!
//! 1. ECPG 站內付 2.0 (AES-JSON, `ecpg-stage` + `ecpayment-stage` domains)
//! 2. 國內物流 Domestic logistics (form POST + CheckMacValue **MD5**,
//!    `logistics-stage/Express/Create`)
//! 3. B2B 電子發票 (AES-JSON, `RqHeader` 帶 `RqID` + `Revision`)
//!
//! Each probe builds its request with this crate's own public crypto helpers
//! (`encrypt_data` / `check_mac_value`) against the official public stage test
//! accounts, prints the RAW server answer, and asserts only transport/protocol
//! facts (HTTP 200, TransCode gating). Business outcomes (order-not-found,
//! 服務未開通, …) are printed, not asserted — the point is to pin down what the
//! stage server actually accepts from our wire format, independent of any
//! language-SDK quirk, and to seed the eventual typed implementations.
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
/// the transport layer succeeded.
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
    // ConsumerInfo is load-bearing: without Email/Phone the stage answers
    // RtnCode≠1 with no message (guides/02 §GetTokenbyTrade 必填欄位速查).
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
        merchant_id: Some("3002607".into()),
        merchant_trade_no: unknown.clone(),
        ..Default::default()
    };

    for name in ["QueryTrade", "QueryPaymentInfo", "CreditDetail/QueryTrade"] {
        let r: Result<Value, _> = match name {
            "QueryTrade" => client.ecpg_query_trade(&trade_ref).await,
            "QueryPaymentInfo" => client.ecpg_query_payment_info(&trade_ref).await,
            _ => client.ecpg_query_credit_trade(&trade_ref).await,
        };
        match r {
            Ok(v) => println!("{name} (unknown trade) = {v}"),
            Err(e) => println!("{name} (unknown trade) error = {e:?}"),
        }
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
            merchant_id: Some("3002607".into()),
            merchant_trade_no: unknown.clone(),
            action: "ReAuth".into(),
        })
        .await;
    println!("CreditCardPeriodAction (merchant_id only) = {period:?}");

    let do_action = client
        .ecpg_do_action(&ecpay::ecpg::EcpgDoActionInput {
            platform_id: None,
            merchant_id: Some("3002607".into()),
            merchant_trade_no: unknown,
            trade_no: "NOSUCHTREADNO0001".into(),
            action: "R".into(),
            total_amount: 100,
        })
        .await;
    println!("DoAction (merchant_id only) = {do_action:?}");
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn unique_no(tag: &str) -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{tag}{n}")
}

fn taipei_now() -> String {
    let secs = unix_now() + 8 * 3600; // UTC+8
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
