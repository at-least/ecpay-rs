//! Full protocol-flow E2E for the four non-AIO services, against LOCAL
//! simulators of ECPay's server behavior — completely offline, runs in the
//! default `cargo test`. Same honest contract as `tests/full_flow.rs`:
//!
//! The simulators prove FLOW WIRING — request signing → server acceptance →
//! callback delivery → merchant verification/decryption → required reply
//! format → state threading through the query APIs. They CANNOT prove parity
//! with the real server (a simulator built on this crate's own crypto
//! can't); that burden stays on `tests/stage_probes.rs`, the live sandbox
//! suites (`tests/sandbox_logistics.rs`, `tests/sandbox_b2b.rs`), and the
//! official vectors. Negative paths ARE delivered over the wire (tampered
//! MD5 callback, wrong-key AES callback) to prove the verifiers do real
//! work; a handler panic surfaces as an opaque connection error, so run
//! failures with `--nocapture` to see the cause.
//!
//! Callback wire formats follow the official docs (ECPay-API-Skill
//! guides/21): domestic logistics ServerReplyURL is an MD5-CMV form POST
//! answered with exact `1|OK`; AllInOne v2 ServerReplyURL is an AES-JSON
//! POST answered with an AES-encrypted JSON ack (`logistics_notify_reply`);
//! ECPG 站內付 ReturnURL is a JSON POST whose `Data` is AES-encrypted
//! (decoded by `decrypt_ecpg_callback`) answered with exact `1|OK`. Field
//! VALUES inside callbacks are illustrative unless noted as live-captured.
//!
//! Four flows:
//! 1. 國內物流 — create → MD5 status callback, accepted and answered
//!    `1|OK`; a tampered-MAC replay is rejected (`0|ERR`); the replayed
//!    VALID callback verifies and acks again while the merchant-side dedup
//!    (application logic, not this crate) counts it once; the query API
//!    returns the simulator's status.
//! 2. 全方位物流 v2 — store-selection redirect → TempTradeEstablished
//!    (ClientReplyURL) → create_by_temp_trade → AES notify + encrypted ack →
//!    query.
//! 3. ECPG 站內付 — token → PayToken payment (PayToken is the JS SDK's
//!    exchange product, modeled as a distinct derived value) → ReturnURL AES
//!    callback → `1|OK`; a wrong-key callback is rejected → query shows paid.
//! 4. B2B 發票 — issue → get → invalid → get_invalid. B2B has NO inbound
//!    callback (all results are pulled via queries), so this flow asserts
//!    envelope/state threading only, not callback handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ecpay::crypto::check_mac_value;
use ecpay::Ecpay;

mod common;
use common::spawn_http_server;

const MERCHANT_ID: &str = "2000132";
const LOG_KEY: &str = "5294y06JbISpM5x9";
const LOG_IV: &str = "v77hoKGq4kWxNNIS";
const PAY_KEY: &str = "pwFHCqoQZGmho4w6";
const PAY_IV: &str = "EkRm7iFT261dpevs";
const B2B_KEY: &[u8] = b"ejCk326UnaZWKisg";
const B2B_IV: &[u8] = b"q9jcZX8Ib9LM8wYk";

// --- tiny shared helpers ---

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

fn md5(fields: &HashMap<String, String>) -> String {
    check_mac_value(fields, LOG_KEY, LOG_IV, 0).expect("md5 cmv")
}

async fn post_form(url: &str, pairs: &[(String, String)]) -> (u16, String) {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .expect("POST");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

async fn post_json(url: &str, body: String) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(body)
        .send()
        .await
        .expect("POST");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in body.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(unquote(k), unquote(v));
        }
    }
    out
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Builds `k=v&...` sorted by key, URL-encoded — how ECPay signs and sends
/// its query-string responses.
fn signed_query(pairs: &[(&str, String)], key: &str, iv: &str, encrypt_type: i64) -> String {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    let mac = check_mac_value(&map, key, iv, encrypt_type).expect("cmv");
    let mut all = map;
    all.insert("CheckMacValue".to_string(), mac);
    let mut sorted: Vec<_> = all.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ===========================================================================
// Flow 1 — 國內物流: create → MD5 callback (idempotent replay) → query
// ===========================================================================

#[derive(Default)]
struct DomesticSim {
    next_id: u64,
    /// AllPayLogisticsID → (MerchantTradeNo, LogisticsStatus)
    orders: HashMap<String, (String, String)>,
}

#[tokio::test]
async fn domestic_logistics_full_flow_with_idempotent_callback() {
    let sim = Arc::new(Mutex::new(DomesticSim::default()));
    let merchant_log: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));

    // --- the merchant's ServerReplyURL handler: verify MD5 CMV (a tampered
    // --- callback must be rejected with `0|ERR`), dedup, reply exact `1|OK`.
    let merchant = {
        let client = Ecpay {
            merchant_id: MERCHANT_ID.into(),
            hash_key: PAY_KEY.into(),
            hash_iv: PAY_IV.into(),
            logistics_hash_key: LOG_KEY.as_bytes().to_vec(),
            logistics_hash_iv: LOG_IV.as_bytes().to_vec(),
            ..Default::default()
        };
        let log = merchant_log.clone();
        spawn_http_server(move |_path, body| {
            let fields = parse_form(&String::from_utf8_lossy(body));
            if !client.verify_logistics_check_mac_value(&fields) {
                // Tampered/forged callback: reject so ECPay retries.
                return (200, "text/plain".into(), b"0|ERR".to_vec());
            }
            let key = format!(
                "{}|{}",
                fields["AllPayLogisticsID"], fields["LogisticsStatus"]
            );
            let mut log = log.lock().unwrap();
            if !log.iter().any(|(k, _)| *k == key) {
                log.push((key, fields["AllPayLogisticsID"].clone()));
            }
            // ECPay retries unless the reply is EXACTLY `1|OK`.
            (200, "text/plain".into(), b"1|OK".to_vec())
        })
    };

    // --- the ECPay simulator: Create + QueryLogisticsTradeInfo/V2.
    let ecpay_sim = {
        let sim = sim.clone();
        spawn_http_server(move |path, body| {
            let fields = parse_form(&String::from_utf8_lossy(body));
            let sent_mac = fields.get("CheckMacValue").cloned().unwrap_or_default();
            let mut sans = fields.clone();
            sans.remove("CheckMacValue");
            let computed = md5(&sans);
            assert_eq!(
                computed, sent_mac,
                "request must carry a valid MD5 CMV: computed={computed} sent={sent_mac} fields={fields:?}"
            );

            let mut state = sim.lock().unwrap();
            if path.ends_with("/Express/Create") {
                state.next_id += 1;
                let id = format!("9000{}", state.next_id);
                state.orders.insert(
                    id.clone(),
                    (fields["MerchantTradeNo"].clone(), "300".into()),
                );
                let query = signed_query(
                    &[
                        ("AllPayLogisticsID", id.clone()),
                        ("MerchantTradeNo", fields["MerchantTradeNo"].clone()),
                        ("RtnCode", "300".into()),
                        ("RtnMsg", "訂單處理中(綠界已收到訂單資料)".into()),
                    ],
                    LOG_KEY,
                    LOG_IV,
                    0,
                );
                (200, "text/plain".into(), format!("1|{query}").into_bytes())
            } else if path.ends_with("/Helper/QueryLogisticsTradeInfo/V2") {
                let id = &fields["AllPayLogisticsID"];
                let (trade_no, status) = state
                    .orders
                    .get(id)
                    .cloned()
                    .expect("queried order exists (created by this flow)");
                let query = signed_query(
                    &[
                        ("AllPayLogisticsID", id.clone()),
                        ("LogisticsStatus", status),
                        ("LogisticsType", "CVS_FAMI".into()),
                        ("MerchantID", MERCHANT_ID.into()),
                        ("MerchantTradeNo", trade_no),
                    ],
                    LOG_KEY,
                    LOG_IV,
                    0,
                );
                (200, "text/plain".into(), query.into_bytes())
            } else {
                panic!("unexpected simulator path {path}");
            }
        })
    };

    let merchant_url = merchant.clone();
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: PAY_KEY.into(),
        hash_iv: PAY_IV.into(),
        logistics_api_url: ecpay_sim.clone(),
        logistics_hash_key: LOG_KEY.as_bytes().to_vec(),
        logistics_hash_iv: LOG_IV.as_bytes().to_vec(),
        ..Default::default()
    };

    // 1. Create the logistics order through the crate.
    let created = client
        .logistics_create(&ecpay::logistics::LogisticsCreateInput {
            merchant_trade_no: "E2E0000001".into(),
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
            server_reply_url: format!("{merchant_url}server-reply"),
            ..Default::default()
        })
        .await
        .expect("create");
    assert_eq!(created["RtnCode"], "300");
    let logistics_id = created["AllPayLogisticsID"].clone();

    // 2. ECPay "processes" the order and delivers the status callback
    //    (MD5-CMV form POST). Merchant must answer exactly `1|OK` — twice,
    //    because ECPay retries, and the merchant dedups by id+status.
    let trade_no = sim
        .lock()
        .unwrap()
        .orders
        .get(&logistics_id)
        .unwrap()
        .0
        .clone();
    let deliver = |status: &'static str| {
        let url = format!("{merchant_url}server-reply");
        let trade_no = trade_no.clone();
        let logistics_id = logistics_id.clone();
        let sim = sim.clone();
        async move {
            // ECPay-side state change happens BEFORE the callback fires.
            sim.lock().unwrap().orders.get_mut(&logistics_id).unwrap().1 = status.to_string();
            let fields: HashMap<String, String> = [
                ("MerchantID", MERCHANT_ID.to_string()),
                ("MerchantTradeNo", trade_no),
                ("AllPayLogisticsID", logistics_id),
                ("LogisticsSubType", "FAMI".into()),
                ("GoodsAmount", "1000".into()),
                ("LogisticsStatus", status.to_string()),
                ("RtnMsg", "貨件已抵達門市".into()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
            let mac = md5(&fields);
            let mut pairs: Vec<(String, String)> = fields.into_iter().collect();
            pairs.push(("CheckMacValue".to_string(), mac));
            post_form(&url, &pairs).await
        }
    };
    let (status, reply) = deliver("310").await;
    assert_eq!(status, 200);
    assert_eq!(reply, "1|OK", "exact reply format, no whitespace");
    // Retry delivery: merchant must not double-process but must still ack.
    let (_, reply2) = deliver("310").await;
    assert_eq!(reply2, "1|OK");
    {
        let log = merchant_log.lock().unwrap();
        assert_eq!(
            log.iter().filter(|(k, _)| k.contains("|310")).count(),
            1,
            "replayed callback deduped by (id, status) — application logic; \
             what the crate guarantees is that the replayed payload still verifies"
        );
    }

    // A FORGED callback (MAC that signs different content) must be rejected
    // over the wire — proving verify_logistics_check_mac_value does real work.
    {
        let url = format!("{merchant_url}server-reply");
        let forged: Vec<(String, String)> = vec![
            ("MerchantID".into(), MERCHANT_ID.into()),
            ("MerchantTradeNo".into(), trade_no.clone()),
            ("AllPayLogisticsID".into(), logistics_id.clone()),
            ("LogisticsSubType".into(), "FAMI".into()),
            ("LogisticsStatus".into(), "999".into()),
            ("CheckMacValue".into(), "0".repeat(32)),
        ];
        let (st, reply) = post_form(&url, &forged).await;
        assert_eq!(st, 200);
        assert_eq!(reply, "0|ERR", "forged MAC must not be accepted");
        let log = merchant_log.lock().unwrap();
        assert!(
            !log.iter().any(|(k, _)| k.contains("|999")),
            "rejected callback must not be processed"
        );
    }

    // 3. The query API returns the simulator's status. (The status itself was
    //    advanced test-side — this asserts the query round-trip, while the
    //    callback handling above is proven by the log/ack assertions.)
    let info = client
        .logistics_query_logistics_trade_info(&ecpay::logistics::DomesticQueryInput {
            all_pay_logistics_id: logistics_id,
            time_stamp: None,
        })
        .await
        .expect("query");
    assert_eq!(info["LogisticsStatus"], "310");
}

// ===========================================================================
// Flow 2 — 全方位物流 v2: redirect → TempTradeEstablished → create → AES
// notify + encrypted ack → query
// ===========================================================================

#[derive(Default)]
struct V2Sim {
    next: u64,
    temps: HashMap<String, bool>,    // TempLogisticsID → bound?
    orders: HashMap<String, String>, // LogisticsID → LogisticsStatus
}

#[tokio::test]
async fn allinone_v2_full_flow_with_encrypted_ack() {
    let sim = Arc::new(Mutex::new(V2Sim::default()));

    // Merchant handlers: ClientReplyURL decodes ResultData (AES envelope in a
    // form field); ServerReplyURL decodes the AES notify and answers with the
    // ENCRYPTED ack ECPay requires for v2.
    let merchant = {
        let client = Ecpay {
            merchant_id: MERCHANT_ID.into(),
            hash_key: PAY_KEY.into(),
            hash_iv: PAY_IV.into(),
            logistics_hash_key: LOG_KEY.as_bytes().to_vec(),
            logistics_hash_iv: LOG_IV.as_bytes().to_vec(),
            ..Default::default()
        };
        spawn_http_server(move |path, body| {
            if path.ends_with("client-reply") {
                let fields = parse_form(&String::from_utf8_lossy(body));
                let decoded: serde_json::Value = client
                    .decrypt_temp_trade_established(&fields["ResultData"])
                    .expect("ResultData decodes");
                assert_eq!(decoded["TempLogisticsID"], "T1");
                (200, "text/html".into(), b"<html>ok</html>".to_vec())
            } else {
                let notify: serde_json::Value =
                    serde_json::from_slice(body).expect("notify is JSON");
                let decoded: serde_json::Value = client
                    .decrypt_logistics_callback(&notify.to_string())
                    .expect("notify decrypts");
                assert_eq!(decoded["LogisticsStatus"], "310");
                // The v2 reply is an AES-encrypted JSON ack, not `1|OK`.
                let ack = client.logistics_notify_reply().expect("ack builds");
                (200, "application/json".into(), ack.into_bytes())
            }
        })
    };

    let ecpay_sim = {
        let sim = sim.clone();
        spawn_http_server(move |path, body| {
            let env: serde_json::Value = serde_json::from_slice(body).unwrap();
            let rq = &env["RqHeader"];
            assert_eq!(rq["Revision"], "1.0.0", "v2 RqHeader pins Revision");
            let mut state = sim.lock().unwrap();
            if path.ends_with("/Express/v2/RedirectToLogisticsSelection") {
                let temp = format!("T{}", state.next + 1);
                state.temps.insert(temp, false);
                state.next += 1;
                // Server-truth (live-captured 2026-09): the redirect answers
                // raw text/html — an auto-submitting form, not an envelope.
                (
                    200,
                    "text/html".into(),
                    b"<html><head><title>AutoSubmitFormToLogisticsSelection</title></head><body><form id=\"PostForm\" action=\"LogisticsSelection\" method=\"POST\"></form></body></html>"
                        .to_vec(),
                )
            } else if path.ends_with("/Express/v2/CreateByTempTrade") {
                let payload: serde_json::Value = ecpay::crypto::decrypt_data(
                    env["Data"].as_str().unwrap(),
                    LOG_KEY.as_bytes(),
                    LOG_IV.as_bytes(),
                )
                .unwrap();
                let temp = payload["TempLogisticsID"].as_str().unwrap().to_string();
                assert!(state.temps.contains_key(&temp), "temp trade exists");
                *state.temps.get_mut(&temp).unwrap() = true;
                state.next += 1;
                let id = format!("L{:06}", state.next);
                state.orders.insert(id.clone(), "300".into());
                // Response shape captured live (CreateTestData family).
                let data = ecpay::crypto::encrypt_data(
                    &serde_json::json!({
                        "RtnCode": 1, "RtnMsg": "成功", "LogisticsID": id,
                        "LogisticsStatus": "300", "LogisticsStatusName": "訂單處理中",
                    }),
                    LOG_KEY.as_bytes(),
                    LOG_IV.as_bytes(),
                )
                .unwrap();
                (
                    200,
                    "application/json".into(),
                    serde_json::json!({
                        "MerchantID": MERCHANT_ID, "RpHeader": {"Timestamp": 1},
                        "TransCode": 1, "TransMsg": "Success", "Data": data,
                    })
                    .to_string()
                    .into_bytes(),
                )
            } else if path.ends_with("/Express/v2/QueryLogisticsTradeInfo") {
                let payload: serde_json::Value = ecpay::crypto::decrypt_data(
                    env["Data"].as_str().unwrap(),
                    LOG_KEY.as_bytes(),
                    LOG_IV.as_bytes(),
                )
                .unwrap();
                let id = payload["LogisticsID"].as_str().unwrap().to_string();
                let status = state.orders[&id].clone();
                let data = ecpay::crypto::encrypt_data(
                    &serde_json::json!({"RtnCode": 1, "LogisticsID": id, "LogisticsStatus": status}),
                    LOG_KEY.as_bytes(),
                    LOG_IV.as_bytes(),
                )
                .unwrap();
                (200, "application/json".into(), serde_json::json!({
                    "MerchantID": MERCHANT_ID, "TransCode": 1, "TransMsg": "Success", "Data": data,
                }).to_string().into_bytes())
            } else {
                panic!("unexpected simulator path {path}");
            }
        })
    };

    let merchant_url = merchant.clone();
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: PAY_KEY.into(),
        hash_iv: PAY_IV.into(),
        logistics_api_url: ecpay_sim.clone(),
        logistics_hash_key: LOG_KEY.as_bytes().to_vec(),
        logistics_hash_iv: LOG_IV.as_bytes().to_vec(),
        ..Default::default()
    };

    // 1. Consumer store selection → temp trade established on ClientReplyURL.
    let redirect = client
        .allinone_redirect_to_logistics_selection(&ecpay::logistics::AllInOneRedirectInput {
            temp_logistics_id: "0".into(),
            goods_amount: 100,
            goods_name: "範例商品".into(),
            sender_name: "陳大明".into(),
            sender_zip_code: "11560".into(),
            sender_address: "台北市南港區三重路19-2號6樓".into(),
            server_reply_url: format!("{merchant_url}server-reply"),
            client_reply_url: format!("{merchant_url}client-reply"),
            ..Default::default()
        })
        .await
        .expect("redirect answers the HTML form");
    assert!(
        redirect.contains("AutoSubmitFormToLogisticsSelection"),
        "raw HTML form must be returned verbatim for the browser"
    );

    // ECPay delivers TempTradeEstablished as urlencoded ResultData.
    let established = serde_json::json!({
        "MerchantID": MERCHANT_ID, "RqHeader": {"Timestamp": 1},
        "TransCode": 1, "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({"TempLogisticsID": "T1", "ReceiverStoreID": "006598"}),
            LOG_KEY.as_bytes(), LOG_IV.as_bytes()).unwrap(),
    });
    let (st, _) = post_form(
        &format!("{merchant_url}client-reply"),
        &[("ResultData".into(), urlencode(&established.to_string()))],
    )
    .await;
    assert_eq!(st, 200, "merchant decoded the temp-trade callback");

    // 2. Bind the temp trade into a real logistics order.
    let created = client
        .allinone_create_by_temp_trade(&ecpay::logistics::CreateByTempTradeInput {
            temp_logistics_id: "T1".into(),
        })
        .await
        .expect("create by temp trade");
    assert_eq!(created["RtnCode"], 1);
    let logistics_id = created["LogisticsID"].as_str().unwrap().to_string();

    // 3. ECPay notifies the status change (AES JSON); merchant decodes and
    //    answers with the encrypted ack — and the ack must decrypt back to
    //    RtnCode "1" or ECPay would retry.
    sim.lock()
        .unwrap()
        .orders
        .insert(logistics_id.clone(), "310".into());
    let notify = serde_json::json!({
        "MerchantID": MERCHANT_ID, "RqHeader": {"Timestamp": 2},
        "TransCode": 1, "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({"LogisticsID": logistics_id, "LogisticsStatus": "310", "RtnCode": 1}),
            LOG_KEY.as_bytes(), LOG_IV.as_bytes()).unwrap(),
    });
    let (st, ack) = post_json(&format!("{merchant_url}server-reply"), notify.to_string()).await;
    assert_eq!(st, 200);
    let ack_env: serde_json::Value = serde_json::from_str(&ack).unwrap();
    assert_eq!(ack_env["TransCode"], "1");
    let ack_data: serde_json::Value = ecpay::crypto::decrypt_data(
        ack_env["Data"].as_str().unwrap(),
        LOG_KEY.as_bytes(),
        LOG_IV.as_bytes(),
    )
    .unwrap();
    assert_eq!(ack_data["RtnCode"], "1", "encrypted ack accepted");

    // 4. Query shows the delivered status.
    let info = client
        .allinone_query_logistics_trade_info(&ecpay::logistics::AllInOneQueryInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id,
        })
        .await
        .expect("query");
    assert_eq!(info["LogisticsStatus"], "310");
}

// ===========================================================================
// Flow 3 — ECPG 站內付: token → PayToken payment → ReturnURL AES callback →
// exact `1|OK` → query shows paid
// ===========================================================================

#[derive(Default)]
struct EcpgSim {
    token: String,
    merchant_trade_no: String,
    paid: bool,
}

#[tokio::test]
async fn ecpg_full_flow_from_token_to_paid_query() {
    let sim = Arc::new(Mutex::new(EcpgSim::default()));
    let merchant = {
        let client = Ecpay {
            merchant_id: MERCHANT_ID.into(),
            hash_key: PAY_KEY.into(),
            hash_iv: PAY_IV.into(),
            ..Default::default()
        };
        spawn_http_server(move |_path, body| {
            // guides/21: parse JSON → TransCode gate → AES decrypt Data →
            // inner RtnCode → reply EXACT `1|OK`. Anything that fails the
            // gate/decryption is answered `0|ERR` (ECPay retries).
            let decoded: serde_json::Value =
                match client.decrypt_ecpg_callback(&String::from_utf8_lossy(body)) {
                    Ok(v) => v,
                    Err(_) => return (200, "text/plain".into(), b"0|ERR".to_vec()),
                };
            assert_eq!(decoded["RtnCode"], 1, "payment success");
            assert_eq!(decoded["MerchantTradeNo"], "E2E0000001");
            (200, "text/plain".into(), b"1|OK".to_vec())
        })
    };

    let ecpay_sim = {
        let sim = sim.clone();
        spawn_http_server(move |path, body| {
            let env: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                env["RqHeader"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                vec!["Timestamp"],
                "ECPG RqHeader carries ONLY Timestamp"
            );
            let payload: serde_json::Value = ecpay::crypto::decrypt_data(
                env["Data"].as_str().unwrap(),
                PAY_KEY.as_bytes(),
                PAY_IV.as_bytes(),
            )
            .unwrap();
            let mut state = sim.lock().unwrap();
            if path.ends_with("/Merchant/GetTokenbyTrade") {
                state.merchant_trade_no = payload["OrderInfo"]["MerchantTradeNo"]
                    .as_str()
                    .unwrap()
                    .into();
                state.token = format!("{:032x}", state.merchant_trade_no.len() + 1);
                let data = ecpay::crypto::encrypt_data(
                    &serde_json::json!({
                        "MerchantID": MERCHANT_ID, "RtnCode": 1, "RtnMsg": "",
                        "Token": state.token, "TokenExpireDate": "2026/09/11 23:59:59",
                    }),
                    PAY_KEY.as_bytes(),
                    PAY_IV.as_bytes(),
                )
                .unwrap();
                (
                    200,
                    "application/json".into(),
                    serde_json::json!({
                        "MerchantID": MERCHANT_ID, "RpHeader": {"Timestamp": 1},
                        "TransCode": 1, "TransMsg": "Success!", "Data": data,
                    })
                    .to_string()
                    .into_bytes(),
                )
            } else if path.ends_with("/Merchant/CreatePayment") {
                // The real front-end JS SDK exchanges the Token for a
                // DISTINCT PayToken; model that exchange as a derivation so
                // the simulator refuses a raw token.
                let expected = format!("PAY{}", state.token);
                assert_eq!(
                    payload["PayToken"], expected,
                    "PayToken is the JS-SDK exchange value, not the raw token"
                );
                assert_ne!(payload["PayToken"], state.token);
                assert_eq!(payload["MerchantTradeNo"], state.merchant_trade_no);
                state.paid = true;
                let data = ecpay::crypto::encrypt_data(
                    &serde_json::json!({"RtnCode": 1, "RtnMsg": "成功", "TradeNo": "T90001"}),
                    PAY_KEY.as_bytes(),
                    PAY_IV.as_bytes(),
                )
                .unwrap();
                (200, "application/json".into(), serde_json::json!({
                    "MerchantID": MERCHANT_ID, "TransCode": 1, "TransMsg": "Success!", "Data": data,
                }).to_string().into_bytes())
            } else if path.ends_with("/1.0.0/Cashier/QueryTrade") {
                let data = ecpay::crypto::encrypt_data(
                    &serde_json::json!({
                        "RtnCode": 1, "RtnMsg": "", "TradeStatus": if state.paid { "1" } else { "0" },
                        "TradeAmt": 100, "PaymentType": "Credit_CreditCard",
                    }),
                    PAY_KEY.as_bytes(), PAY_IV.as_bytes()).unwrap();
                (200, "application/json".into(), serde_json::json!({
                    "MerchantID": MERCHANT_ID, "TransCode": 1, "TransMsg": "Success!", "Data": data,
                }).to_string().into_bytes())
            } else {
                panic!("unexpected simulator path {path}");
            }
        })
    };

    let merchant_url = merchant.clone();
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: PAY_KEY.into(),
        hash_iv: PAY_IV.into(),
        ecpg_api_url: format!("{ecpay_sim}Merchant/"),
        ecpayment_api_url: format!("{ecpay_sim}1.0.0/"),
        ..Default::default()
    };

    // 1. 取號: the typed output proven live on stage.
    let token_out = client
        .get_token_by_trade(&ecpay::ecpg::GetTokenbyTradeInput {
            merchant_id: MERCHANT_ID.into(),
            choose_payment_list: "1".into(),
            order_info: Some(ecpay::ecpg::OrderInfo {
                merchant_trade_date: "2026/09/11 12:00:00".into(),
                merchant_trade_no: "E2E0000001".into(),
                total_amount: 100,
                return_url: format!("{merchant_url}return"),
                trade_desc: "e2e".into(),
                item_name: "商品".into(),
            }),
            consumer_info: Some(ecpay::ecpg::ConsumerInfo {
                email: "customer@email.com".into(),
                phone: "0912345678".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .expect("token issued");
    assert_eq!(token_out.rtn_code, 1);
    assert!(!token_out.token.is_empty());

    // 2. The front-end JS SDK exchanges the token for a DISTINCT PayToken
    //    (modeled as `PAY{token}`); the merchant then creates the payment
    //    server-side with that exchange value.
    let pay_token = format!("PAY{}", token_out.token);
    assert_ne!(
        pay_token, token_out.token,
        "the exchange produces a distinct value"
    );
    let pay = client
        .create_payment(&ecpay::ecpg::CreatePaymentInput {
            merchant_id: MERCHANT_ID.into(),
            pay_token,
            merchant_trade_no: "E2E0000001".into(),
        })
        .await
        .expect("payment accepted");
    assert_eq!(pay["RtnCode"], 1);

    // 3. ECPay delivers the payment result to ReturnURL (JSON + AES Data);
    //    answered exactly `1|OK`. A callback encrypted under a WRONG key
    //    must be rejected (`0|ERR`) — proving the AES gate does real work.
    let return_url = format!("{merchant_url}return");
    let callback = serde_json::json!({
        "MerchantID": MERCHANT_ID, "RqHeader": {"Timestamp": 3},
        "TransCode": 1, "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({
                "RtnCode": 1, "RtnMsg": "付款成功", "MerchantID": MERCHANT_ID,
                "MerchantTradeNo": "E2E0000001", "TradeNo": "T90001",
                "PaymentType": "Credit_CreditCard", "PaymentDate": "2026/09/11 12:01:00",
                "TradeAmt": 100,
            }),
            PAY_KEY.as_bytes(), PAY_IV.as_bytes()).unwrap(),
    });
    let (st, reply) = post_json(&return_url, callback.to_string()).await;
    assert_eq!(st, 200);
    assert_eq!(reply, "1|OK", "ECPG ReturnURL must be answered 1|OK");

    let forged = serde_json::json!({
        "MerchantID": MERCHANT_ID, "TransCode": 1, "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({"RtnCode": 1, "MerchantTradeNo": "FORGED"}),
            b"XXXXXXXXXXXXXXXX", PAY_IV.as_bytes()).unwrap(),
    });
    let (st, reply) = post_json(&return_url, forged.to_string()).await;
    assert_eq!(st, 200);
    assert_eq!(reply, "0|ERR", "wrong-key callback must be rejected");

    // 4. The query API reflects the payment state (set by CreatePayment —
    //    the ReturnURL handling is proven by the 1|OK/0|ERR asserts above).
    let trade = client
        .ecpg_query_trade(&ecpay::ecpg::EcpgTradeRefInput {
            merchant_trade_no: "E2E0000001".into(),
            ..Default::default()
        })
        .await
        .expect("query");
    assert_eq!(trade["TradeStatus"], "1");
}

// ===========================================================================
// Flow 4 — B2B 發票: issue → get → invalid → get_invalid. B2B has NO inbound
// callback — every result is pulled — so this asserts envelope + state
// threading only.
// ===========================================================================

#[derive(Default)]
struct B2bSim {
    next: u64,
    invoices: HashMap<String, (String, bool)>, // InvoiceNumber → (RelateNumber, voided)
}

#[tokio::test]
async fn b2b_issue_get_invalid_getinvalid_chain() {
    let sim = Arc::new(Mutex::new(B2bSim::default()));
    let ecpay_sim = {
        let sim = sim.clone();
        spawn_http_server(move |path, body| {
            let env: serde_json::Value = serde_json::from_slice(body).unwrap();
            let rq = &env["RqHeader"];
            assert_eq!(
                rq.as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
                vec!["Revision", "RqID", "Timestamp"],
                "B2B RqHeader = Timestamp + RqID + Revision"
            );
            assert_eq!(rq["Revision"], "1.0.0");
            let payload: serde_json::Value =
                ecpay::crypto::decrypt_data(env["Data"].as_str().unwrap(), B2B_KEY, B2B_IV)
                    .unwrap();
            let mut state = sim.lock().unwrap();
            let aes_reply = |data: serde_json::Value| {
                (
                    200u16,
                    "application/json".to_string(),
                    serde_json::json!({
                        "MerchantID": 2000132,
                        "RpHeader": {"Timestamp": 1, "RqID": "x", "Reversion": "1.0.0"},
                        "TransCode": 1, "TransMsg": "Success",
                        "Data": ecpay::crypto::encrypt_data(&data, B2B_KEY, B2B_IV).unwrap(),
                    })
                    .to_string()
                    .into_bytes(),
                )
            };
            if path.ends_with("/Issue") {
                state.next += 1;
                let no = format!("LP30000{:03}", state.next);
                state.invoices.insert(
                    no.clone(),
                    (payload["RelateNumber"].as_str().unwrap().into(), false),
                );
                aes_reply(serde_json::json!({
                    "RtnCode": 1, "RtnMsg": "發票開立成功",
                    "InvoiceNumber": no, "RandomNumber": "4016",
                }))
            } else if path.ends_with("/GetIssue") {
                let (relate, voided) =
                    state.invoices[&payload["InvoiceNumber"].as_str().unwrap().to_string()].clone();
                aes_reply(serde_json::json!({
                    "RtnCode": "1", "RtnMsg": "",
                    "RtnData": {
                        "InvoiceNumber": payload["InvoiceNumber"], "RelateNumber": relate,
                        "Invalid_Status": if voided { 1 } else { 0 }, "Issue_Status": 1,
                    },
                }))
            } else if path.ends_with("/Invalid") {
                let no = payload["InvoiceNumber"].as_str().unwrap().to_string();
                state.invoices.get_mut(&no).unwrap().1 = true;
                aes_reply(serde_json::json!({"RtnCode": 1, "RtnMsg": "發票作廢成功"}))
            } else if path.ends_with("/GetInvalid") {
                let (relate, voided) =
                    state.invoices[&payload["InvoiceNumber"].as_str().unwrap().to_string()].clone();
                assert!(voided, "invalid query only meaningful after voiding");
                aes_reply(serde_json::json!({
                    "RtnCode": "1", "RtnMsg": "",
                    "RtnData": {"InvoiceNumber": payload["InvoiceNumber"], "RelateNumber": relate, "Invalid_Status": 1},
                }))
            } else {
                panic!("unexpected simulator path {path}");
            }
        })
    };

    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: PAY_KEY.into(),
        hash_iv: PAY_IV.into(),
        invoice_hash_key: B2B_KEY.to_vec(),
        invoice_hash_iv: B2B_IV.to_vec(),
        b2b_invoice_api_url: ecpay_sim.clone(),
        b2b_rq_id: "701b3264-a538-437e-ad45-2505eb7dde39".into(),
        ..Default::default()
    };

    // 開立 → 查詢 → 作廢 → 查作廢。
    let issue = client
        .issue_b2b(&ecpay::invoice_b2b::IssueB2bInput {
            merchant_id: MERCHANT_ID.into(),
            relate_number: "B2BE2E0001".into(),
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
            tax_amount: 2,
            total_amount: 32,
            ..Default::default()
        })
        .await
        .expect("issue");
    assert_eq!(issue.rtn_code, 1);

    let got = client
        .get_issue_b2b(&ecpay::invoice_b2b::GetIssueInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_category: 0,
            invoice_number: issue.invoice_number.clone(),
            invoice_date: "2026-09-11".into(),
        })
        .await
        .expect("get issue");
    assert_eq!(
        got["RtnCode"], "1",
        "B2B GetIssue RtnCode is the STRING \"1\""
    );
    assert_eq!(got["RtnData"]["RelateNumber"], "B2BE2E0001");

    let voided = client
        .invalid_b2b(&ecpay::invoice_b2b::InvalidInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_number: issue.invoice_number.clone(),
            invoice_date: "2026-09-11".into(),
            reason: "sandbox test".into(), // ≤20 chars (2103005 otherwise)
        })
        .await
        .expect("invalid");
    assert_eq!(voided["RtnCode"], 1);

    let record = client
        .get_invalid_b2b(&ecpay::invoice_b2b::GetInvalidInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_category: 0,
            invoice_number: issue.invoice_number,
            invoice_date: "2026-09-11".into(),
        })
        .await
        .expect("get invalid");
    assert_eq!(record["RtnData"]["Invalid_Status"], 1);
}

// ===========================================================================
// decrypt_ecpg_callback unit coverage (hermetic, no servers)
// ===========================================================================

#[test]
fn ecpg_callback_helper_decodes_a_self_encrypted_envelope() {
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: PAY_KEY.into(),
        hash_iv: PAY_IV.into(),
        ..Default::default()
    };
    let body = serde_json::json!({
        "MerchantID": MERCHANT_ID, "RqHeader": {"Timestamp": 1},
        "TransCode": 1, "TransMsg": "",
        "Data": ecpay::crypto::encrypt_data(
            &serde_json::json!({"RtnCode": 1, "MerchantTradeNo": "X1"}),
            PAY_KEY.as_bytes(), PAY_IV.as_bytes()).unwrap(),
    });
    let decoded: serde_json::Value = client
        .decrypt_ecpg_callback(&body.to_string())
        .expect("decodes");
    assert_eq!(decoded["MerchantTradeNo"], "X1");
}

#[test]
fn ecpg_callback_helper_gates_on_transcode() {
    let client = Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: PAY_KEY.into(),
        hash_iv: PAY_IV.into(),
        ..Default::default()
    };
    let body = serde_json::json!({
        "MerchantID": MERCHANT_ID, "TransCode": 110, "TransMsg": "decrypt fail", "Data": "",
    });
    let err = client
        .decrypt_ecpg_callback::<serde_json::Value>(&body.to_string())
        .expect_err("TransCode ≠ 1 must fail");
    assert!(
        matches!(err, ecpay::Error::TransCode { code: 110, .. }),
        "{err:?}"
    );
}
