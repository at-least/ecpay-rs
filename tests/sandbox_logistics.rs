//! Live logistics tests against the ECPay stage server (public test account
//! 2000132). Like `tests/sandbox.rs`, every test is `#[ignore]`d — the
//! default `cargo test` stays offline; run them with `-- --ignored` and an
//! outbound network. They create real stage logistics orders.
//!
//! Wire-format facts pinned here were first captured by the probes in
//! `tests/stage_probes.rs` (commit ed87553) and are now asserted:
//! `Express/Create` answers `1|<signed query>` with RtnCode=300 for a fresh
//! B2C CVS order.

use ecpay::logistics::{
    AllInOneCancelC2cInput, AllInOneCreateTestDataInput, AllInOneQueryInput,
    AllInOneUpdateStoreInfoInput, CancelC2cInput, CrossBorderCreateTestDataInput,
    DomesticQueryInput, GetStoreListInput, LogisticsCreateInput, UpdateStoreInfoInput,
};
use ecpay::{BaseUrl, Ecpay, Env, Keys, Urls};
mod common;
use common::sandbox::{taipei_now, taipei_today, unique_no};

const MERCHANT_ID: &str = "2000132";
const LOGISTICS_KEY: &str = "5294y06JbISpM5x9";
const LOGISTICS_IV: &str = "v77hoKGq4kWxNNIS";

fn sdk() -> Ecpay {
    // Logistics-only suite: sign/verify through the dedicated logistics
    // pair; NO payment pair is attached (the family accessors refuse an
    // AIO call loudly instead of silently using a wrong pair).
    Ecpay::new(
        MERCHANT_ID,
        Env::Custom(Urls {
            logistics: Some(BaseUrl::new("https://logistics-stage.ecpay.com.tw/").unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_logistics_keys(Keys::new(LOGISTICS_KEY, LOGISTICS_IV).unwrap())
}

/// The same stage account with its logistics credentials attached as the
/// PAYMENT pair and NO dedicated logistics pair: the whole-pair fallback a
/// merchant whose payment and logistics keys are the same value produces.
/// Signs byte-identically to [`sdk`] — same key/IV, only the setter differs
/// — so the live round-trip below proves the real server accepts what the
/// fallback signs without minting an order of its own to prove it.
///
/// Scope, precisely: with a single pair in play these bytes are identical to
/// what the old key-from-one/IV-from-another mix would sign, so nothing live
/// can discriminate whole-pair from per-field fallback. `logistics_wire.rs`
/// (Shape 3) pins that per-field mixing is now unrepresentable, and
/// `client_construction.rs` pins the routing; all the live call adds is that
/// the real MD5 endpoint accepts the result.
///
/// `Env::Custom` with only the logistics base wired, like [`sdk`]: a payment
/// pair IS attached here, so leaving the other families unset is what keeps
/// an accidental AIO call refusing loudly instead of riding these keys out
/// to a real stage endpoint.
fn fallback_sdk() -> Ecpay {
    Ecpay::new(
        MERCHANT_ID,
        Env::Custom(Urls {
            logistics: Some(BaseUrl::new("https://logistics-stage.ecpay.com.tw/").unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_payment_keys(Keys::new(LOGISTICS_KEY, LOGISTICS_IV).unwrap())
}

/// The CVS/FAMI order every live create in this suite mints — only the
/// MerchantTradeNo tag and the amount differ between them. Previously
/// copy-pasted per test, so a wire-field fix needed four edits.
///
/// `server_reply_url` is stage-only: ECPay's example receiver page (this
/// suite never processes the callback). In production point
/// `server_reply_url` at YOUR https endpoint.
fn cvs_order(tag: &str, goods_amount: i64) -> LogisticsCreateInput {
    LogisticsCreateInput {
        merchant_trade_no: unique_no(tag),
        merchant_trade_date: taipei_now(),
        logistics_type: "CVS".into(),
        logistics_sub_type: "FAMI".into(),
        goods_amount,
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

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn domestic_create_then_query_roundtrip() {
    // Runs through the WHOLE-PAIR FALLBACK client on purpose: it signs the
    // same bytes as `sdk()`, so this one live order proves both the create
    // → query round-trip and that the real server accepts a fallback
    // signature — instead of a second order proving the latter alone. The
    // dedicated-pair path stays live-pinned by the two other `sdk()` creates
    // (`domestic_create_update_shipment_query_chain` also queries through it).
    let client = fallback_sdk();
    let out = client
        .logistics_create(&cvs_order("SBX", 1000))
        .await
        .expect("Express/Create round-trips the MD5 MAC and parses");
    println!("create = {out:?}");
    assert_eq!(out["_status_prefix"], "1", "status segment must be 1");
    assert_eq!(
        out["RtnCode"], "300",
        "訂單處理中 = accepted (stage OTP 流程)"
    );
    let logistics_id = &out["AllPayLogisticsID"];
    assert!(!logistics_id.is_empty(), "a logistics order id is minted");

    let info = client
        .logistics_query_logistics_trade_info(&DomesticQueryInput {
            all_pay_logistics_id: logistics_id.clone(),
            time_stamp: None,
        })
        .await
        .expect("QueryLogisticsTradeInfo/V2 round-trips the MAC");
    println!("query = {info:?}");
    // The reply must actually carry the trade back, not just "not a status
    // prefix": the queried id is echoed (spec guides/06: the reply includes
    // AllPayLogisticsID), and the core status field decoded.
    assert!(!info.contains_key("_status_prefix"));
    assert_eq!(
        info.get("AllPayLogisticsID").map(String::as_str),
        Some(logistics_id.as_str()),
        "spec: the reply carries AllPayLogisticsID (guides/06) — got {info:?}"
    );
    assert!(
        info.contains_key("LogisticsStatus"),
        "a decode regression to an empty map must fail here: {info:?}"
    );
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn domestic_create_update_shipment_query_chain() {
    // One live order taken through create → UpdateShipmentInfo → query:
    // three signed round-trips against stage on the same order.
    let client = sdk();
    let created = client
        .logistics_create(&cvs_order("SBXU", 500))
        .await
        .expect("create");
    assert_eq!(created["RtnCode"], "300");
    let logistics_id = created["AllPayLogisticsID"].clone();

    let update = client
        .logistics_update_shipment_info(&ecpay::logistics::UpdateShipmentInfoInput {
            all_pay_logistics_id: logistics_id.clone(),
            shipment_date: taipei_today(),
            receiver_store_id: Some("006598".into()), // CVS 必填 (0|ReceiverStoreID Is Null otherwise)
        })
        .await;
    // Server-truth (2026-09): an OTP order still at RtnCode=300 (消費者尚未
    // 完成門市確認) answers a SHORT UNSIGNED rejection `0|資料處理中，無法
    // 更新貨資訊` — surfaced as Error::Message, not a misleading MAC error.
    match update {
        // Spec (ECPay-API-Skill guides/06): this endpoint answers PLAIN TEXT
        // (`1|OK` accepted, `0|...` rejected), which the crate surfaces as
        // Error::Message either way — never a parsed query.
        Ok(v) => panic!("UpdateShipmentInfo answered a parsed query — new server shape: {v:?}"),
        Err(ecpay::Error::Message(m)) => {
            println!("update answered (plain-text contract) = {m}");
            assert!(
                m.contains("status 1")        // accepted — spec `1|OK`
                    || m.contains("無法更新")
                    || m.contains("處理中"), // OTP-flow rejection (2026-09)
                "documented outcomes only, got: {m}"
            );
        }
        Err(e) => panic!("unexpected error: {e:?}"),
    }

    let info = client
        .logistics_query_logistics_trade_info(&DomesticQueryInput {
            all_pay_logistics_id: logistics_id.clone(),
            time_stamp: None,
        })
        .await
        .expect("query after update");
    println!("query after update = {info:?}");
    assert_eq!(
        info.get("AllPayLogisticsID").map(String::as_str),
        Some(logistics_id.as_str()),
        "spec: the reply carries AllPayLogisticsID (guides/06) — got {info:?}"
    );
    assert!(
        info.contains_key("LogisticsStatus"),
        "the post-update query must decode the trade state: {info:?}"
    );
}

/// C2C 取消/更新門市 need the store-confirmation codes (CVSPaymentNo/
/// CVSValidationNo) that only exist after the consumer completes store
/// selection. An OTP order that never confirmed cannot provide them, so
/// these pin the SIGNED REQUEST + judged-rejection shape with placeholder
/// codes: what must NOT happen is a MAC error, a local panic, or a local
/// validation error — the server must decode and judge the request.
/// (The exact stage rejection text is deliberately not pinned; the update
/// test captured `0|資料處理中…` for the same flow position.)
async fn judged_rejection_of_unconfirmed_c2c(
    client: &Ecpay,
    logistics_id: String,
) -> (String, String) {
    let cancel = client
        .logistics_cancel_c2c_order(&CancelC2cInput {
            all_pay_logistics_id: logistics_id.clone(),
            cvs_payment_no: "F0012345".into(),
            cvs_validation_no: "1234".into(),
        })
        .await;
    match &cancel {
        Ok(v) => assert!(v.contains_key("RtnCode"), "decoded query: {v:?}"),
        Err(ecpay::Error::Message(m)) => assert!(!m.trim().is_empty(), "protocol text: {m}"),
        Err(e) => panic!("cancel must be judged by the server, got: {e:?}"),
    }
    let update_store = client
        .logistics_update_store_info(&UpdateStoreInfoInput {
            all_pay_logistics_id: logistics_id.clone(),
            cvs_payment_no: "F0012345".into(),
            cvs_validation_no: "1234".into(),
            store_type: "01".into(),
            receiver_store_id: "006598".into(),
        })
        .await;
    match &update_store {
        Ok(v) => assert!(v.contains_key("RtnCode"), "decoded query: {v:?}"),
        Err(ecpay::Error::Message(m)) => assert!(!m.trim().is_empty(), "protocol text: {m}"),
        Err(e) => panic!("update store must be judged by the server, got: {e:?}"),
    }
    (format!("{cancel:?}"), format!("{update_store:?}"))
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn cancel_and_update_store_on_unconfirmed_order_are_judged() {
    let client = sdk();
    let created = client
        .logistics_create(&cvs_order("SBXC", 100))
        .await
        .expect("create");
    assert_eq!(created["RtnCode"], "300");
    let (cancel, update_store) =
        judged_rejection_of_unconfirmed_c2c(&client, created["AllPayLogisticsID"].clone()).await;
    println!("cancel = {cancel}");
    println!("update store = {update_store}");
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn get_store_list_answers_json() {
    let out = sdk()
        .logistics_get_store_list(&GetStoreListInput {
            cvs_type: "FAMI".into(),
        })
        .await
        .expect("GetStoreList returns JSON");
    println!(
        "store list keys = {:?}",
        out.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert!(out.is_object() || out.is_array(), "JSON response: {out}");
    // A FAMI store list is never empty on stage; an empty container means
    // the decode regressed, which must fail here rather than pass silently.
    let empty = match &out {
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(o) => o.is_empty(),
        _ => true,
    };
    assert!(!empty, "store list must carry entries: {out}");
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn allinone_v2_endpoints_answer_with_the_aes_envelope() {
    let client = sdk();
    // CreateTestData: the official smoke endpoint for the v2 envelope.
    let out = client
        .allinone_create_test_data(&AllInOneCreateTestDataInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_sub_type: "FAMI".into(),
        })
        .await
        .expect("v2 envelope accepted (TransCode gate)");
    println!("allinone create_test_data = {out:?}");
    // Live-captured shape (stage_probes 2026-09): a successful CreateTestData
    // mints a `LogisticsID` string — pin it so a shape regression fails.
    assert!(
        out["LogisticsID"].as_str().is_some_and(|s| !s.is_empty()),
        "CreateTestData must mint a LogisticsID: {out}"
    );
    let logistics_id = out["LogisticsID"].as_str().unwrap().to_owned();

    // The C2C mutation endpoints on the minted TEST order: the disposable
    // test order carries no store-confirmation codes, so these answer the
    // in-band business shape (integer RtnCode) rather than success — and if
    // stage ever DID accept one, both actions are no-ops/cleanup on the
    // disposable order itself. (ReturnCVS is deliberately NOT driven here:
    // a successful return MINTS a new stage-side return order — record-
    // creating flows stay in the manual stage_probes.) The exact rejection
    // code is server state, not pinned.
    for (name, out) in [
        (
            "cancel",
            client
                .allinone_cancel_c2c_order(&AllInOneCancelC2cInput {
                    merchant_id: MERCHANT_ID.into(),
                    logistics_id: logistics_id.clone(),
                    cvs_payment_no: "F0012345".into(),
                    cvs_validation_no: "1234".into(),
                })
                .await,
        ),
        (
            "update store",
            client
                .allinone_update_store_info(&AllInOneUpdateStoreInfoInput {
                    merchant_id: MERCHANT_ID.into(),
                    logistics_id: logistics_id.clone(),
                    cvs_payment_no: "F0012345".into(),
                    cvs_validation_no: "1234".into(),
                    store_type: "01".into(),
                    receiver_store_id: "006598".into(),
                })
                .await,
        ),
    ] {
        let v = out.expect("v2 envelope decodes (TransCode gate)");
        println!("{name} on the test order = {v:?}");
        assert!(
            v.get("RtnCode").is_some(),
            "{name}: in-band integer RtnCode required: {v}"
        );
    }

    // Query with a not-yet-existing logistics id: the server answers HTTP 500
    // with a VALID envelope (captured live 2026-09) whose Data carries the
    // business error — the client must surface that, not a bare HTTP error.
    let q = client
        .allinone_query_logistics_trade_info(&AllInOneQueryInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1".into(),
        })
        .await;
    match q {
        Ok(v) => {
            println!("allinone query (unknown id) business error = {v:?}");
            assert_eq!(v["RtnCode"], 85002, "找不到訂單: {v}");
            assert_eq!(v["RtnMsg"], "找不到訂單", "{v}");
        }
        Err(e) => panic!("non-2xx envelope must still decode, got {e:?}"),
    }
}

/// A wrong AES key is answered IN-BAND by the v2 envelope — `TransCode=712
/// 解密失敗` on AllInOne, `114 反序列化Json格式失敗` on CrossBorder (captured
/// 2026-09) — never as a transport or MAC error, which is what a caller
/// debugging their keys must see.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn wrong_aes_key_is_answered_in_band_by_the_v2_envelope() {
    let wrong_key = Ecpay::new(
        MERCHANT_ID,
        Env::Custom(Urls {
            logistics: Some(BaseUrl::new("https://logistics-stage.ecpay.com.tw/").unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_logistics_keys(Keys::new("0000000000000000", LOGISTICS_IV).unwrap());
    match wrong_key
        .allinone_query_logistics_trade_info(&AllInOneQueryInput {
            merchant_id: MERCHANT_ID.into(),
            logistics_id: "1".into(),
        })
        .await
    {
        Err(ecpay::Error::TransCode { code, msg }) => {
            assert_eq!((code, msg.as_str()), (712, "解密失敗"));
        }
        other => panic!("expected TransCode 712, got {other:?}"),
    }
    match wrong_key
        .crossborder_create_test_data(&CrossBorderCreateTestDataInput {
            merchant_id: MERCHANT_ID.into(),
            country: "SG".into(),
            logistics_type: "CB".into(),
            logistics_sub_type: "UNIMARTCBCVS".into(),
        })
        .await
    {
        Err(ecpay::Error::TransCode { code, msg }) => {
            assert_eq!((code, msg.as_str()), (114, "反序列化Json格式失敗"));
        }
        other => panic!("expected TransCode 114, got {other:?}"),
    }
}

/// The domestic form protocol's own rejections (`0|<message>`) reach the
/// caller as one shape whatever HTTP status they ride on: stage answers
/// `0|找不到訂單` and `0|CheckMacValue驗證錯誤` on HTTP 500 but `0|TimeStamp
/// Is Expired` on HTTP 200 (captured 2026-09). Before the fix the 500s
/// surfaced as a payment-family status error and the 200 as `Message` — the
/// same protocol error in two shapes.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn domestic_rejections_share_one_shape_on_any_http_status() {
    let query = |id: &str, ts: Option<i64>| DomesticQueryInput {
        all_pay_logistics_id: id.into(),
        time_stamp: ts,
    };
    let expect_rejection = |label: &str, r: Result<_, ecpay::Error>, want: &str| match r {
        Err(ecpay::Error::Message(m)) => {
            assert!(m.contains(want), "{label}: {m}");
            assert!(m.starts_with("ecpay logistics: status 0: "), "{label}: {m}");
        }
        other => panic!("{label}: expected Error::Message with {want:?}, got {other:?}"),
    };
    expect_rejection(
        "unknown id (HTTP 500)",
        sdk()
            .logistics_query_logistics_trade_info(&query("1", None))
            .await,
        "找不到訂單",
    );
    let wrong_key = Ecpay::new(
        MERCHANT_ID,
        Env::Custom(Urls {
            logistics: Some(BaseUrl::new("https://logistics-stage.ecpay.com.tw/").unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_logistics_keys(Keys::new("0000000000000000", LOGISTICS_IV).unwrap());
    expect_rejection(
        "wrong MD5 key (HTTP 500)",
        wrong_key
            .logistics_query_logistics_trade_info(&query("1", None))
            .await,
        "CheckMacValue驗證錯誤",
    );
    expect_rejection(
        "stale TimeStamp (HTTP 200)",
        sdk()
            .logistics_query_logistics_trade_info(&query("1", Some(1_600_000_000)))
            .await,
        "TimeStamp Is Expired",
    );
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn crossborder_create_test_data_answers_with_the_aes_envelope() {
    // Server-truth (2026-09): the envelope is accepted and answered in-band,
    // but public account 2000132 gets `TransCode=128 System exception` —
    // 跨境物流 appears not to be enabled for it. What this pins is that our
    // wire format speaks CrossBorder (a wrong key answers TransCode=114
    // instead — see `wrong_aes_key_is_answered_in_band_by_the_v2_envelope`).
    match sdk()
        .crossborder_create_test_data(&CrossBorderCreateTestDataInput {
            merchant_id: MERCHANT_ID.into(),
            country: "SG".into(),
            logistics_type: "CB".into(),
            logistics_sub_type: "UNIMARTCBCVS".into(),
        })
        .await
    {
        Ok(out) => println!("crossborder create_test_data = {out:?}"),
        Err(ecpay::Error::TransCode { code, msg }) => {
            println!("crossborder create_test_data TransCode answer = {code} {msg:?}");
            assert_eq!(code, 128, "captured server-truth for this account");
        }
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}
