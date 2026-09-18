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
    AllInOneCreateTestDataInput, AllInOneQueryInput, CrossBorderCreateTestDataInput,
    DomesticQueryInput, GetStoreListInput, LogisticsCreateInput,
};
use ecpay::Ecpay;
mod common;
use common::sandbox::{taipei_now, taipei_today, unique_no};

const MERCHANT_ID: &str = "2000132";
const LOGISTICS_KEY: &str = "5294y06JbISpM5x9";
const LOGISTICS_IV: &str = "v77hoKGq4kWxNNIS";

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        logistics_api_url: "https://logistics-stage.ecpay.com.tw/".into(),
        logistics_hash_key: LOGISTICS_KEY.to_owned(),
        logistics_hash_iv: LOGISTICS_IV.to_owned(),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn domestic_create_then_query_roundtrip() {
    let client = sdk();
    let out = client
        .logistics_create(&LogisticsCreateInput {
            merchant_trade_no: unique_no("SBX"),
            merchant_trade_date: taipei_now(),
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
        })
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
    assert!(!info.contains_key("_status_prefix"));
}

#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox_logistics -- --ignored --nocapture"]
async fn domestic_create_update_shipment_query_chain() {
    // One live order taken through create → UpdateShipmentInfo → query:
    // three signed round-trips against stage on the same order.
    let client = sdk();
    let created = client
        .logistics_create(&LogisticsCreateInput {
            merchant_trade_no: unique_no("SBXU"),
            merchant_trade_date: taipei_now(),
            logistics_type: "CVS".into(),
            logistics_sub_type: "FAMI".into(),
            goods_amount: 500,
            goods_name: "綠界 SDK 範例商品".into(),
            sender_name: "陳大明".into(),
            sender_cell_phone: "0911222333".into(),
            receiver_name: "王小美".into(),
            receiver_cell_phone: "0933222111".into(),
            receiver_store_id: Some("006598".into()),
            server_reply_url: "https://www.ecpay.com.tw/example/server-reply".into(),
            ..Default::default()
        })
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
        Ok(v) => println!("update accepted = {v:?}"),
        Err(ecpay::Error::Message(m)) => {
            println!("update rejected while 資料處理中: {m}");
            assert!(
                m.contains("無法更新") || m.contains("處理中"),
                "documented OTP-flow rejection, got: {m}"
            );
        }
        Err(e) => panic!("unexpected error: {e:?}"),
    }

    let info = client
        .logistics_query_logistics_trade_info(&DomesticQueryInput {
            all_pay_logistics_id: logistics_id,
            time_stamp: None,
        })
        .await
        .expect("query after update");
    println!("query after update = {info:?}");
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
    let wrong_key = Ecpay {
        logistics_hash_key: "0000000000000000".into(),
        ..sdk()
    };
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
    let wrong_key = Ecpay {
        logistics_hash_key: "0000000000000000".into(),
        ..sdk()
    };
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
