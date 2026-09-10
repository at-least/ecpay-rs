//! Live logistics tests against the ECPay stage server (public test account
//! 2000132). Like `tests/sandbox.rs`, these run on every `cargo test` and
//! need outbound network; they create real stage logistics orders.
//!
//! Wire-format facts pinned here were first captured by the probes in
//! `tests/stage_probes.rs` (commit ed87553) and are now asserted:
//! `Express/Create` answers `1|<signed query>` with RtnCode=300 for a fresh
//! B2C CVS order.

use ecpay::logistics::{
    AllInOneCreateTestDataInput, AllInOneQueryInput, DomesticQueryInput, GetStoreListInput,
    LogisticsCreateInput,
};
use ecpay::Ecpay;

const MERCHANT_ID: &str = "2000132";
const LOGISTICS_KEY: &[u8] = b"5294y06JbISpM5x9";
const LOGISTICS_IV: &[u8] = b"v77hoKGq4kWxNNIS";

fn unique_no(tag: &str) -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{tag}{n}")
}

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        logistics_api_url: "https://logistics-stage.ecpay.com.tw/".into(),
        logistics_hash_key: LOGISTICS_KEY.to_vec(),
        logistics_hash_iv: LOGISTICS_IV.to_vec(),
        ..Default::default()
    }
}

#[tokio::test]
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
    assert_eq!(out["RtnCode"], "300", "訂單處理中 = accepted (stage OTP 流程)");
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
async fn get_store_list_answers_json() {
    let out = sdk()
        .logistics_get_store_list(&GetStoreListInput { cvs_type: "FAMI".into() })
        .await
        .expect("GetStoreList returns JSON");
    println!(
        "store list keys = {:?}",
        out.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert!(out.is_object() || out.is_array(), "JSON response: {out}");
}

#[tokio::test]
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
            assert!(v.get("RtnCode").is_some(), "decoded business error: {v}");
        }
        Err(e) => panic!("non-2xx envelope must still decode, got {e:?}"),
    }
}

fn taipei_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 8 * 3600; // UTC+8
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
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
