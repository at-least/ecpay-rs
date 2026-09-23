//! Vectors from ECPay's OWN AI-skill repository
//! (github.com/ECPay/ECPay-API-Skill, test-vectors/checkmacvalue.json,
//! maintained by ECPay's team; available in this repo as the
//! `.claude/skills/ecpay` git submodule, commit ae964f7 2026-09-01).
//! These are ECPay's current official test
//! vectors — note the tilde vector's note: "ecpayUrlEncode 會將 ~ 編碼為
//! %7e", confirming the Python SDK's literal-~ behavior is the deviation.

use std::collections::HashMap;

fn cmv(params: &[(&str, &str)], key: &str, iv: &str, t: ecpay::EncryptType) -> String {
    let m: HashMap<String, String> = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    ecpay::check_mac_value(&m, key, iv, t)
}

#[test]
fn official_skill_vectors() {
    // SHA256 基本測試(AIO 金流)
    assert_eq!(
        cmv(
            &[
                ("MerchantID", "3002607"),
                ("MerchantTradeNo", "Test1234567890"),
                ("MerchantTradeDate", "2025/01/01 12:00:00"),
                ("PaymentType", "aio"),
                ("TotalAmount", "100"),
                ("TradeDesc", "測試"),
                ("ItemName", "測試商品"),
                ("ReturnURL", "https://example.com/notify"),
                ("ChoosePayment", "ALL"),
                ("EncryptType", "1"),
            ],
            "pwFHCqoQZGmho4w6",
            "EkRm7iFT261dpevs",
            ecpay::EncryptType::Sha256
        ),
        "291CBA324D31FB5A4BBBFDF2CFE5D32598524753AFD4959C3BF590C5B2F57FB2"
    );
    // MD5 測試(國內物流)
    assert_eq!(
        cmv(
            &[
                ("MerchantID", "2000132"),
                ("LogisticsType", "CVS"),
                ("LogisticsSubType", "UNIMART"),
                ("MerchantTradeDate", "2025/01/01 12:00:00"),
            ],
            "5294y06JbISpM5x9",
            "v77hoKGq4kWxNNIS",
            ecpay::EncryptType::Md5
        ),
        "545E6146FD45BDA683C88454DB34CE8D"
    );
    // 特殊字元 ' 測試
    assert_eq!(
        cmv(
            &[
                ("MerchantID", "3002607"),
                ("ItemName", "Tom's Shop"),
                ("TotalAmount", "100"),
            ],
            "pwFHCqoQZGmho4w6",
            "EkRm7iFT261dpevs",
            ecpay::EncryptType::Sha256
        ),
        "CF0A3D4901D99459D8641516EC57210700E8A5C9AB26B1D021301E9CB93EF78D"
    );
    // 特殊字元 ~ 測試:官方明文 ecpayUrlEncode 將 ~ 編碼為 %7e
    assert_eq!(
        cmv(
            &[
                ("MerchantID", "3002607"),
                ("ItemName", "Test~Product"),
                ("TotalAmount", "200"),
            ],
            "pwFHCqoQZGmho4w6",
            "EkRm7iFT261dpevs",
            ecpay::EncryptType::Sha256
        ),
        "CEEAE01D2F9A8E74D4AC0DCE7735B046D73F35A5EC99558A31A2EE03159DA1C9"
    );
}
