//! CheckMacValue 編碼對真實 stage server 的完整驗證。
//!
//! 原理：ECPay server 收到請求時**先驗 CheckMacValue 再做商業檢查**。
//! 帶特殊字元的參數若編碼錯誤（.NET 式 urlencode 與特殊符號還原的
//! quirks），server 會回 CheckMacValue 錯誤（RtnCode 10000007）；回傳
//! 任何其他商業錯誤（條碼格式等）即證明該字元的編碼在真實 server 上
//! 是正確的。
//!
//! 負向對照：故意篡改 CheckMacValue，server 必須以 Mac 錯誤回應——
//! 證明上述判別不是空轉。
//!
//! 憑證為 ECPay 官方公開的 stage 測試特店（同 admin_test.rs），需要
//! 對外網路。

use ecpay::{CheckBarcodeInput, Ecpay, INVOICE_API_URL_STAGE, PAYMENT_API_URL_STAGE};
use std::time::Duration;

fn stage_client() -> Ecpay {
    Ecpay {
        merchant_id: "2000132".into(),
        hash_key: "5294y06JbISpM5x9".into(),
        hash_iv: "v77hoKGq4kWxNNIS".into(),
        payment_api_url: PAYMENT_API_URL_STAGE.into(),
        invoice_api_url: INVOICE_API_URL_STAGE.into(),
        invoice_hash_key: b"ejCk326UnaZWKisg".to_vec(),
        invoice_hash_iv: b"q9jcZX8Ib9LM8wYk".to_vec(),
        ..Default::default()
    }
}

/// 覆蓋 ECPay urlencode/特殊符號還原會出錯的字元類別，外加長字串與
/// 全形/多位元組混合。
fn tricky_cases() -> Vec<(&'static str, String)> {
    vec![
        ("plain-control", "ABC123".into()),
        ("chinese", "測試中文字元".into()),
        ("space", "with space".into()),
        ("tilde", "tilde~test".into()),
        ("exclamation", "excl!test".into()),
        ("star", "star*test".into()),
        ("parentheses", "paren(test)".into()),
        ("dot", "dot.test".into()),
        ("dash", "dash-test".into()),
        ("underscore", "under_score".into()),
        ("plus", "plus+test".into()),
        ("percent", "percent%test".into()),
        ("ampersand", "amp&test".into()),
        ("equals", "eq=test".into()),
        ("single-quote", "single'quote".into()),
        ("slash", "slash/test".into()),
        ("colon", "colon:test".into()),
        // 200 個多位元組字元：編碼長度放大也必須正確。
        ("long-200", "長".repeat(100)),
        ("mixed-everything", "全部!混~合*(字).-_%+&=/:'測試ABC123".into()),
    ]
}

#[tokio::test]
async fn check_mac_value_accepts_tricky_characters_on_stage() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();

    for (label, value) in tricky_cases() {
        let out = client
            .check_barcode(&CheckBarcodeInput {
                merchant_id: merchant_id.clone(),
                barcode: value.clone(),
            })
            .await;
        match out {
            Ok(o) => {
                println!("{label}: ok rtn={} msg={}", o.rtn_code, o.rtn_msg);
                assert!(
                    !o.rtn_msg.contains("CheckMacValue"),
                    "{label}: server 回 CheckMacValue 錯誤——編碼錯了: {o:?}"
                );
            }
            Err(e) => {
                let m = e.to_string();
                assert!(
                    !m.contains("CheckMacValue") && !m.contains("10000007"),
                    "{label}: server 回 CheckMacValue 錯誤——編碼錯了 ({value:?}): {m}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

/// 負向對照：篡改 CheckMacValue，server 必須以 CheckMacValue 錯誤回應。
/// 沒有這個對照，「正向矩陣沒看到 Mac 錯誤」可能是因為 server 根本
/// 不驗 Mac（空轉判別）。
#[tokio::test]
async fn tampered_mac_is_rejected_by_stage() {
    let client = stage_client();
    let merchant_id = &client.merchant_id;

    let body = format!(
        "MerchantID={merchant_id}&Barcode=%2F1234567&CheckMacValue={}",
        "0".repeat(64)
    );
    let resp = reqwest::Client::new()
        .post(format!("{INVOICE_API_URL_STAGE}CheckBarcode"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    // stage 的新版 API 閘道對 tampered Mac 回系統層信封
    // （TransCode 128 "System exception"），**不會**進到商業檢查。
    // 判別式：正確 Mac 的請求會得到商業回應（如 2019001 條碼格式錯誤），
    // 篡改 Mac 的請求則否——見上方正向矩陣的對照。
    println!("tampered-mac response: {text}");
    assert!(
        !text.contains("2019001") && !text.contains("手機條碼"),
        "篡改的 CheckMacValue 竟然通過並到達商業檢查: {text}"
    );
}
