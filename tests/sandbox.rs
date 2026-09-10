//! ECPay **stage（沙盒）**整合測試：驗證 encode → CheckMacValue → 真實端點
//! → 回應解析的成功路徑，這部分無法用 mock 或 unreachable URL 覆蓋。
//!
//! 憑證只從環境變數讀取，絕不簽入 repo。未設定時測試直接跳過（通過），
//! 一般 `cargo test` 不需要網路與憑證。實際執行：
//!
//! ```sh
//! ECPAY_STAGE_MERCHANT_ID=2000132 \
//! ECPAY_STAGE_HASH_KEY=... ECPAY_STAGE_HASH_IV=... \
//! ECPAY_STAGE_INVOICE_HASH_KEY=... ECPAY_STAGE_INVOICE_HASH_IV=... \
//! cargo test --test sandbox -- --nocapture
//! ```
//!
//! 測試會在 stage 帳號開立真實（沙盒）發票、查詢、再作廢，不留垃圾資料。
//! 付費（AIO 信用卡授權）成功路徑需要走跳轉頁輸入卡號，無法單純以
//! HTTP 自動化，不在本檔範圍。

use ecpay::{
    Ecpay, GetIssueInput, InvalidInput, IssueInput, INVOICE_API_URL_STAGE, Item,
    PAYMENT_API_URL_STAGE,
};

fn stage_client() -> Option<Ecpay> {
    let merchant_id = std::env::var("ECPAY_STAGE_MERCHANT_ID").unwrap_or_default();
    let hash_key = std::env::var("ECPAY_STAGE_HASH_KEY").unwrap_or_default();
    let hash_iv = std::env::var("ECPAY_STAGE_HASH_IV").unwrap_or_default();
    let inv_key = std::env::var("ECPAY_STAGE_INVOICE_HASH_KEY").unwrap_or_default();
    let inv_iv = std::env::var("ECPAY_STAGE_INVOICE_HASH_IV").unwrap_or_default();
    if merchant_id.is_empty()
        || hash_key.is_empty()
        || hash_iv.is_empty()
        || inv_key.is_empty()
        || inv_iv.is_empty()
    {
        eprintln!("skip sandbox tests: ECPAY_STAGE_* environment variables not set");
        return None;
    }
    Some(Ecpay {
        merchant_id,
        hash_key,
        hash_iv,
        payment_api_url: PAYMENT_API_URL_STAGE.to_string(),
        invoice_api_url: INVOICE_API_URL_STAGE.to_string(),
        invoice_hash_key: inv_key.into_bytes(),
        invoice_hash_iv: inv_iv.into_bytes(),
        ..Default::default()
    })
}

/// ECPay 要求特店自訂編號唯一不可重複：用時間戳尾數保證。
fn unique_relate_number() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    format!("TS{}", &nanos[nanos.len().saturating_sub(14)..])
}

fn sample_issue_input(relate_number: String, merchant_id: String) -> IssueInput {
    IssueInput {
        merchant_id,
        relate_number,
        customer_email: "sandbox@example.com".to_owned(),
        customer_phone: "0912345678".to_owned(),
        print: "0".to_owned(),
        donation: "0".to_owned(),
        tax_type: "1".to_owned(),
        sales_amount: 100,
        inv_type: "07".to_owned(),
        items: Some(vec![Item {
            item_name: "沙盒測試商品".to_owned(),
            item_count: 1.0,
            item_word: "個".to_owned(),
            item_price: 100.0,
            item_amount: 100.0,
            ..Default::default()
        }]),
        ..Default::default()
    }
}

#[tokio::test]
async fn issue_then_get_then_invalid_roundtrip() {
    let Some(client) = stage_client() else { return };

    let relate = unique_relate_number();
    let input = sample_issue_input(relate.clone(), client.merchant_id.clone());

    let issued = client.try_issue(&input).await.expect("stage issue 應成功");
    assert_eq!(issued.rtn_code, 1, "issue rtn_msg={}", issued.rtn_msg);
    assert!(!issued.invoice_no.is_empty());

    let got = client
        .get_issue(&GetIssueInput {
            merchant_id: client.merchant_id.clone(),
            relate_number: relate,
        })
        .await
        .expect("stage get_issue 應成功");
    assert_eq!(got.rtn_code, 1, "get_issue rtn_msg={}", got.rtn_msg);
    assert_eq!(got.iis_number, issued.invoice_no, "查得的發票號碼應一致");

    // 作廢（Invalid 需要 yyyy-MM-dd 的開立日期），讓 stage 帳號不留
    // 未作廢的測試發票。
    client
        .invalid(&InvalidInput {
            merchant_id: client.merchant_id.clone(),
            invoice_no: issued.invoice_no,
            invoice_date: issued.invoice_date.chars().take(10).collect(),
            reason: "sandbox test cleanup".to_owned(),
        })
        .await
        .expect("stage invalid 應成功");
}

#[test]
fn sandbox_gate_documents_required_variables() {
    // 未設定憑證時，stage_client 回 None 並跳過——本測試固定通過，
    // 用來防止 gate 條件被意外改壞（例如變數名稱打錯仍視為已設定）。
    if std::env::var("ECPAY_STAGE_MERCHANT_ID").is_ok() {
        return; // 有憑證的環境不適用此反向斷言。
    }
    assert!(stage_client().is_none());
}
