//! ECPay **stage（沙盒）**整合測試：驗證 encode → CheckMacValue → 真實端點
//! → 回應解析的成功路徑，這部分無法用 mock 或 unreachable URL 覆蓋。
//!
//! 憑證是 ECPay 官方文件公開的 stage 測試特店（與
//! `crates/admin/tests/admin_test.rs::test_ecpay` 同一組），僅作用於
//! 沙盒環境，不是機密。測試會在 stage 帳號開立真實（沙盒）發票、查詢、
//! 再作廢，不留垃圾資料。需要對外網路。
//!
//! 付費（AIO 信用卡授權）成功路徑需要走跳轉頁輸入卡號，無法單純以
//! HTTP 自動化，不在本檔範圍。

use ecpay::{
    Ecpay, GetIssueInput, InvalidInput, IssueInput, INVOICE_API_URL_STAGE, Item,
    PAYMENT_API_URL_STAGE,
};

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
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();

    let relate = unique_relate_number();
    let issued = client
        .try_issue(&sample_issue_input(relate.clone(), merchant_id.clone()))
        .await
        .expect("stage issue 應成功");
    assert_eq!(issued.rtn_code, 1, "issue rtn_msg={}", issued.rtn_msg);
    assert!(!issued.invoice_no.is_empty());

    let got = client
        .get_issue(&GetIssueInput {
            merchant_id: merchant_id.clone(),
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
            merchant_id,
            invoice_no: issued.invoice_no,
            invoice_date: issued.invoice_date.chars().take(10).collect(),
            reason: "sandbox test cleanup".to_owned(),
        })
        .await
        .expect("stage invalid 應成功");
}
