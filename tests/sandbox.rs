//! ECPay **stage（沙盒）**整合測試：驗證 encode → CheckMacValue → 真實端點
//! → 回應解析的成功路徑，這部分無法用 mock 或 unreachable URL 覆蓋。
//!
//! 憑證是 ECPay 官方文件公開的 stage 測試特店（與
//! `crates/admin/tests/admin_test.rs::test_ecpay` 同一組），僅作用於
//! 沙盒環境，不是機密。測試會在 stage 帳號開立真實（沙盒）發票、查詢、
//! 再作廢，不留垃圾資料(作廢重開測試除外——ECPay 5070451 規定重開後的
//! 發票需等上傳財政部狀態更新才能作廢，見該測試內的註解)。需要對外網路。
//!
//! 付費（AIO 信用卡授權）成功路徑需要走跳轉頁輸入卡號，無法單純以
//! HTTP 自動化，不在本檔範圍。

use ecpay::{
    Ecpay, GetIssueInput, InvalidInput, IssueInput, IssueModel, Item, VoidModel,
    VoidWithReIssueInput, INVOICE_API_URL_STAGE, PAYMENT_API_URL_STAGE,
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

/// `VoidWithReIssue`（作廢重開）的沙盒回合測試：Data 信封是巢狀的
/// `{VoidModel, IssueModel}`（不是像 Issue/Invalid 那樣扁平），且真實端點
/// 是 `/B2CInvoice/VoidWithReIssue`（官方 Go 移植原始檔誤植為
/// `VoidWithIssue`，打上去只會拿到 ECPay 的一般錯誤頁，見 src/invoice.rs
/// module doc）。這兩點若配置錯，之前只用 mock transport 的測試完全測不出來。
#[tokio::test]
async fn issue_then_void_with_reissue_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();

    let relate = unique_relate_number();
    let issued = client
        .try_issue(&sample_issue_input(relate, merchant_id.clone()))
        .await
        .expect("stage issue 應成功");
    assert_eq!(issued.rtn_code, 1, "issue rtn_msg={}", issued.rtn_msg);

    // ECPay 沙盒實測(2026-09):重開後的新發票沿用舊 RelateNumber 查詢
    // (IssueModel.RelateNumber 在作廢重開時不生效),所以這裡送新值僅為
    // 符合欄位必填,不用於後續查詢。
    let reissued = client
        .void_with_reissue(&VoidWithReIssueInput {
            void_model: VoidModel {
                merchant_id: merchant_id.clone(),
                invoice_no: issued.invoice_no.clone(),
                void_reason: "sandbox void test".to_owned(), // VoidReason 上限 20 字元
            },
            issue_model: IssueModel {
                merchant_id: merchant_id.clone(),
                relate_number: unique_relate_number(),
                invoice_date: issued.invoice_date.clone(),
                customer_email: "sandbox@example.com".to_owned(),
                print: "0".to_owned(),
                donation: "0".to_owned(),
                tax_type: "1".to_owned(),
                sales_amount: 100,
                inv_type: "07".to_owned(),
                items: Some(vec![Item {
                    item_name: "沙盒測試商品(重開)".to_owned(),
                    item_count: 1.0,
                    item_word: "個".to_owned(),
                    item_price: 100.0,
                    item_amount: 100.0,
                    ..Default::default()
                }]),
                ..Default::default()
            },
        })
        .await
        .expect("stage void_with_reissue 應成功");
    // 沙盒實測(2026-09):重開後回傳的發票號碼有時與原發票相同、有時不同,
    // 行為不穩定,不在本測試斷言範圍內；這裡只驗證呼叫本身成功
    // (RtnCode=1),證明端點路徑與 Data 信封形狀（VoidModel + IssueModel
    // 巢狀結構）是正確的。
    assert_eq!(
        reissued.rtn_code, 1,
        "void_with_reissue rtn_msg={}",
        reissued.rtn_msg
    );
    assert!(!reissued.invoice_no.is_empty());

    // 註：與其他測試不同，這裡不再呼叫 invalid() 清理重開後的新發票。
    // 沙盒實測(2026-09):立刻作廢會得到 ECPay 5070451「註銷重開的發票請於
    // 上傳財政部狀態更新後，再嘗試作廢」——這是 ECPay 端的非同步批次上傳
    // 限制，不是本函式庫能控制的時序，故此處刻意省略清理。
}
