//! ECPay **stage（沙盒）**整合測試：驗證 encode → CheckMacValue → 真實端點
//! → 回應解析的成功路徑，這部分無法用 mock 或 unreachable URL 覆蓋。
//!
//! 憑證是 ECPay 官方文件公開的 stage 測試特店（與
//! `crates/admin/tests/admin_test.rs::test_ecpay` 同一組），僅作用於
//! 沙盒環境，不是機密。測試會在 stage 帳號開立真實（沙盒）發票、查詢、
//! 再作廢，不留垃圾資料。兩個例外（皆已現場驗證、非設計疏漏）：
//! - 作廢重開測試——ECPay 5070451 規定重開後的發票需等上傳財政部狀態更新
//!   才能作廢，見該測試內的註解。
//! - 延遲開立觸發測試（`delay_issue_then_trigger_roundtrip`）——現場測試
//!   確認 `TriggerIssue` 回應 `RtnCode=4000003`（延後開立成功）後，
//!   `GetIssue` 立即查詢仍回 `RtnCode=2 查無發票資料`，代表發票本體是
//!   非同步產生的，同一測試內無法立即取得發票號碼來作廢；
//!   `折讓/合意折讓` 測試則反向驗證過——`allowance_invalid`/
//!   `allowance_invalid_by_collegiate` 後，原發票可以正常 `invalid()`，
//!   故這兩個測試都補上了清理步驟。需要對外網路。
//!
//! 付費（AIO 信用卡授權）成功路徑需要走跳轉頁輸入卡號，無法單純以
//! HTTP 自動化，不在本檔範圍。

use ecpay::{
    AllowanceByCollegiateInput, AllowanceInput, AllowanceInvalidByCollegiateInput,
    AllowanceInvalidInput, AllowanceItem, CancelDelayIssueInput, CheckBarcodeInput,
    CheckLoveCodeInput, DelayIssueInput, Ecpay, GetAllowanceInput, GetAllowanceInvalidInput,
    GetInvalidInput, GetIssueInput, InvalidInput, IssueInput, IssueModel, Item, TriggerIssueInput,
    VoidModel, VoidWithReIssueInput, INVOICE_API_URL_STAGE, PAYMENT_API_URL_STAGE,
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
/// A process-wide counter, not just a timestamp: with 7+ `#[tokio::test]`
/// functions in this file starting within the same instant, plain
/// nanosecond timestamps collided in practice (confirmed live, 2026-09:
/// ECPay rejected a duplicate RelateNumber with `RtnCode=5070353`) — clock
/// resolution isn't fine enough to guarantee uniqueness across threads that
/// all read it near-simultaneously, but a monotonic counter is.
fn unique_relate_number() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("TS{}{seq}", nanos % 100_000_000_000_000)
}

/// Shared cleanup for the allowance roundtrip tests: invalidates the
/// underlying invoice after the allowance/collegiate-allowance path is
/// exercised, so the sandbox account doesn't accumulate live invoices.
async fn cleanup_invalid(
    client: &Ecpay,
    merchant_id: String,
    invoice_no: String,
    invoice_date10: String,
) {
    let voided = client
        .invalid(&InvalidInput {
            merchant_id,
            invoice_no,
            invoice_date: invoice_date10,
            reason: "sandbox cleanup".into(),
        })
        .await
        .expect("stage invalid 應成功");
    assert_eq!(voided.rtn_code, 1, "invalid rtn_msg={}", voided.rtn_msg);
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

/// 覆蓋 AES 信封 URL 編碼（`aes_url_encode`）會出錯的字元類別：.NET/PHP
/// urlencode 的保留字元、`~`、`+`、`%`、`&`、`=`、引號、空白、多位元組。
/// 伺服器解密後 url-decode 再存檔，GetIssue 回顯的就是它實際收到的位元組。
const TRICKY_TEXT: &str = "全部!混~合*(字).-_%+&=/:'\"測試ABC123 空格";

#[tokio::test]
async fn issue_then_get_then_invalid_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();

    let relate = unique_relate_number();
    let mut input = sample_issue_input(relate.clone(), merchant_id.clone());
    input.customer_name = TRICKY_TEXT.to_owned();
    input.invoice_remark = TRICKY_TEXT.to_owned();
    input.items.as_mut().unwrap()[0].item_name = TRICKY_TEXT.to_owned();
    let issued = client.try_issue(&input).await.expect("stage issue 應成功");
    assert_eq!(issued.rtn_code, 1, "issue rtn_msg={}", issued.rtn_msg);
    assert!(!issued.invoice_no.is_empty());

    let got = client
        .get_issue(&GetIssueInput {
            merchant_id: merchant_id.clone(),
            relate_number: relate.clone(),
            ..Default::default()
        })
        .await
        .expect("stage get_issue 應成功");
    assert_eq!(got.rtn_code, 1, "get_issue rtn_msg={}", got.rtn_msg);
    assert_eq!(got.iis_number, issued.invoice_no, "查得的發票號碼應一致");
    // 逐位元組回顯：這是 aes_url_encode 對真實伺服器唯一的精確證明
    // （CheckBarcode 那類查詢只能證明解密/解碼階段通過，看不出字元是否
    // 被改寫，例如 `+` 變空白）。現場實測 2026-09 三個欄位皆原樣回顯。
    assert_eq!(got.iis_customer_name, TRICKY_TEXT, "CustomerName 回顯");
    assert_eq!(got.invoice_remark, TRICKY_TEXT, "InvoiceRemark 回顯");
    let items = got.items.as_deref().unwrap_or_default();
    assert_eq!(items.len(), 1, "Items 回顯: {items:?}");
    assert_eq!(items[0].item_name, TRICKY_TEXT, "ItemName 回顯");

    // GetIssue 的第二種查詢模式：只用 InvoiceNo + InvoiceDate（不帶
    // RelateNumber）。offline 的 conformance 測試只能證明 JSON 信封形狀
    // 正確，這裡是唯一能證明伺服器真的接受這個查詢模式的地方。
    let got_by_invoice_no = client
        .get_issue(&GetIssueInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            invoice_date: issued.invoice_date.chars().take(10).collect(),
            ..Default::default()
        })
        .await
        .expect("stage get_issue（以發票號碼查詢）應成功");
    assert_eq!(
        got_by_invoice_no.rtn_code, 1,
        "get_issue(by invoice_no) rtn_msg={}",
        got_by_invoice_no.rtn_msg
    );
    assert_eq!(got_by_invoice_no.iis_number, issued.invoice_no);

    // 作廢（Invalid 需要 yyyy-MM-dd 的開立日期），讓 stage 帳號不留
    // 未作廢的測試發票。
    let invoice_date10: String = issued.invoice_date.chars().take(10).collect();
    client
        .invalid(&InvalidInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            invoice_date: invoice_date10.clone(),
            reason: "sandbox test cleanup".to_owned(),
        })
        .await
        .expect("stage invalid 應成功");

    // GetInvalid（查詢作廢發票明細）：與 GetIssue 不同，沙盒實測(2026-09)
    // 確認 RelateNumber/InvoiceNo/InvoiceDate 三個欄位都是真的必填(不是
    // GetIssue 那種擇一模式)——留空 RelateNumber 會被伺服器拒絕
    // (RtnCode=2013001「自訂編號為必填」)，帶錯的值則查無資料
    // (RtnCode=2，都在沙盒對照驗證過，此處只斷言成功路徑)。
    let got_invalid = client
        .get_invalid(&GetInvalidInput {
            merchant_id,
            relate_number: relate,
            invoice_no: issued.invoice_no.clone(),
            invoice_date: invoice_date10,
        })
        .await
        .expect("stage get_invalid 應成功");
    assert_eq!(
        got_invalid.rtn_code, 1,
        "get_invalid rtn_msg={}",
        got_invalid.rtn_msg
    );
    assert_eq!(got_invalid.ii_invoice_no, issued.invoice_no);
}

/// `CheckLoveCode`（捐贈碼驗證）：無狀態查詢，不依賴任何先前開立的發票。
#[tokio::test]
async fn check_love_code_roundtrip() {
    let client = stage_client();
    let got = client
        .check_love_code(&CheckLoveCodeInput {
            merchant_id: client.merchant_id.clone(),
            love_code: "168001".into(), // 官方 PHP 範例 CheckLoveCode.php 用的公開測試捐贈碼
        })
        .await
        .expect("stage check_love_code 應成功");
    assert_eq!(got.rtn_code, 1, "check_love_code rtn_msg={}", got.rtn_msg);
    assert_eq!(got.is_exist, "Y");
    assert!(!got.organ_name.is_empty());
}

/// AES 信封的 URL 編碼（`aes_url_encode`：PHP urlencode 風格，`~` → `%7E`）
/// 對真實 stage server 的「解碼階段」驗證，用無狀態的 `CheckBarcode` 當
/// 探針：伺服器必須先成功解密、url-decode、JSON 解析 `Data` 才能進到商業
/// 檢查，所以每個含特殊字元的條碼都必須得到 `Ok`（TransCode=1 的商業
/// 回應：格式正確的條碼回 RtnCode=1 + IsExist，其餘回條碼格式錯誤
/// 2019001；現場實測 2026-09）。一個會產生非法 `%xx` 的編碼在這裡就會
/// 被擋下。它證明不了字元是否被改寫（例如 `+` 變空白）——那由
/// [`issue_then_get_then_invalid_roundtrip`] 的逐位元組回顯負責。
///
/// 負向對照：用錯的 invoice AES key 送同一個請求，伺服器必須拒絕
/// （現場實測 2026-09：HTTP 500 信封 TransCode=110 "The parameter [Data]
/// decrypt fail."，本函式庫以 `Err` 回報）。沒有這個對照，「全部 Ok」
/// 可能只是伺服器根本不看 Data。
///
/// 前身 `tests/check_mac_stage.rs` 宣稱在驗 CheckMacValue，但 B2C 發票
/// 端點走 AES 信封、請求裡根本沒有 CheckMacValue，其斷言（回應不含
/// "CheckMacValue" 字樣）連錯 key、空 body 都能通過，已移除。
#[tokio::test]
async fn aes_payload_encoding_survives_tricky_characters_on_stage() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let tricky: Vec<(&str, String)> = vec![
        ("plain", "ABC123".into()),
        ("chinese", "測試中文字元".into()),
        ("space", "with space".into()),
        ("tilde", "tilde~test".into()),
        ("exclamation", "excl!test".into()),
        ("star", "star*test".into()),
        ("parentheses", "paren(test)".into()),
        ("plus", "plus+test".into()),
        ("percent", "percent%test".into()),
        ("ampersand", "amp&test".into()),
        ("equals", "eq=test".into()),
        ("single-quote", "single'quote".into()),
        ("slash", "slash/test".into()),
        ("colon", "colon:test".into()),
        ("long-100-cjk", "長".repeat(100)),
        ("mixed", "全部!混~合*(字).-_%+&=/:'測試ABC123".into()),
        ("well-formed", "/1234567".into()),
    ];
    for (label, barcode) in tricky {
        let out = client
            .check_barcode(&CheckBarcodeInput {
                merchant_id: merchant_id.clone(),
                barcode: barcode.clone(),
            })
            .await
            .unwrap_or_else(|e| {
                panic!("{label}: stage rejected the AES payload for {barcode:?}: {e}")
            });
        println!("{label}: {out:?}");
        match out.rtn_code {
            // Well-formed barcode: the business answer is IsExist (stage
            // answers with an empty RtnMsg here, observed 2026-09).
            1 => assert!(
                out.is_exist == "Y" || out.is_exist == "N",
                "{label}: {out:?}"
            ),
            // Format rejection: the server decoded our exact bytes and
            // judged them, which is the encoding proof.
            2019001 => assert!(!out.rtn_msg.is_empty(), "{label}: {out:?}"),
            other => panic!("{label}: expected RtnCode 1 or 2019001, got {other}: {out:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }

    // Negative control: the same request under a wrong AES key must not
    // reach the business check.
    let wrong_key = Ecpay {
        invoice_hash_key: b"0000000000000000".to_vec(),
        ..stage_client()
    };
    let err = wrong_key
        .check_barcode(&CheckBarcodeInput {
            merchant_id,
            barcode: "/1234567".into(),
        })
        .await
        .expect_err("a payload encrypted with the wrong key must be rejected by stage");
    // Observed on stage (2026-09): HTTP 500 with a TransCode 110 envelope,
    // TransMsg "The parameter [Data] decrypt fail.". Pin the decrypt
    // rejection itself so a flake (timeout, 502, DNS) cannot pass as the
    // negative control.
    let text = err.to_string();
    assert!(
        matches!(
            err,
            ecpay::Error::InvoiceStatus { .. } | ecpay::Error::Transport { .. }
        ) && text.contains("decrypt"),
        "expected stage to reject the wrong-key payload at decrypt, got {err:?}"
    );
}

/// 折讓(Allowance)系列的沙盒回合測試：開立發票 → 開立折讓(紙本) →
/// 查詢折讓明細 → 作廢折讓 → 查詢作廢折讓明細。
///
/// `get_allowance` 是這裡驗證過兩個真實 bug 的地方(已修正，見
/// src/invoice.rs `GetAllowanceInput`/`GetAllowanceOutput` 的文件註解)：
/// 官方規格頁(7928.md)說 `AllowanceNo` 只在 `SearchType="0"` 時必填，
/// 沙盒實測卻是 `AllowanceNo` 與 `InvoiceNo` 不論 `SearchType` 為何都必填；
/// 且回應不是規格頁講的 `AllowanceInfo: Array[Object]`，而是把欄位直接
/// 攤平在最外層(單筆查詢)。offline 的 conformance 測試沒辦法測出這種
/// 「文件寫的和伺服器實際回應的形狀不一樣」的問題，只有這裡能測出來。
#[tokio::test]
async fn allowance_lifecycle_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();

    let issued = client
        .try_issue(&sample_issue_input(relate, merchant_id.clone()))
        .await
        .expect("stage issue 應成功");
    let invoice_date10: String = issued.invoice_date.chars().take(10).collect();

    let allowed = client
        .allowance(&AllowanceInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            invoice_date: invoice_date10.clone(),
            allowance_notify: "N".into(), // N:皆不通知，沙盒測試不需要真的發信
            allowance_amount: 30,
            reason: "sandbox allowance test".into(),
            items: Some(vec![AllowanceItem {
                item_seq: 1,
                item_name: "沙盒測試商品(折讓)".into(),
                item_count: 1.0,
                item_word: "個".into(),
                item_price: 30.0,
                item_tax_type: "1".into(),
                item_amount: 30.0,
            }]),
            ..Default::default()
        })
        .await
        .expect("stage allowance 應成功");
    assert_eq!(allowed.rtn_code, 1, "allowance rtn_msg={}", allowed.rtn_msg);
    assert!(!allowed.ia_allow_no.is_empty());

    let got = client
        .get_allowance(&GetAllowanceInput {
            merchant_id: merchant_id.clone(),
            search_type: "0".into(),
            allowance_no: allowed.ia_allow_no.clone(),
            invoice_no: issued.invoice_no.clone(),
            ..Default::default()
        })
        .await
        .expect("stage get_allowance 應成功");
    assert_eq!(got.rtn_code, 1, "get_allowance rtn_msg={}", got.rtn_msg);
    assert_eq!(got.ia_allow_no, allowed.ia_allow_no);
    assert_eq!(got.ia_invoice_no, issued.invoice_no);
    assert!(got.items.is_some());

    // 作廢原因(Reason)上限 20 字元。
    let invalidated = client
        .allowance_invalid(&AllowanceInvalidInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            allowance_no: allowed.ia_allow_no.clone(),
            reason: "sandbox cleanup".into(),
        })
        .await
        .expect("stage allowance_invalid 應成功");
    assert_eq!(
        invalidated.rtn_code, 1,
        "allowance_invalid rtn_msg={}",
        invalidated.rtn_msg
    );

    let got_invalid = client
        .get_allowance_invalid(&GetAllowanceInvalidInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            allowance_no: allowed.ia_allow_no,
        })
        .await
        .expect("stage get_allowance_invalid 應成功");
    assert_eq!(
        got_invalid.rtn_code, 1,
        "get_allowance_invalid rtn_msg={}",
        got_invalid.rtn_msg
    );

    cleanup_invalid(&client, merchant_id, issued.invoice_no, invoice_date10).await;
}

/// `AllowanceByCollegiate`(線上折讓/合意折讓)+`AllowanceInvalidByCollegiate`
/// (取消線上折讓)的沙盒回合測試。後者官方 PHP SDK 沒有對應範例(容易誤用
/// `AllowanceInvalid` 取消)，是規格頁(7913.md)才記載的獨立端點，這裡是
/// 唯一驗證過它真的存在且能在客戶確認前取消的地方。
#[tokio::test]
async fn allowance_by_collegiate_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();

    let issued = client
        .try_issue(&sample_issue_input(relate, merchant_id.clone()))
        .await
        .expect("stage issue 應成功");
    let invoice_date10: String = issued.invoice_date.chars().take(10).collect();

    let allowed = client
        .allowance_by_collegiate(&AllowanceByCollegiateInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            invoice_date: invoice_date10.clone(),
            allowance_notify: "E".into(), // 規格固定值
            customer_name: "測試消費者".into(),
            notify_mail: "test-allowance@ecpay.com.tw".into(),
            allowance_amount: 30,
            reason: "sandbox collegiate allowance test".into(),
            return_url: "https://example.com/ecpay/allowance-return".into(),
            items: Some(vec![AllowanceItem {
                item_seq: 1,
                item_name: "沙盒測試商品(合意折讓)".into(),
                item_count: 1.0,
                item_word: "個".into(),
                item_price: 30.0,
                item_tax_type: "1".into(),
                item_amount: 30.0,
            }]),
        })
        .await
        .expect("stage allowance_by_collegiate 應成功");
    assert_eq!(
        allowed.rtn_code, 1,
        "allowance_by_collegiate rtn_msg={}",
        allowed.rtn_msg
    );
    assert!(!allowed.ia_allow_no.is_empty());

    let cancelled = client
        .allowance_invalid_by_collegiate(&AllowanceInvalidByCollegiateInput {
            merchant_id: merchant_id.clone(),
            invoice_no: issued.invoice_no.clone(),
            allowance_no: allowed.ia_allow_no,
            reason: "sandbox cleanup".into(),
        })
        .await
        .expect("stage allowance_invalid_by_collegiate 應成功");
    assert_eq!(
        cancelled.rtn_code, 1,
        "allowance_invalid_by_collegiate rtn_msg={}",
        cancelled.rtn_msg
    );

    cleanup_invalid(&client, merchant_id, issued.invoice_no, invoice_date10).await;
}

fn sample_delay_issue_input(
    relate_number: String,
    merchant_id: String,
    tsr: String,
) -> DelayIssueInput {
    DelayIssueInput {
        merchant_id,
        relate_number,
        customer_email: "sandbox@example.com".into(),
        customer_phone: "0912345678".into(),
        print: "0".into(),
        donation: "0".into(),
        tax_type: "1".into(),
        sales_amount: 100,
        inv_type: "07".into(),
        items: Some(vec![Item {
            item_name: "沙盒測試商品(延遲開立)".into(),
            item_count: 1.0,
            item_word: "個".into(),
            item_price: 100.0,
            item_amount: 100.0,
            item_tax_type: "1".into(),
            ..Default::default()
        }]),
        delay_flag: "1".into(), // 1:延遲開立，等候手動觸發
        delay_day: 15,
        tsr,
        pay_type: "2".into(),    // 規格固定值
        pay_act: "ECPAY".into(), // 規格固定值
        ..Default::default()
    }
}

/// `DelayIssue`（延遲開立）+ `TriggerIssue`（觸發開立）的沙盒回合測試。
///
/// `TriggerIssue` 沒有單一的成功代碼：沙盒實測確認規格頁記載的
/// `RtnCode=4000003`(延後開立成功)/`4000004`(立即開立成功)，不是像其他
/// 指令類 API 那樣以 `1` 為成功，故 `Ecpay::trigger_issue` 不用
/// [`ecpay::Error::Api`] 判斷，這裡直接檢查 RtnCode 屬於這兩者之一。
#[tokio::test]
async fn delay_issue_then_trigger_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();
    let tsr = format!("tsr{}", unique_relate_number());

    let delayed = client
        .delay_issue(&sample_delay_issue_input(
            relate,
            merchant_id.clone(),
            tsr.clone(),
        ))
        .await
        .expect("stage delay_issue 應成功");
    assert_eq!(
        delayed.rtn_code, 1,
        "delay_issue rtn_msg={}",
        delayed.rtn_msg
    );
    assert_eq!(delayed.order_number, tsr);

    let triggered = client
        .trigger_issue(&TriggerIssueInput {
            merchant_id,
            tsr: tsr.clone(),
            pay_type: "2".into(),
        })
        .await
        .expect("stage trigger_issue 應成功");
    assert!(
        triggered.rtn_code == 4_000_003 || triggered.rtn_code == 4_000_004,
        "trigger_issue rtn_code={} rtn_msg={}",
        triggered.rtn_code,
        triggered.rtn_msg
    );
    assert_eq!(triggered.tsr, tsr);
}

/// `DelayIssue` + `CancelDelayIssue`（取消延遲開立）的沙盒回合測試。
#[tokio::test]
async fn delay_issue_then_cancel_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();
    let tsr = format!("tsrc{}", unique_relate_number());

    let delayed = client
        .delay_issue(&sample_delay_issue_input(
            relate,
            merchant_id.clone(),
            tsr.clone(),
        ))
        .await
        .expect("stage delay_issue 應成功");
    assert_eq!(
        delayed.rtn_code, 1,
        "delay_issue rtn_msg={}",
        delayed.rtn_msg
    );

    let cancelled = client
        .cancel_delay_issue(&CancelDelayIssueInput { merchant_id, tsr })
        .await
        .expect("stage cancel_delay_issue 應成功");
    assert_eq!(
        cancelled.rtn_code, 1,
        "cancel_delay_issue rtn_msg={}",
        cancelled.rtn_msg
    );
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
