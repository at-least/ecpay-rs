//! ECPay **stage（沙盒）**整合測試：驗證 encode → AES 信封 → 真實端點
//! → 回應解析的成功路徑，這部分無法用 mock 或 unreachable URL 覆蓋。
//! （本檔全部走 B2C 發票的 AES-JSON 信封端點—— CheckMacValue 的 live
//! 覆蓋在 `tests/sandbox_logistics.rs`（MD5 回呼）與 `stage_smoke`。）
//!
//! 憑證是 ECPay 官方公開的 stage 測試特店 2000132/3002607（ECPay-API-Skill
//! submodule `.claude/skills/ecpay` 的 AGENTS.md 即列出同一組），僅作用於
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
//!   故這兩個測試都補上了清理步驟。
//!
//! 每個測試皆 `#[ignore]`（預設 `cargo test` 完全離線），執行需對外網路：
//! `cargo test --test sandbox -- --ignored --nocapture`。
//!
//! 付費（AIO 信用卡授權）成功路徑需要走跳轉頁輸入卡號，無法單純以
//! HTTP 自動化，不在本檔範圍。

use ecpay::{
    AllowanceByCollegiateInput, AllowanceInput, AllowanceInvalidByCollegiateInput,
    AllowanceInvalidInput, AllowanceItem, CancelDelayIssueInput, CheckBarcodeInput,
    CheckLoveCodeInput, DelayIssueInput, Ecpay, Error, GetAllowanceInput, GetAllowanceInvalidInput,
    GetInvalidInput, GetIssueInput, InvalidInput, IssueInput, IssueModel, Item, TriggerIssueInput,
    VoidModel, VoidWithReIssueInput, INVOICE_API_URL_STAGE, PAYMENT_API_URL_STAGE,
};

fn stage_client() -> Ecpay {
    Ecpay {
        merchant_id: "2000132".into(),
        // Inert placeholders: every test in this file calls invoice-family
        // APIs (invoice_hash_key below), which ignore the payment pair. The
        // values are the LOGISTICS pair, not an AIO credential for 2000132 —
        // kept explicit so an AIO call added here fails loudly at a wrong-key
        // MAC instead of looking configured.
        hash_key: "5294y06JbISpM5x9".into(),
        hash_iv: "v77hoKGq4kWxNNIS".into(),
        payment_api_url: PAYMENT_API_URL_STAGE.into(),
        invoice_api_url: INVOICE_API_URL_STAGE.into(),
        invoice_hash_key: "ejCk326UnaZWKisg".into(),
        invoice_hash_iv: "q9jcZX8Ib9LM8wYk".into(),
        ..Default::default()
    }
}

/// ECPay 要求特店自訂編號唯一不可重複：用時間戳尾數保證。
/// A process-wide counter, not just a timestamp: with 7+ `#[tokio::test]`
/// functions in this file starting within the same instant, plain
/// nanosecond timestamps collided in practice (confirmed live, 2026-09:
/// ECPay rejected the duplicate RelateNumber; the code stage answers today,
/// 5070357, is pinned by `issue_lifecycle_error_contracts`) — clock
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
        print: "0".into(),
        donation: "0".into(),
        tax_type: "1".into(),
        sales_amount: 100,
        inv_type: "07".into(),
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn issue_then_get_then_invalid_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();

    let relate = unique_relate_number();
    let mut input = sample_issue_input(relate.clone(), merchant_id.clone());
    input.customer_name = TRICKY_TEXT.to_owned();
    input.invoice_remark = TRICKY_TEXT.to_owned();
    input.items.as_mut().unwrap()[0].item_name = TRICKY_TEXT.to_owned();
    let issued = client.issue(&input).await.expect("stage issue 應成功");
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

/// One invoice taken through every documented error contract of its
/// lifecycle — the codes an integration branches on, each captured live
/// (2026-09) and pinned here so a server-side change is noticed:
/// duplicate RelateNumber, GetIssue's key-presence query mode, a second
/// Invalid, and GetInvalid's truly-required RelateNumber.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn issue_lifecycle_error_contracts() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();
    let issued = client
        .issue(&sample_issue_input(relate.clone(), merchant_id.clone()))
        .await
        .expect("stage issue 應成功");
    let invoice_date10: String = issued.invoice_date.chars().take(10).collect();

    // RelateNumber is unique per merchant: re-issuing is a business error,
    // not a second invoice.
    let dup = client
        .issue(&sample_issue_input(relate.clone(), merchant_id.clone()))
        .await
        .expect_err("a duplicate RelateNumber must not issue again");
    match &dup {
        Error::Api(e) => assert_eq!(e.code, 5070357, "{e}"),
        other => panic!("expected Error::Api, got {other:?}"),
    }

    // GetIssue picks its query mode by KEY PRESENCE, not by value: the same
    // RelateNumber query fails (RtnCode=2) once empty InvoiceNo/InvoiceDate
    // keys ride along — the reason `GetIssueInput` omits empty fields
    // instead of sending "" like the rest of the invoice structs.
    let with_empty_keys: serde_json::Value = client
        .call_invoice_api(
            "GetIssue",
            &serde_json::json!({
                "MerchantID": merchant_id,
                "RelateNumber": relate,
                "InvoiceNo": "",
                "InvoiceDate": "",
            }),
        )
        .await
        .expect("decodes");
    assert_eq!(with_empty_keys["RtnCode"], 2, "{with_empty_keys}");
    let typed = client
        .get_issue(&GetIssueInput {
            merchant_id: merchant_id.clone(),
            relate_number: relate.clone(),
            ..Default::default()
        })
        .await
        .expect("stage get_issue 應成功");
    assert_eq!(typed.rtn_code, 1, "{}", typed.rtn_msg);
    assert_eq!(typed.iis_number, issued.invoice_no);
    // An unknown RelateNumber is RtnCode=2 in the body, not an error
    // (`get_issue` is a query; only the command calls map RtnCode to
    // `Error::Api`).
    let unknown = client
        .get_issue(&GetIssueInput {
            merchant_id: merchant_id.clone(),
            relate_number: format!("NOSUCH{relate}"),
            ..Default::default()
        })
        .await
        .expect("stage get_issue 應成功");
    assert_eq!(unknown.rtn_code, 2, "{}", unknown.rtn_msg);

    // Invalid.Reason is capped at 20 characters (2009005 作廢原因長度錯誤 —
    // learned live when this test's first reason was 21 chars long).
    let invalid = InvalidInput {
        merchant_id: merchant_id.clone(),
        invoice_no: issued.invoice_no.clone(),
        invoice_date: invoice_date10.clone(),
        reason: "sandbox contract test".into(), // 21 chars
    };
    match client.invalid(&invalid).await {
        Err(Error::Api(e)) => assert_eq!(e.code, 2009005, "{e}"),
        other => panic!("a 21-char reason must be refused, got {other:?}"),
    }
    let invalid = InvalidInput {
        reason: "sandbox contract".into(),
        ..invalid
    };
    client
        .invalid(&invalid)
        .await
        .expect("stage invalid 應成功");
    let again = client
        .invalid(&invalid)
        .await
        .expect_err("a second Invalid must be refused");
    match &again {
        Error::Api(e) => assert_eq!(e.code, 5070453, "{e}"),
        other => panic!("expected Error::Api, got {other:?}"),
    }

    // GetInvalid: RelateNumber is genuinely required (2013001), and a wrong
    // one is 查無資料 (2) — unlike GetIssue's either/or modes.
    let missing = client
        .get_invalid(&GetInvalidInput {
            merchant_id: merchant_id.clone(),
            relate_number: String::new(),
            invoice_no: issued.invoice_no.clone(),
            invoice_date: invoice_date10.clone(),
        })
        .await
        .expect("decodes");
    assert_eq!(missing.rtn_code, 2013001, "{}", missing.rtn_msg);
    let wrong = client
        .get_invalid(&GetInvalidInput {
            merchant_id,
            relate_number: format!("WRONG{relate}"),
            invoice_no: issued.invoice_no.clone(),
            invoice_date: invoice_date10,
        })
        .await
        .expect("decodes");
    assert_eq!(wrong.rtn_code, 2, "{}", wrong.rtn_msg);
}

/// The wire enums pass unmodeled codes through verbatim; the server is the
/// one that adjudicates them. Pin that it does — each unknown code is a
/// format error from ECPay (captured 2026-09), so no invoice is issued and
/// nothing needs cleanup.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn unknown_codes_are_adjudicated_by_the_server() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let mut carrier = sample_issue_input(unique_relate_number(), merchant_id.clone());
    carrier.carrier_type = ecpay::invoice::CarrierType::Other("9".into());
    match client.issue(&carrier).await {
        Err(Error::Api(e)) => assert_eq!((e.code, e.msg.as_str()), (2001096, "載具類別格式錯誤")),
        other => panic!("CarrierType=9: expected the server's format error, got {other:?}"),
    }
    let mut tax = sample_issue_input(unique_relate_number(), merchant_id);
    tax.tax_type = "7".into();
    match client.issue(&tax).await {
        Err(Error::Api(e)) => assert_eq!((e.code, e.msg.as_str()), (2001019, "課稅別格式錯誤")),
        other => panic!("TaxType=7: expected the server's format error, got {other:?}"),
    }
}

/// `GetAllowance` requires BOTH `AllowanceNo` and `InvoiceNo` on every
/// `SearchType`, contrary to the spec page (see the input's docs); the
/// server checks InvoiceNo first. Stateless: the refusals come before any
/// lookup, so no allowance has to exist.
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn get_allowance_requires_allowance_no_and_invoice_no_on_every_search_type() {
    let client = stage_client();
    for (search_type, allowance_no, invoice_no, want) in [
        ("1", "", "AB12345678", 2014003),
        ("0", "2026091500001", "", 2014001),
        ("2", "", "", 2014001),
    ] {
        let got = client
            .get_allowance(&GetAllowanceInput {
                merchant_id: client.merchant_id.clone(),
                search_type: search_type.into(),
                allowance_no: allowance_no.into(),
                invoice_no: invoice_no.into(),
                date: "2026-09-15".into(),
            })
            .await
            .expect("decodes");
        assert_eq!(
            got.rtn_code, want,
            "SearchType={search_type} AllowanceNo={allowance_no:?} InvoiceNo={invoice_no:?}: {}",
            got.rtn_msg
        );
    }
}

/// `CheckLoveCode`（捐贈碼驗證）：無狀態查詢，不依賴任何先前開立的發票。
#[tokio::test]
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
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
        invoice_hash_key: "0000000000000000".into(),
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
            ecpay::Error::HttpStatus { .. } | ecpay::Error::TransCode { .. }
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn allowance_lifecycle_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();

    let issued = client
        .issue(&sample_issue_input(relate, merchant_id.clone()))
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn allowance_by_collegiate_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();
    let relate = unique_relate_number();

    let issued = client
        .issue(&sample_issue_input(relate, merchant_id.clone()))
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
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
#[ignore = "hits the live ECPay stage server (public test account); run with: cargo test --test sandbox -- --ignored --nocapture"]
async fn issue_then_void_with_reissue_roundtrip() {
    let client = stage_client();
    let merchant_id = client.merchant_id.clone();

    let relate = unique_relate_number();
    let issued = client
        .issue(&sample_issue_input(relate, merchant_id.clone()))
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
                print: "0".into(),
                donation: "0".into(),
                tax_type: "1".into(),
                sales_amount: 100,
                inv_type: "07".into(),
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
