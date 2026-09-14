//! The B2B e-invoice (電子發票 `B2BInvoice`) family — all 23 actions of the
//! official PHP SDK's `example/Invoice/B2B/` examples, with ECPay's verbatim
//! wire field names (JSON 欄位名與官方範例逐字一致).
//!
//! Wire format (verified live against the stage server on 2026-09, see
//! `tests/stage_probes.rs`): each call POSTs `{MerchantID, RqHeader, Data}`
//! to `{b2b_base_url}{Action}`. `RqHeader` carries exactly `Timestamp` (unix
//! seconds), `RqID` (the GUID-format `Ecpay::b2b_rq_id` you configure) and
//! `Revision: "1.0.0"` — B2C invoice uses `"3.0.0"` and no RqID. ECPay wants
//! `MerchantID` in BOTH the envelope AND as the first field inside `Data`
//! (every official PHP example does this), so each input struct keeps its own
//! `MerchantID` field on top of the client's `merchant_id`, which the AES
//! helper puts in the envelope. Every method checks — before any bytes go
//! out — that the `Data`-level `MerchantID` is set and equals the client's
//! (ECPay rejects a mismatch opaquely with `RtnCode != 1` and no message;
//! same guard as the ecpg module's `require_data_merchant_id`).
//!
//! HashKey/HashIV are the SAME ones as the B2C invoice API (the official PHP
//! B2B examples reuse `ejCk326UnaZWKisg`/`q9jcZX8Ib9LM8wYk` for the stage
//! test account 2000132).
//!
//! Only [`Ecpay::issue_b2b`] decodes into a typed output
//! ([`B2bIssueOutput`], stage-proven live: `{"InvoiceNumber":"LP30000931",
//! "RandomNumber":"3990","RtnCode":1,"RtnMsg":"發票開立成功"}` — note
//! `RtnCode` is an INTEGER, unlike the B2C invoice's string-typed one).
//! Every other endpoint's full response field set is not stage-proven, so
//! those methods honestly return the decrypted `serde_json::Value` and the
//! caller inspects `RtnCode` itself.
//!
//! ECPay's own response-envelope typos, noted but NOT modeled: the response
//! header is spelled `RpHeader` and the revision key `Reversion` — their
//! typos, irrelevant to our decode, which only reads `TransCode`/`TransMsg`/
//! `Data`.
//!
//! Method names are the snake_case of each action; the seven that would
//! collide with the existing B2C invoice methods (`allowance`, `invalid`,
//! `get_issue`, `get_invalid`, `get_allowance`, `get_allowance_invalid`,
//! `get_invoice_word_setting`) take a `_b2b` suffix — the same treatment
//! [`Ecpay::issue_b2b`] gets to avoid [`Ecpay::issue`].

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{api_error, Result};
use crate::wire::wire_enum;
use crate::Ecpay;

// --- B2B 發票的代碼欄位 enum(per-service;B2B 規格頁的值域) ---

wire_enum! {
    /// B2B 發票的課稅類別 (`TaxType`,1/2/3/4——**沒有** B2C 的混合 `'9'`,
    /// 與 [`crate::payment::TaxType`]、[`crate::invoice::TaxType`] 值域
    /// 不同,型別刻意分開)。
    TaxType {
        /// 應稅 (1)
        Dutiable => "1",
        /// 零稅率 (2)
        ZeroRate => "2",
        /// 免稅 (3)
        Free => "3",
        /// 應稅(特種稅率) (4)
        SpecialTaxable => "4",
    }
}

wire_enum! {
    /// B2B 發票的字軌類別 (`InvType`,07/08)。
    InvType {
        /// 一般稅額 (07)
        General => "07",
        /// 特種稅額 (08)
        Special => "08",
    }
}

impl Ecpay {
    /// B2B 的 `MerchantID` 要同時出現在信封與 `Data` 內（見模組文件）。
    /// 帶空值或與 client 的 `merchant_id` 不一致時，ECPay 只會回不帶訊息的
    /// `RtnCode != 1`，故在出網前就地擋下（與 ecpg 模組的
    /// `require_data_merchant_id` 同一防呆，名稱不同以免重複定義）。
    fn b2b_require_data_merchant_id(&self, data_merchant_id: &str) -> Result<()> {
        self.require_data_merchant_id_with(data_merchant_id, "")
    }

    /// 每個 B2B 端點共用的出網路徑：`Data` 層 `MerchantID` 防呆 → 組
    /// `RqHeader`（`Timestamp`/`RqID`/`Revision: "1.0.0"`）→
    /// AES-JSON POST 到 `{b2b_base_url}{action}`。
    async fn b2b_post<I: Serialize, O: DeserializeOwned>(
        &self,
        action: &str,
        data_merchant_id: &str,
        data: &I,
    ) -> Result<O> {
        self.b2b_require_data_merchant_id(data_merchant_id)?;
        let endpoint = format!("{}{}", self.b2b_base_url(), action);
        let rq_header = serde_json::json!({
            "Timestamp": crate::client::unix_now(),
            "RqID": self.b2b_rq_id.clone(),
            "Revision": "1.0.0",
        });
        let (key, iv) = self.invoice_keys();
        self.post_aes_json(&endpoint, rq_header, &self.merchant_id, data, key, iv)
            .await
    }
}

// --- Issue (開立發票) — example/Invoice/B2B/Issue.php ---

/// 開立 B2B 發票的輸入參數（欄位集逐字對應官方 PHP 範例
/// `example/Invoice/B2B/Issue.php`，該請求已於 2026-09 在 stage 實測開立
/// 成功）。
///
/// 注意：官方規格頁（存證模式 24230 / 交換模式 14850）的欄位名與 PHP 範例
/// 有兩處出入，本結構依可實證的 PHP 範例／stage 實測為準：
/// 1. 商品課稅別欄位：規格頁寫 `ItemTax`（Number 稅額），但 PHP 範例與
///    stage 實測（RtnCode=1）都用 `ItemTaxType`（String 課稅別），見
///    [`B2bItem::item_tax_type`]。
/// 2. 下方 `customer_name` 等 B2C 風格的選填欄位不在現行規格頁欄位表中，
///    依整合慣例保留為 `Option`；未設值時整個欄位不會出現在 `Data`
///    （`skip_serializing_if`），不影響已驗證的必填欄位集。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssueB2bInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號。ECPay 要它出現在兩處：信封（client 的 merchant_id）與 Data 的第一個欄位（官方 PHP 範例即如此）
    #[serde(rename = "RelateNumber")]
    pub relate_number: String, // 特店自訂編號 每張發票需唯一不可重複使用
    #[serde(rename = "CustomerIdentifier")]
    pub customer_identifier: String, // 買方統一編號 格式為 8 碼數字字串
    #[serde(rename = "CustomerEmail")]
    pub customer_email: String, // 買方電子信箱 多組以半形分號區隔
    #[serde(rename = "InvType")]
    pub inv_type: InvType, // 字軌類別(見 enum 文件)
    #[serde(rename = "TaxType")]
    pub tax_type: TaxType, // 課稅類別(見 enum 文件)
    #[serde(rename = "Items")]
    pub items: Vec<B2bItem>, // 商品明細
    /// 銷售額合計 ＝ `Items[].ItemAmount` 加總，且
    /// `TotalAmount = SalesAmount + TaxAmount`（官方 PHP 範例即按此算術；
    /// 規格頁稱之為未稅銷售額合計）。
    #[serde(rename = "SalesAmount")]
    pub sales_amount: i64,
    #[serde(rename = "TaxAmount")]
    pub tax_amount: i64, // 稅額合計 官方範例帶 round(SalesAmount × 0.05)
    #[serde(rename = "TotalAmount")]
    pub total_amount: i64, // 發票總金額 ＝ SalesAmount + TaxAmount
    // --- 以下為 B2C 風格的選填欄位（見結構文件註解第 2 點）---
    #[serde(rename = "CustomerName", skip_serializing_if = "Option::is_none")]
    pub customer_name: Option<String>, // 客戶名稱
    #[serde(rename = "CustomerAddr", skip_serializing_if = "Option::is_none")]
    pub customer_addr: Option<String>, // 客戶地址
    #[serde(rename = "CustomerPhone", skip_serializing_if = "Option::is_none")]
    pub customer_phone: Option<String>, // 客戶手機號碼 格式為數字
    #[serde(rename = "Print", skip_serializing_if = "Option::is_none")]
    pub print: Option<String>, // 列印註記 '0' 不列印 '1' 列印
    #[serde(rename = "Donation", skip_serializing_if = "Option::is_none")]
    pub donation: Option<String>, // 捐贈註記
    #[serde(rename = "LoveCode", skip_serializing_if = "Option::is_none")]
    pub love_code: Option<String>, // 捐贈碼 (Donation=1 時必填)
    #[serde(rename = "CarrierType", skip_serializing_if = "Option::is_none")]
    pub carrier_type: Option<String>, // 載具類別
    #[serde(rename = "CarrierNum", skip_serializing_if = "Option::is_none")]
    pub carrier_num: Option<String>, // 載具編號
    #[serde(rename = "TaxCenterFlag", skip_serializing_if = "Option::is_none")]
    pub tax_center_flag: Option<String>, // 稅籍機關別註記
    #[serde(rename = "ClearInvoice", skip_serializing_if = "Option::is_none")]
    pub clear_invoice: Option<String>, // 沖帳/銷帳註記
    #[serde(rename = "CustomerID", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>, // 客戶編號 格式為『英文、數字、下底線』
}

/// B2B 商品明細。欄位集與 B2C 的 [`crate::invoice::Item`] 不同（無
/// `ItemWord` 必填、無 `vat` 概念），獨立定義。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct B2bItem {
    #[serde(rename = "ItemSeq")]
    pub item_seq: i64, // 商品序號
    #[serde(rename = "ItemName")]
    pub item_name: String, // 商品名稱
    #[serde(rename = "ItemCount", with = "crate::crypto::finite_f64")]
    pub item_count: f64, // 商品數量 支援小數（serde_json 原樣序列化，3.0 與官方範例的 3 是同一 JSON 數值）
    #[serde(rename = "ItemPrice", with = "crate::crypto::finite_f64")]
    pub item_price: f64, // 商品單價 支援小數（serde_json 原樣序列化，10.0 與範例的 10 是同一 JSON 數值）
    /// 商品課稅別 '1'~'9'。官方規格頁的 B2B 欄位名是 `ItemTax`（Number
    /// 稅額），但官方 PHP 範例與 stage 實測（2026-09 開立成功）都是
    /// `ItemTaxType`（String 課稅別），本欄位依可實證的後者。
    #[serde(rename = "ItemTaxType")]
    pub item_tax_type: String,
    #[serde(rename = "ItemAmount", with = "crate::crypto::finite_f64")]
    pub item_amount: f64, // 商品合計 各項加總（四捨五入）= SalesAmount
    #[serde(rename = "ItemWord", skip_serializing_if = "Option::is_none")]
    pub item_word: Option<String>, // 商品單位
    #[serde(rename = "ItemRemark", skip_serializing_if = "Option::is_none")]
    pub item_remark: Option<String>, // 商品備註
    #[serde(rename = "RelateNumber", skip_serializing_if = "Option::is_none")]
    pub relate_number: Option<String>, // 商品層級的自訂編號（選填）
}

/// 開立成功的回傳。`RtnCode` 在 B2B 是整數（stage 實測），欄位名與 B2C
/// 不同：這裡是 `InvoiceNumber`（B2C 為 `InvoiceNo`）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct B2bIssueOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗（整數，非字串）
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    /// 若開立成功，則會回傳一組發票號碼；若開立失敗，則會回傳空值。
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "RandomNumber")]
    pub random_number: String, // 隨機碼
}

impl Ecpay {
    /// Issue (開立發票)。名稱帶 `_b2b` 後綴以免與 B2C 的
    /// [`Ecpay::issue`] 衝突。
    ///
    /// 回傳型別是單純的 `Result`（B2B 沒有 Go 參考實作，不需要 B2C
    /// `issue` 的雙回傳 shape）：業務層失敗（RtnCode ≠ 1）回
    /// [`crate::Error::Api`]，傳輸層失敗回各自的錯誤。
    pub async fn issue_b2b(&self, input: &IssueB2bInput) -> Result<B2bIssueOutput> {
        let output: B2bIssueOutput = self.b2b_post("Issue", &input.merchant_id, input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- IssueConfirm (確認開立，交換模式) — IssueConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssueConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼（開立回應的 InvoiceNumber）
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// IssueConfirm (確認開立，交換模式)。回應的完整欄位集未經 stage
    /// 逐欄位驗證，故以解密後的 `serde_json::Value` 原樣回傳（`RtnCode`
    /// 為整數 1 代表成功，由呼叫端檢查）——本模組其餘非 Issue 端點同此。
    pub async fn issue_confirm(&self, input: &IssueConfirmInput) -> Result<serde_json::Value> {
        self.b2b_post("IssueConfirm", &input.merchant_id, input)
            .await
    }
}

// --- Allowance (開立折讓) — Allowance.php ---

/// 開立折讓的輸入參數。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "TaxAmount")]
    pub tax_amount: i64, // 折讓的稅額合計
    #[serde(rename = "TotalAmount")]
    pub total_amount: i64, // 折讓總金額
    #[serde(rename = "Details")]
    pub details: Vec<B2bAllowanceDetail>, // 折讓的商品明細
}

/// 折讓明細（對照原發票的單一商品列）。欄位集與 B2C 的
/// [`crate::invoice::AllowanceItem`] 不同，獨立定義。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct B2bAllowanceDetail {
    #[serde(rename = "OriginalInvoiceNumber")]
    pub original_invoice_number: String, // 原發票號碼
    #[serde(rename = "OriginalInvoiceDate")]
    pub original_invoice_date: String, // 原發票開立日期 格式為 yyyy-MM-dd
    #[serde(rename = "ItemName")]
    pub item_name: String, // 商品名稱
    #[serde(rename = "OriginalSequenceNumber")]
    pub original_sequence_number: i64, // 原發票商品序號
    #[serde(rename = "ItemCount", with = "crate::crypto::finite_f64")]
    pub item_count: f64, // 折讓數量
    #[serde(rename = "ItemPrice", with = "crate::crypto::finite_f64")]
    pub item_price: f64, // 商品單價
    #[serde(rename = "ItemAmount", with = "crate::crypto::finite_f64")]
    pub item_amount: f64, // 折讓金額合計
}

impl Ecpay {
    /// Allowance (開立折讓)。名稱帶 `_b2b` 後綴以免與 B2C 的
    /// [`Ecpay::allowance`] 衝突。
    pub async fn allowance_b2b(&self, input: &AllowanceInput) -> Result<serde_json::Value> {
        self.b2b_post("Allowance", &input.merchant_id, input).await
    }
}

// --- AllowanceConfirm (確認折讓，交換模式) — AllowanceConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
}

impl Ecpay {
    /// AllowanceConfirm (確認折讓，交換模式)。
    pub async fn allowance_confirm(
        &self,
        input: &AllowanceConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("AllowanceConfirm", &input.merchant_id, input)
            .await
    }
}

// --- CancelAllowance (取消折讓) — CancelAllowance.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CancelAllowanceInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
    #[serde(rename = "Reason")]
    pub reason: String, // 取消原因
}

impl Ecpay {
    /// CancelAllowance (取消折讓)。
    pub async fn cancel_allowance(
        &self,
        input: &CancelAllowanceInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("CancelAllowance", &input.merchant_id, input)
            .await
    }
}

// --- CancelAllowanceConfirm (確認取消折讓，交換模式) — CancelAllowanceConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CancelAllowanceConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
}

impl Ecpay {
    /// CancelAllowanceConfirm (確認取消折讓，交換模式)。
    pub async fn cancel_allowance_confirm(
        &self,
        input: &CancelAllowanceConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("CancelAllowanceConfirm", &input.merchant_id, input)
            .await
    }
}

// --- Invalid (作廢發票) — Invalid.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
    #[serde(rename = "Reason")]
    pub reason: String, // 作廢原因 maxlength 20（stage 實測 2026-09：超過回 2103005 發票作廢原因格式錯誤）
}

impl Ecpay {
    /// Invalid (作廢發票)。名稱帶 `_b2b` 後綴以免與 B2C 的
    /// [`Ecpay::invalid`] 衝突。
    pub async fn invalid_b2b(&self, input: &InvalidInput) -> Result<serde_json::Value> {
        self.b2b_post("Invalid", &input.merchant_id, input).await
    }
}

// --- InvalidConfirm (確認作廢，交換模式) — InvalidConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvalidConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// InvalidConfirm (確認作廢，交換模式)。
    pub async fn invalid_confirm(&self, input: &InvalidConfirmInput) -> Result<serde_json::Value> {
        self.b2b_post("InvalidConfirm", &input.merchant_id, input)
            .await
    }
}

// --- Notify (發送通知) — Notify.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "NotifyMail")]
    pub notify_mail: String, // 發送電子郵件 可多組，以分號區隔
    #[serde(rename = "InvoiceTag")]
    pub invoice_tag: String, // 發送內容類型 '1' 開立，其餘值依官方文件
    #[serde(rename = "Notified")]
    pub notified: String, // 發送對象 'C' 客戶 等
}

impl Ecpay {
    /// Notify (發送通知)。
    pub async fn notify(&self, input: &NotifyInput) -> Result<serde_json::Value> {
        self.b2b_post("Notify", &input.merchant_id, input).await
    }
}

// --- Reject (退回/拒絕，交換模式店家拒收) — Reject.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RejectInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
    #[serde(rename = "Reason")]
    pub reason: String, // 退回原因
}

impl Ecpay {
    /// Reject (退回，交換模式店家拒收)。
    pub async fn reject(&self, input: &RejectInput) -> Result<serde_json::Value> {
        self.b2b_post("Reject", &input.merchant_id, input).await
    }
}

// --- RejectConfirm (確認退回，交換模式) — RejectConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RejectConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// RejectConfirm (確認退回，交換模式)。
    pub async fn reject_confirm(&self, input: &RejectConfirmInput) -> Result<serde_json::Value> {
        self.b2b_post("RejectConfirm", &input.merchant_id, input)
            .await
    }
}

// --- MaintainMerchantCustomerData (維護交易對象/客戶資料) —
// MaintainMerchantCustomerData.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MaintainMerchantCustomerDataInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "Action")]
    pub action: String, // 操作 'Add'/'Update' 等
    #[serde(rename = "Identifier")]
    pub identifier: String, // 交易對象統一編號
    /// 客戶類型。ECPay 的 wire 欄位名就是小寫的 "type"（官方 PHP 範例即
    /// 如此，全模組唯一的小寫欄位名），serde 已原樣 rename。
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "CompanyName")]
    pub company_name: String, // 公司名稱
    #[serde(rename = "TradingSlang")]
    pub trading_slang: String, // 交易說明（官方範例帶自由文字）
    #[serde(rename = "ExchangeMode")]
    pub exchange_mode: String, // 交換模式註記（官方範例帶 '0'）
    #[serde(rename = "EmailAddress")]
    pub email_address: String, // 電子信箱
}

impl Ecpay {
    /// MaintainMerchantCustomerData (維護交易對象/客戶資料)。
    pub async fn maintain_merchant_customer_data(
        &self,
        input: &MaintainMerchantCustomerDataInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("MaintainMerchantCustomerData", &input.merchant_id, input)
            .await
    }
}

// --- GetIssue (查詢開立發票) — GetIssue.php ---

/// 查詢開立發票的輸入參數。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 查詢類別（官方 PHP 範例帶 0）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// GetIssue (查詢開立發票)。名稱帶 `_b2b` 後綴以免與 B2C 的
    /// [`Ecpay::get_issue`] 衝突。
    pub async fn get_issue_b2b(&self, input: &GetIssueInput) -> Result<serde_json::Value> {
        self.b2b_post("GetIssue", &input.merchant_id, input).await
    }
}

// --- GetIssueConfirm (查詢開立確認) — GetIssueConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetIssueConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 查詢類別（官方 PHP 範例帶 0）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// GetIssueConfirm (查詢開立確認)。
    pub async fn get_issue_confirm(
        &self,
        input: &GetIssueConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetIssueConfirm", &input.merchant_id, input)
            .await
    }
}

// --- GetInvalid (查詢作廢發票) — GetInvalid.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 查詢類別（官方 PHP 範例帶 0）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// GetInvalid (查詢作廢發票)。名稱帶 `_b2b` 後綴以免與 B2C 的
    /// [`Ecpay::get_invalid`] 衝突。
    pub async fn get_invalid_b2b(&self, input: &GetInvalidInput) -> Result<serde_json::Value> {
        self.b2b_post("GetInvalid", &input.merchant_id, input).await
    }
}

// --- GetInvalidConfirm (查詢作廢確認) — GetInvalidConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvalidConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 查詢類別（官方 PHP 範例帶 0）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// GetInvalidConfirm (查詢作廢確認)。
    pub async fn get_invalid_confirm(
        &self,
        input: &GetInvalidConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetInvalidConfirm", &input.merchant_id, input)
            .await
    }
}

// --- GetAllowance (查詢折讓) — GetAllowance.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
}

impl Ecpay {
    /// GetAllowance (查詢折讓)。名稱帶 `_b2b` 後綴以免與 B2C 的
    /// [`Ecpay::get_allowance`] 衝突。
    pub async fn get_allowance_b2b(&self, input: &GetAllowanceInput) -> Result<serde_json::Value> {
        self.b2b_post("GetAllowance", &input.merchant_id, input)
            .await
    }
}

// --- GetAllowanceConfirm (查詢折讓確認) — GetAllowanceConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
}

impl Ecpay {
    /// GetAllowanceConfirm (查詢折讓確認)。
    pub async fn get_allowance_confirm(
        &self,
        input: &GetAllowanceConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetAllowanceConfirm", &input.merchant_id, input)
            .await
    }
}

// --- GetAllowanceInvalid (查詢作廢折讓) — GetAllowanceInvalid.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceInvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
}

impl Ecpay {
    /// GetAllowanceInvalid (查詢作廢折讓)。名稱帶 `_b2b` 後綴以免與 B2C
    /// 的 [`Ecpay::get_allowance_invalid`] 衝突。
    pub async fn get_allowance_invalid_b2b(
        &self,
        input: &GetAllowanceInvalidInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetAllowanceInvalid", &input.merchant_id, input)
            .await
    }
}

// --- GetAllowanceInvalidConfirm (查詢折讓作廢確認) — GetAllowanceInvalidConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceInvalidConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
}

impl Ecpay {
    /// GetAllowanceInvalidConfirm (查詢折讓作廢確認)。
    pub async fn get_allowance_invalid_confirm(
        &self,
        input: &GetAllowanceInvalidConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetAllowanceInvalidConfirm", &input.merchant_id, input)
            .await
    }
}

// --- GetReject (查詢退回) — GetReject.php ---
//
// 注意：官方 PHP 範例在這個「查詢」端點的 Data 也帶 Reason，本結構照抄
// 保留（與其他查詢端點不一致是 ECPay 範例本身的樣子）。

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetRejectInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
    #[serde(rename = "Reason")]
    pub reason: String, // 退回原因（官方範例在查詢端點也帶此欄位，照抄）
}

impl Ecpay {
    /// GetReject (查詢退回)。
    pub async fn get_reject(&self, input: &GetRejectInput) -> Result<serde_json::Value> {
        self.b2b_post("GetReject", &input.merchant_id, input).await
    }
}

// --- GetRejectConfirm (查詢退回確認) — GetRejectConfirm.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetRejectConfirmInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 查詢類別（官方 PHP 範例帶 0）
    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd
}

impl Ecpay {
    /// GetRejectConfirm (查詢退回確認)。
    pub async fn get_reject_confirm(
        &self,
        input: &GetRejectConfirmInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetRejectConfirm", &input.merchant_id, input)
            .await
    }
}

// --- GetInvoiceWordSetting (查詢字軌) — GetInvoiceWordSetting.php ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvoiceWordSettingInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號（信封與 Data 兩處都要）
    #[serde(rename = "InvoiceYear")]
    pub invoice_year: String, // 發票年度 格式為民國年 ex '109'
    #[serde(rename = "InvoiceTerm")]
    pub invoice_term: i64, // 發票期別 0:全部 1:1-2 月 … 6:11-12 月
    #[serde(rename = "UseStatus")]
    pub use_status: i64, // 字軌使用狀態 0:全部 等
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 發票類別 B2B 官方範例固定填 2
}

impl Ecpay {
    /// GetInvoiceWordSetting (查詢字軌)。名稱帶 `_b2b` 後綴以免與 B2C
    /// 的 [`Ecpay::get_invoice_word_setting`] 衝突。
    pub async fn get_invoice_word_setting_b2b(
        &self,
        input: &GetInvoiceWordSettingInput,
    ) -> Result<serde_json::Value> {
        self.b2b_post("GetInvoiceWordSetting", &input.merchant_id, input)
            .await
    }
}
