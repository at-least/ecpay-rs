//! The typed B2C e-invoice APIs (Go issue.go, void_with_issue.go, invalid.go,
//! invoice_notify.go, check_barcode.go, get_company_name_by_tax_id.go,
//! get_gov_invoice_word_setting.go, get_invoice_word_setting.go, get_issue.go),
//! plus the delay-issue, GetInvalid, CheckLoveCode, and Allowance families
//! ported below from `ECPay/SDK_PHP`'s example files and the official spec
//! pages (developers.ecpay.com.tw) — not present in the reference Go port.
//! JSON field names are ECPay's verbatim spec names — locked by the
//! conformance tests.
//!
//! `VoidWithReIssue` is the one exception: the reference Go port names both
//! the file and the wire action `VoidWithIssue`, but ECPay's real endpoint is
//! `/B2CInvoice/VoidWithReIssue` (confirmed live against stage: the old name
//! hits ECPay's generic error page, HTTP 500, not a JSON response). This
//! crate uses the correct wire name and the accurate Rust name/semantics
//! (作廢重開, void-and-reissue — distinct from 折讓/allowance, see
//! [`Ecpay::allowance`] below).

use serde::{Deserialize, Serialize};

use crate::error::{api_error, Error, Result};
use crate::wire::wire_enum;
use crate::Ecpay;

// --- B2C 發票的代碼欄位 enum(per-service,與 payment 模組的 AIO 語彙不同) ---

wire_enum! {
    /// B2C 發票的課稅類別 (`TaxType`,1/2/3/4/9——比 AIO 多特種稅率 `'4'`,
    /// 比 B2B 多混合 `'9'`,與 [`crate::payment::TaxType`]、
    /// [`crate::invoice_b2b::TaxType`] 值域不同,型別刻意分開)。
    TaxType {
        /// 應稅 (1)
        Dutiable => "1",
        /// 零稅率 (2;需 ClearanceMark 與 ZeroTaxRateReason)
        ZeroRate => "2",
        /// 免稅 (3)
        Free => "3",
        /// 應稅(特種稅率) (4)
        SpecialTaxable => "4",
        /// 應稅與免稅混合 (9;各商品列需 ItemTaxType)
        Mixed => "9",
    }
}

wire_enum! {
    /// B2C 發票的捐贈註記 (`Donation`,`'0'` 不捐贈/`'1'` 捐贈)——與 AIO 的
    /// [`crate::payment::Donation`](`'1'`/`'2'`)語意相反,型別刻意分開。
    Donation {
        /// 不捐贈 (0)
        No => "0",
        /// 捐贈 (1;需要 LoveCode)
        Yes => "1",
    }
}

wire_enum! {
    /// B2C 發票的列印註記 (`Print`,0/1)。
    PrintMark {
        /// 不列印 (0)
        No => "0",
        /// 列印 (1)
        Yes => "1",
    }
}

wire_enum! {
    /// B2C 發票的載具類別 (`CarrierType`)。空字串(無載具)= `Other("")`
    /// (即 `Default`)。`'4'`/`'5'`(實體卡片,需 `CarrierNum2`)官方文件
    /// 未載明代碼名稱,以 `Other` 穿隧。
    CarrierType {
        /// 綠界電子發票載具 (1)
        Ecpay => "1",
        /// 自然人憑證 (2)
        Citizen => "2",
        /// 手機條碼 (3)
        Cellphone => "3",
    }
}

wire_enum! {
    /// B2C 發票的通關方式 (`ClearanceMark`,TaxType 為零稅率時必填)——
    /// **與 AIO 的 [`crate::payment::ClearanceMark`] wire 值相反**
    /// (`'1'`=非經海關出口、`'2'`=經海關出口),型別刻意分開。
    ClearanceMark {
        /// 非經海關出口 (1;B2C 發票指南語彙)
        NotViaCustoms => "1",
        /// 經海關出口 (2;B2C 發票指南語彙)
        ViaCustoms => "2",
    }
}

wire_enum! {
    /// B2C 發票的字軌類別 (`InvType`,07/08)。
    InvType {
        /// 一般稅額 (07)
        General => "07",
        /// 特種稅額 (08)
        Special => "08",
    }
}

// --- Issue (開立發票) — issue.go ---

/// 開立發票的輸入參數。
/// 欄位與 IssueModel（VoidWithReIssue 的重開部分）相同，外加 IssueModel
/// 專屬必填的 InvoiceDate，刻意分開維護。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "RelateNumber")]
    pub relate_number: String, // 特店自訂編號 需為唯一值不可重複使用。 注意事項:請勿使用特殊符號
    #[serde(rename = "ChannelPartner")]
    pub channel_partner: String, // 通路商編號 '1'=蝦皮，其餘忽略
    #[serde(rename = "CustomerID")]
    pub customer_id: String, // 客戶編號 格式為『英文、數字、下底線』等字元。
    #[serde(rename = "ProductServiceID")]
    pub product_service_id: String, // 產品服務別代號 (需開通「B2C 系統多組字軌」功能)
    #[serde(rename = "CustomerIdentifier")]
    pub customer_identifier: String, // 統一編號 格式為數字
    #[serde(rename = "CustomerName")]
    pub customer_name: String, // 客戶名稱 (當 Print=1 或 CustomerIdentifier 有值時為必填)
    #[serde(rename = "CustomerAddr")]
    pub customer_addr: String, // 客戶地址 當列印註記[Print]=1(列印)時，為必填。
    #[serde(rename = "CustomerPhone")]
    pub customer_phone: String, // 客戶手機號碼 當客戶電子信箱為空字串時，為必填。 格式為數字。
    #[serde(rename = "CustomerEmail")]
    pub customer_email: String, // 客戶電子信箱 當客戶手機號碼為空字串時，為必填。
    #[serde(rename = "ClearanceMark")]
    pub clearance_mark: ClearanceMark, // 通關方式 (TaxType 為零稅率時必填)
    #[serde(rename = "Print")]
    pub print: PrintMark, // 列印註記
    #[serde(rename = "Donation")]
    pub donation: Donation, // 捐贈註記 (捐贈時 LoveCode 必填)
    #[serde(rename = "LoveCode")]
    pub love_code: String, // 捐贈碼 (Donation=捐贈時為必填)
    #[serde(rename = "CarrierType")]
    pub carrier_type: CarrierType, // 載具類別 (空=無載具,見 enum 文件)
    #[serde(rename = "CarrierNum")]
    pub carrier_num: String, // 載具編號
    #[serde(rename = "CarrierNum2")]
    pub carrier_num2: String, // 實體卡片顯碼id(外觀號碼) CarrierType=4 或 5 時必填
    #[serde(rename = "TaxType")]
    pub tax_type: TaxType, // 課稅類別(見 enum 文件)
    /// 零稅率原因代號(71~79)。官方文件(developers.ecpay.com.tw/7896.md、
    /// guides/04)載明 TaxType=2 或 9 時必填，自 2026-01-01 起強制；沙盒
    /// 實測(2026-09,公開測試特店 2000132)未填仍開立成功，該帳號似未強制
    /// 此規則，正式環境/其他特店請勿依賴沙盒行為，務必依文件填寫。
    #[serde(rename = "ZeroTaxRateReason")]
    pub zero_tax_rate_reason: String,
    #[serde(rename = "SpecialTaxType")]
    pub special_tax_type: i64, // 特種稅額類別
    #[serde(rename = "SalesAmount")]
    pub sales_amount: i64, // 發票總金額(含稅) 金額不可為 0 元。
    #[serde(rename = "TaxAmount", skip_serializing_if = "Option::is_none")]
    pub tax_amount: Option<i64>, // 稅額合計 未填由綠界代算(省略此欄位)；特種稅額請帶 0
    #[serde(rename = "InvoiceRemark")]
    pub invoice_remark: String, // 發票備註
    #[serde(rename = "Items")]
    pub items: Option<Vec<Item>>, // 商品 (Go nil slice marshals as null)
    #[serde(rename = "InvType")]
    pub inv_type: InvType, // 字軌類別(見 enum 文件)
    /// ECPay quirk: the tax-inclusive flag is lowercase "vat" (every other
    /// field is PascalCase).
    #[serde(rename = "vat")]
    pub vat: String, // 商品單價是否含稅 1:含稅 0:未稅
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Item {
    #[serde(rename = "ItemSeq")]
    pub item_seq: i64, // 商品序號
    #[serde(rename = "ItemName")]
    pub item_name: String, // 商品名稱
    #[serde(rename = "ItemCount", with = "crate::crypto::finite_f64")]
    pub item_count: f64, // 商品數量 支援整數 8 位小數 2 位
    #[serde(rename = "ItemWord")]
    pub item_word: String, // 商品單位
    /// 若 vat=0(未稅)，商品金額需為未稅金額 若 vat=1(含稅)，商品金額需為含稅金額
    ///
    /// 所有 `finite_f64` 欄位(含本欄位):會以**指數記法**上 wire 的量級
    /// (serde_json 1.0.151 實測:小於 1e-5 或 1e16 以上,如 `0.000001`)
    /// 一律在本機以 serialization error 拒絕——指數形式從未對綠界驗證過,
    /// 且其十進位窗口會隨 serde_json 版本漂移。請帶文件範圍內、十進位
    /// 記法可完整表示的值。
    #[serde(rename = "ItemPrice", with = "crate::crypto::finite_f64")]
    pub item_price: f64, // 商品單價 支援整數 8 位小數 7 位
    #[serde(rename = "ItemTaxType")]
    pub item_tax_type: String, // 商品課稅別 (TaxType=9 時不可為空)
    #[serde(rename = "ItemAmount", with = "crate::crypto::finite_f64")]
    pub item_amount: f64, // 商品合計(含稅) 各項總合並四捨五入=salesAmount(含稅)
    #[serde(rename = "ItemRemark")]
    pub item_remark: String, // 商品備註
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssueOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    /// 若開立成功，則會回傳一組發票號碼；若開立失敗，則會回傳空值。
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String, // 發票號碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立時間 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "RandomNumber")]
    pub random_number: String, // 隨機碼
}

impl Ecpay {
    /// 開立發票。業務層失敗（RtnCode ≠ 1，如欄位驗證或重複開立）回
    /// [`crate::Error::Api`]（code 與 RtnMsg 都在 [`crate::ApiError`] 內），
    /// 傳輸/解密失敗回各自的錯誤。ECPay 規格：開立失敗時 InvoiceNo/
    /// InvoiceDate 為空值，故失敗路徑不需要、也不回傳部分輸出。
    pub async fn issue(&self, input: &IssueInput) -> Result<IssueOutput> {
        // A negative total is never a valid wire value (same stance as
        // `aio_check_out`'s TotalAmount); zero stays allowed — the field's
        // documented 金額不可為 0 元 rule is the server's to enforce.
        if input.sales_amount < 0 {
            return Err(Error::Validation("SalesAmount cannot be negative.".into()));
        }
        let output: IssueOutput = self.call_invoice_api("Issue", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- VoidWithReIssue (作廢重開) — void_with_issue.go ---
//
// ECPay 的真實端點是 /B2CInvoice/VoidWithReIssue（Go 版原始檔名/action
// 字串誤植為 VoidWithIssue，本函式庫已改用正確名稱，見上方 module doc）。
//
// Data 信封本身是 `{VoidModel: {...}, IssueModel: {...}}` 兩個巢狀物件
// （不是像 Issue/Invalid 那樣的扁平欄位）；核對官方 PHP 範例
// `scripts/SDK_PHP/example/Invoice/B2C/VoidWithReIssue.php` 逐位元組一致。

/// `VoidModel`：要作廢的舊發票。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VoidModel {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String, // 發票號碼 長度固定為 10 碼
    #[serde(rename = "VoidReason")]
    pub void_reason: String, // 註銷原因
}

/// `IssueModel`：重開的新發票。欄位與 `IssueInput` 相同，外加作廢重開專屬
/// 的必填欄位 `InvoiceDate`。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssueModel {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "RelateNumber")]
    pub relate_number: String,
    /// 發票開立時間 格式為 yyyy-MM-dd HH:mm:ss。作廢重開專屬必填欄位，
    /// 一般開立（Issue）沒有這個欄位。
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String,
    #[serde(rename = "ChannelPartner")]
    pub channel_partner: String,
    #[serde(rename = "CustomerID")]
    pub customer_id: String,
    #[serde(rename = "ProductServiceID")]
    pub product_service_id: String,
    #[serde(rename = "CustomerIdentifier")]
    pub customer_identifier: String,
    #[serde(rename = "CustomerName")]
    pub customer_name: String,
    #[serde(rename = "CustomerAddr")]
    pub customer_addr: String,
    #[serde(rename = "CustomerPhone")]
    pub customer_phone: String,
    #[serde(rename = "CustomerEmail")]
    pub customer_email: String,
    #[serde(rename = "ClearanceMark")]
    pub clearance_mark: ClearanceMark,
    #[serde(rename = "Print")]
    pub print: PrintMark,
    #[serde(rename = "Donation")]
    pub donation: Donation,
    #[serde(rename = "LoveCode")]
    pub love_code: String,
    #[serde(rename = "CarrierType")]
    pub carrier_type: CarrierType,
    #[serde(rename = "CarrierNum")]
    pub carrier_num: String,
    #[serde(rename = "CarrierNum2")]
    pub carrier_num2: String,
    #[serde(rename = "TaxType")]
    pub tax_type: TaxType,
    /// 零稅率原因代號(71~79)。TaxType=2 或 9 時必填，見 IssueInput 對應
    /// 欄位的說明（含沙盒實測備註）。
    #[serde(rename = "ZeroTaxRateReason")]
    pub zero_tax_rate_reason: String,
    #[serde(rename = "SpecialTaxType")]
    pub special_tax_type: i64,
    #[serde(rename = "SalesAmount")]
    pub sales_amount: i64,
    #[serde(rename = "TaxAmount", skip_serializing_if = "Option::is_none")]
    pub tax_amount: Option<i64>,
    #[serde(rename = "InvoiceRemark")]
    pub invoice_remark: String,
    #[serde(rename = "Items")]
    pub items: Option<Vec<Item>>,
    #[serde(rename = "InvType")]
    pub inv_type: InvType,
    #[serde(rename = "vat")]
    pub vat: String,
}

/// 作廢重開的輸入參數：`VoidModel`（作廢舊發票）+ `IssueModel`（開立新發票）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VoidWithReIssueInput {
    #[serde(rename = "VoidModel")]
    pub void_model: VoidModel,
    #[serde(rename = "IssueModel")]
    pub issue_model: IssueModel,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VoidWithReIssueOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String,
    #[serde(rename = "RandomNumber")]
    pub random_number: String,
}

impl Ecpay {
    /// VoidWithReIssue (作廢重開) is a command like Issue/Invalid, so a
    /// non-success RtnCode is surfaced as [`crate::ApiError`] rather than
    /// swallowed. Its Data nests TWO MerchantIDs (`VoidModel` and
    /// `IssueModel`) below the top level, so the shared envelope guard
    /// (`encrypt_checked`, top-level only) cannot see them —
    /// both are checked here with the same rule (a SET value must equal the
    /// client's MerchantID; empty passes through), before any bytes go out.
    pub async fn void_with_reissue(
        &self,
        input: &VoidWithReIssueInput,
    ) -> Result<VoidWithReIssueOutput> {
        for (label, mid) in [
            ("VoidModel.MerchantID", &input.void_model.merchant_id),
            ("IssueModel.MerchantID", &input.issue_model.merchant_id),
        ] {
            if !mid.is_empty() && mid != &self.merchant_id {
                return Err(Error::Validation(format!(
                    "ecpay: {label} must equal the client's MerchantID \
                     (got {mid:?}, client has {:?}); ECPay rejects a mismatch opaquely \
                     with RtnCode != 1 and no message",
                    self.merchant_id
                )));
            }
        }
        // The re-issued invoice's total follows `issue`'s negative-amount
        // stance (zero stays allowed — the server adjudicates it).
        if input.issue_model.sales_amount < 0 {
            return Err(Error::Validation("SalesAmount cannot be negative.".into()));
        }
        let output: VoidWithReIssueOutput = self.call_invoice_api("VoidWithReIssue", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- Invalid (作廢發票) — invalid.go ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String, // 發票號碼 長度固定為 10 碼
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 發票開立日期 格式為「yyyy-MM-dd」
    #[serde(rename = "Reason")]
    pub reason: String, // 作廢原因 maxlength 20（沙盒實測 2026-09：超過回 2009005 作廢原因長度錯誤）
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvalidOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗。
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    /// 若作廢成功，則會回傳發票號碼；若開立失敗，則會回傳空值。
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String, // 發票號碼
}

impl Ecpay {
    /// 作廢發票。A command: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn invalid(&self, input: &InvalidInput) -> Result<InvalidOutput> {
        let output: InvalidOutput = self.call_invoice_api("Invalid", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- InvoiceNotify (發送通知) — invoice_notify.go ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvoiceNotifyInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String, // 發票號碼
    /// 若 InvoiceTag 為 A(折讓開立)、AI(折讓作廢)或 OA(線上折讓)時為必填
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String, // 折讓編號
    #[serde(rename = "Phone")]
    pub phone: String, // 發送簡訊號碼 (與 NotifyMail 擇一必填)
    #[serde(rename = "NotifyMail")]
    pub notify_mail: String, // 發送電子郵件 可多組，以分號區隔 ex: aa@aa.aa;bb@bb.bb
    #[serde(rename = "Notify")]
    pub notify: String, // 發送方式 S:簡訊 E:電子郵件 A:皆通知
    #[serde(rename = "InvoiceTag")]
    pub invoice_tag: String, // 發送內容類型 I/II/A/AI/AW/OA
    #[serde(rename = "Notified")]
    pub notified: String, // 發送對象 C:客戶 M:特店 A:皆發送
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvoiceNotifyOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗。
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    #[serde(rename = "MerchantID")]
    pub merchant_id: serde_json::Value, // ECPay 回傳型態不固定
}

impl Ecpay {
    /// InvoiceNotify is a command (it triggers ECPay to re-send a
    /// notification), so it follows the same contract as Issue / Invalid /
    /// VoidWithReIssue: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn invoice_notify(&self, input: &InvoiceNotifyInput) -> Result<InvoiceNotifyOutput> {
        let output: InvoiceNotifyOutput = self.call_invoice_api("InvoiceNotify", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- CheckBarcode (手機條碼驗證) — check_barcode.go ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckBarcodeInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    /// ECPay's spec field is "Barcode" (not the Go field name BarCode).
    #[serde(rename = "Barcode")]
    pub barcode: String, // 手機條碼 /1234567 格式
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckBarcodeOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗。
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    /// 若回應代碼 RtnCode 為 1(成功)時，請再判斷此欄位值 Y:存在 N:不存在
    #[serde(rename = "IsExist")]
    pub is_exist: String, // 手機條碼是否存在
}

impl Ecpay {
    /// A query: a non-1 RtnCode is returned verbatim, not raised as an error.
    pub async fn check_barcode(&self, input: &CheckBarcodeInput) -> Result<CheckBarcodeOutput> {
        self.call_invoice_api("CheckBarcode", input).await
    }
}

// --- GetCompanyNameByTaxID — get_company_name_by_tax_id.go ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetCompanyNameByTaxIDInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "UnifiedBusinessNo")]
    pub unified_business_no: String, // 統一編號
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetCompanyNameByTaxIDOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    #[serde(rename = "CompanyName")]
    pub company_name: String, // 公司名稱
}

impl Ecpay {
    /// 統一編號查詢(營業人名稱)。A query: a non-1 RtnCode (e.g. not-found)
    /// is a normal result, NOT an [`crate::ApiError`] — the caller inspects
    /// RtnCode directly.
    pub async fn get_company_name_by_tax_id(
        &self,
        input: &GetCompanyNameByTaxIDInput,
    ) -> Result<GetCompanyNameByTaxIDOutput> {
        self.call_invoice_api("GetCompanyNameByTaxID", input).await
    }
}

// --- GetGovInvoiceWordSetting (政府字軌設定查詢) — get_gov_invoice_word_setting.go ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetGovInvoiceWordSettingInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "InvoiceYear")]
    pub invoice_year: String, // 發票年度
}

/// Go's anonymous InvoiceInfo element struct.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GovInvoiceInfo {
    #[serde(rename = "InvoiceTerm")]
    pub invoice_term: i64, // 發票期別 1:1-2月 ,2:3-4月 ,3:5-6月 ,4:7-8月 ,5:9-10月 ,6:11-12月
    #[serde(rename = "InvType")]
    pub inv_type: InvType, // 字軌類別 07:一般稅額發票 08:特種稅額發票
    #[serde(rename = "InvoiceHeader")]
    pub invoice_header: String, // 發票字軌 ex:KK
    #[serde(rename = "InvoiceStart")]
    pub invoice_start: String, // 起始發票編號 8 碼，尾數需為 00 或 50。(例:10000000)
    #[serde(rename = "InvoiceEnd")]
    pub invoice_end: String, // 8 碼發票號碼，尾數需為 49 或 99。(例:10000049)
    #[serde(rename = "Number")]
    pub number: i64, // 申請本數 一本為 50 個發票號碼。
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetGovInvoiceWordSettingOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗。
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    #[serde(rename = "InvoiceInfo")]
    pub invoice_info: Vec<GovInvoiceInfo>, // 發票配號結果清單
}

impl Ecpay {
    /// 政府字軌設定查詢。A query: a non-1 RtnCode (e.g. not-found) is a
    /// normal result, NOT an [`crate::ApiError`] — the caller inspects
    /// RtnCode directly.
    pub async fn get_gov_invoice_word_setting(
        &self,
        input: &GetGovInvoiceWordSettingInput,
    ) -> Result<GetGovInvoiceWordSettingOutput> {
        self.call_invoice_api("GetGovInvoiceWordSetting", input)
            .await
    }
}

// --- GetInvoiceWordSetting (字軌使用狀態查詢) — get_invoice_word_setting.go ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvoiceWordSettingInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "InvoiceYear")]
    pub invoice_year: String, // 發票年度 格式為民國年 ex:109
    #[serde(rename = "InvoiceTerm")]
    pub invoice_term: i64, // 發票期別 0:全部，1: 1-2 月，...，6: 11-12 月
    #[serde(rename = "UseStatus")]
    pub use_status: i64, // 字軌使用狀態 0:全部，1:未啟用，2:使用中，3:已停用，4:暫停中，5:待審核，6:審核不通過
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 發票類別 1:B2C，請固定填寫為 1
    #[serde(rename = "InvType")]
    pub inv_type: InvType, // 字軌類別 07:一般稅額發票，08:特種稅額發票
    #[serde(rename = "InvoiceHeader")]
    pub invoice_header: String, // 字軌名稱
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvoiceInfo {
    #[serde(rename = "TrackID")]
    pub track_id: String, // 字軌號碼
    #[serde(rename = "InvoiceYear")]
    pub invoice_year: String, // 發票年度 格式為民國年 ex:109
    #[serde(rename = "InvoiceTerm")]
    pub invoice_term: i64, // 發票期別
    #[serde(rename = "InvoiceCategory")]
    pub invoice_category: i64, // 發票類別 1:B2C
    #[serde(rename = "InvType")]
    pub inv_type: InvType, // 字軌類別 07:一般稅額發票，08:特種稅額發票
    #[serde(rename = "InvoiceHeader")]
    pub invoice_header: String, // 字軌名稱
    #[serde(rename = "InvoiceStart")]
    pub invoice_start: String, // 起始發票編號
    #[serde(rename = "InvoiceEnd")]
    pub invoice_end: String, // 結束發票編號
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String, // 目前已使用號碼
    #[serde(rename = "UseStatus")]
    pub use_status: i64, // 使用狀態 1:未啟用，2:使用中，3:已停用，4:暫停中，5:待審核，6:審核不通過
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvoiceWordSettingOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    #[serde(rename = "InvoiceInfo")]
    pub invoice_info: Vec<InvoiceInfo>, // 發票資訊
}

impl Ecpay {
    /// 字軌使用狀態查詢(自有字軌)。A query: a non-1 RtnCode (e.g.
    /// not-found) is a normal result, NOT an [`crate::ApiError`] — the
    /// caller inspects RtnCode directly.
    pub async fn get_invoice_word_setting(
        &self,
        input: &GetInvoiceWordSettingInput,
    ) -> Result<GetInvoiceWordSettingOutput> {
        self.call_invoice_api("GetInvoiceWordSetting", input).await
    }
}

// --- GetIssue (查詢發票開立資訊) — get_issue.go ---

/// 查詢發票開立資訊的輸入參數。兩種互斥的查詢方式擇一：只填
/// `relate_number`；或只填 `invoice_no` + `invoice_date`（格式 yyyy-MM-dd）。
/// 衝突（兩邊都填）或只填半對（`invoice_no`/`invoice_date` 缺一）由
/// [`Ecpay::get_issue`](Self::get_issue) 在出網前以 `Error::Validation`
/// 拒絕；全空交給伺服器裁定。
///
/// ECPay 沙盒實測(2026-09):是否存在於 JSON（而非其值是否為空字串）決定
/// 查詢模式——就算欄位是空字串,只要 key 出現在請求裡,伺服器就會採用該
/// 模式。實測兩個方向都成立：帶空 `InvoiceNo`/`InvoiceDate`
/// 會讓合法的 `RelateNumber` 查詢失敗；帶空 `RelateNumber` 同樣會讓合法的
/// `InvoiceNo`+`InvoiceDate` 查詢失敗（皆回 RtnCode=2 查無資料）。因此這三
/// 個欄位只要空值就必須整個省略,不能像本檔其他欄位一樣送空字串。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "RelateNumber", skip_serializing_if = "String::is_empty")]
    pub relate_number: String, // 特店自訂編號（即 OrderID）；與 InvoiceNo+InvoiceDate 擇一
    #[serde(rename = "InvoiceNo", skip_serializing_if = "String::is_empty")]
    pub invoice_no: String, // 發票號碼；與 RelateNumber 擇一，需搭配 InvoiceDate
    #[serde(rename = "InvoiceDate", skip_serializing_if = "String::is_empty")]
    pub invoice_date: String, // 發票開立日期 格式為 yyyy-MM-dd；搭配 InvoiceNo 使用
}

/// 查詢發票開立資訊的回傳參數。
/// ECPay 回傳的欄位型態不固定（數字或字串），不需要用到的欄位用 Value 接
/// (Go `any`)。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetIssueOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    #[serde(rename = "IIS_Mer_ID")]
    pub iis_mer_id: serde_json::Value, // 特店編號
    #[serde(rename = "ChannelPartner")]
    pub channel_partner: String, // 通路商編號
    #[serde(rename = "IIS_Number")]
    pub iis_number: String, // 發票號碼
    #[serde(rename = "IIS_Relate_Number")]
    pub iis_relate_number: String, // 特店自訂編號
    #[serde(rename = "IIS_Customer_ID")]
    pub iis_customer_id: String, // 客戶編號
    #[serde(rename = "IIS_Identifier")]
    pub iis_identifier: String, // 統一編號
    #[serde(rename = "IIS_Customer_Name")]
    pub iis_customer_name: String, // 客戶名稱
    #[serde(rename = "IIS_Customer_Addr")]
    pub iis_customer_addr: String, // 客戶地址
    #[serde(rename = "IIS_Customer_Phone")]
    pub iis_customer_phone: String, // 客戶手機號碼
    #[serde(rename = "IIS_Customer_Email")]
    pub iis_customer_email: String, // 客戶電子信箱
    #[serde(rename = "IIS_Clearance_Mark")]
    pub iis_clearance_mark: String, // 通關方式
    #[serde(rename = "IIS_Type")]
    pub iis_type: String, // 字軌類別 07/08
    #[serde(rename = "IIS_Category")]
    pub iis_category: serde_json::Value, // 發票種類
    #[serde(rename = "IIS_Tax_Type")]
    pub iis_tax_type: String, // 課稅類別
    #[serde(rename = "ZeroTaxRateReason")]
    pub zero_tax_rate_reason: String, // 零稅率原因
    #[serde(rename = "SpecialTaxType")]
    pub special_tax_type: serde_json::Value, // 特種稅額類別
    #[serde(rename = "IIS_Tax_Rate")]
    pub iis_tax_rate: serde_json::Value, // 稅率
    #[serde(rename = "IIS_Tax_Amount")]
    pub iis_tax_amount: serde_json::Value, // 稅額
    #[serde(rename = "IIS_Sales_Amount")]
    pub iis_sales_amount: serde_json::Value, // 發票金額
    #[serde(rename = "IIS_Check_Number")]
    pub iis_check_number: String, // 檢查碼
    #[serde(rename = "IIS_Carrier_Type")]
    pub iis_carrier_type: String, // 載具類別
    #[serde(rename = "IIS_Carrier_Num")]
    pub iis_carrier_num: String, // 載具編號
    #[serde(rename = "IIS_Love_Code")]
    pub iis_love_code: String, // 捐贈碼
    #[serde(rename = "IIS_IP")]
    pub iis_ip: String, // 開立來源 IP
    #[serde(rename = "IIS_Create_Date")]
    pub iis_create_date: String, // 發票開立時間 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "IIS_Issue_Status")]
    pub iis_issue_status: serde_json::Value, // 發票開立狀態
    #[serde(rename = "IIS_Invalid_Status")]
    pub iis_invalid_status: serde_json::Value, // 作廢旗標
    #[serde(rename = "IIS_Upload_Status")]
    pub iis_upload_status: serde_json::Value, // 上傳旗標
    #[serde(rename = "IIS_Upload_Date")]
    pub iis_upload_date: String, // 上傳時間
    #[serde(rename = "IIS_Turnkey_Status")]
    pub iis_turnkey_status: String, // 財政部處理狀態
    #[serde(rename = "IIS_Remain_Allowance_Amt")]
    pub iis_remain_allowance_amt: serde_json::Value, // 剩餘可折讓金額
    #[serde(rename = "IIS_Print_Flag")]
    pub iis_print_flag: String, // 列印註記
    #[serde(rename = "IIS_Award_Flag")]
    pub iis_award_flag: serde_json::Value, // 中獎旗標
    #[serde(rename = "IIS_Award_Type")]
    pub iis_award_type: serde_json::Value, // 中獎獎別
    #[serde(rename = "Items")]
    pub items: Option<Vec<Item>>, // 商品明細
    #[serde(rename = "IIS_Random_Number")]
    pub iis_random_number: String, // 隨機碼
    #[serde(rename = "InvoiceRemark")]
    pub invoice_remark: String, // 發票備註
    #[serde(rename = "PosBarCode")]
    pub pos_bar_code: String, // POS 機用短碼
    #[serde(rename = "QRCode_Left")]
    pub qr_code_left: String, // QRCode 左碼
    #[serde(rename = "QRCode_Right")]
    pub qr_code_right: String, // QRCode 右碼
}

impl Ecpay {
    /// A query: a non-1 RtnCode (e.g. not-found) is a normal result, NOT an
    /// [`crate::ApiError`] — the caller inspects RtnCode directly.
    ///
    /// The struct's 擇一 contract is enforced here: the server picks the
    /// query mode by KEY PRESENCE, so a filled second mode (or a
    /// half-filled `InvoiceNo`/`InvoiceDate` pair) silently breaks the
    /// other — every real invoice answers `RtnCode=2` not-found. Refused
    /// loudly before the envelope, like the crate's other
    /// representable-conflict guards. All-empty is left to the server.
    pub async fn get_issue(&self, input: &GetIssueInput) -> Result<GetIssueOutput> {
        let has_relate = !input.relate_number.is_empty();
        let has_no = !input.invoice_no.is_empty();
        let has_date = !input.invoice_date.is_empty();
        if (has_relate && (has_no || has_date)) || (has_no != has_date) {
            return Err(Error::Validation(
                "GetIssue query modes are mutually exclusive: fill RelateNumber, \
                 or InvoiceNo + InvoiceDate together — never both, never half a pair"
                    .into(),
            ));
        }
        self.call_invoice_api("GetIssue", input).await
    }
}

// --- DelayIssue (延遲開立發票/預約開立) — developers.ecpay.com.tw/15369.md ---
//
// 官方 PHP SDK 範例 example/Invoice/B2C/{DelayIssue,TriggerIssue,
// CancelDelayIssue}.php 沒有涵蓋所有規格頁欄位，本節欄位集合以規格頁為準，
// 逐一在沙盒對真實伺服器驗證過(見 tests/sandbox.rs)。

/// 延遲開立發票的輸入參數。欄位與 [`IssueInput`] 相同，外加
/// `DelayFlag`/`DelayDay`/`Tsr`/`PayType`/`PayAct`/`NotifyURL` 等延遲開立
/// 專屬欄位。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DelayIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "RelateNumber")]
    pub relate_number: String,
    #[serde(rename = "ChannelPartner")]
    pub channel_partner: String,
    #[serde(rename = "CustomerID")]
    pub customer_id: String,
    #[serde(rename = "ProductServiceID")]
    pub product_service_id: String,
    #[serde(rename = "CustomerIdentifier")]
    pub customer_identifier: String,
    #[serde(rename = "CustomerName")]
    pub customer_name: String,
    #[serde(rename = "CustomerAddr")]
    pub customer_addr: String,
    #[serde(rename = "CustomerPhone")]
    pub customer_phone: String,
    #[serde(rename = "CustomerEmail")]
    pub customer_email: String,
    #[serde(rename = "ClearanceMark")]
    pub clearance_mark: ClearanceMark,
    #[serde(rename = "Print")]
    pub print: PrintMark,
    #[serde(rename = "Donation")]
    pub donation: Donation,
    #[serde(rename = "LoveCode")]
    pub love_code: String,
    #[serde(rename = "CarrierType")]
    pub carrier_type: CarrierType,
    #[serde(rename = "CarrierNum")]
    pub carrier_num: String,
    #[serde(rename = "CarrierNum2")]
    pub carrier_num2: String,
    #[serde(rename = "TaxType")]
    pub tax_type: TaxType,
    #[serde(rename = "ZeroTaxRateReason")]
    pub zero_tax_rate_reason: String,
    #[serde(rename = "SpecialTaxType")]
    pub special_tax_type: i64,
    #[serde(rename = "SalesAmount")]
    pub sales_amount: i64,
    #[serde(rename = "TaxAmount", skip_serializing_if = "Option::is_none")]
    pub tax_amount: Option<i64>,
    #[serde(rename = "InvoiceRemark")]
    pub invoice_remark: String,
    #[serde(rename = "Items")]
    pub items: Option<Vec<Item>>,
    #[serde(rename = "InvType")]
    pub inv_type: InvType,
    #[serde(rename = "vat")]
    pub vat: String,
    /// 1:延遲開立(等候手動/排程觸發) 2:排程觸發開立
    #[serde(rename = "DelayFlag")]
    pub delay_flag: String,
    /// 延遲天數：`DelayFlag=1` 時為 1~15，`DelayFlag=2` 時為 0~15。
    #[serde(rename = "DelayDay")]
    pub delay_day: i64,
    /// 交易單號，須唯一不可重複；[`Ecpay::trigger_issue`]／
    /// [`Ecpay::cancel_delay_issue`] 皆以此欄位為查詢鍵。
    #[serde(rename = "Tsr")]
    pub tsr: String,
    /// 固定值 `"2"`。
    #[serde(rename = "PayType")]
    pub pay_type: String,
    /// 固定值 `"ECPAY"`。
    #[serde(rename = "PayAct")]
    pub pay_act: String,
    #[serde(rename = "NotifyURL")]
    pub notify_url: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DelayIssueOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String, // 回應訊息
    /// 成功時回傳請求帶入的 Tsr；失敗時為空值。
    #[serde(rename = "OrderNumber")]
    pub order_number: String,
}

impl Ecpay {
    /// 延遲開立發票。A command: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn delay_issue(&self, input: &DelayIssueInput) -> Result<DelayIssueOutput> {
        // Same negative-amount stance as `issue` (zero stays allowed).
        if input.sales_amount < 0 {
            return Err(Error::Validation("SalesAmount cannot be negative.".into()));
        }
        let output: DelayIssueOutput = self.call_invoice_api("DelayIssue", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- TriggerIssue (觸發開立發票) — developers.ecpay.com.tw/15371.md ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TriggerIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "Tsr")]
    pub tsr: String, // 交易單號，需與 DelayIssue 的 Tsr 相同
    /// 固定值 `"2"`。
    #[serde(rename = "PayType")]
    pub pay_type: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TriggerIssueOutput {
    /// 4000003:已排入延遲開立 4000004:立即開立成功；其餘為失敗。
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    #[serde(rename = "Tsr")]
    pub tsr: String, // 成功時回傳 Tsr；失敗時為空值
}

impl Ecpay {
    /// TriggerIssue 沒有單一的成功代碼(4000003/4000004 皆代表成功)，不適用
    /// 本檔其他指令類 API 的「RtnCode 非 1 即視為錯誤」判斷，故比照查詢類
    /// API 直接把回應原樣交給呼叫端自行檢查 RtnCode。
    pub async fn trigger_issue(&self, input: &TriggerIssueInput) -> Result<TriggerIssueOutput> {
        self.call_invoice_api("TriggerIssue", input).await
    }
}

// --- CancelDelayIssue (取消延遲開立發票) — developers.ecpay.com.tw/15382.md ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CancelDelayIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "Tsr")]
    pub tsr: String, // 交易單號，需與 DelayIssue 的 Tsr 相同
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CancelDelayIssueOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64, // 回應代碼 1 為成功，其餘為失敗
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
}

impl Ecpay {
    /// 取消延遲開立。A command: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn cancel_delay_issue(
        &self,
        input: &CancelDelayIssueInput,
    ) -> Result<CancelDelayIssueOutput> {
        let output: CancelDelayIssueOutput =
            self.call_invoice_api("CancelDelayIssue", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- GetInvalid (查詢作廢發票明細) — developers.ecpay.com.tw/7933.md ---
//
// 與 GetIssue 不同：規格頁與官方 PHP 範例(GetInvalid.php)都是三個欄位一起
// 帶入(RelateNumber + InvoiceNo + InvoiceDate)，不是 GetIssue 那種互斥的
// 兩種查詢模式，故不套用 skip_serializing_if 技巧。

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "RelateNumber")]
    pub relate_number: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String, // 格式為 yyyy-MM-dd
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetInvalidOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    #[serde(rename = "ChannelPartner")]
    pub channel_partner: String,
    #[serde(rename = "IIS_Mer_ID")]
    pub iis_mer_id: serde_json::Value,
    #[serde(rename = "II_Invoice_No")]
    pub ii_invoice_no: String,
    #[serde(rename = "II_Date")]
    pub ii_date: String, // 作廢時間 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "II_Upload_Status")]
    pub ii_upload_status: serde_json::Value,
    #[serde(rename = "II_Upload_Date")]
    pub ii_upload_date: String,
    #[serde(rename = "Reason")]
    pub reason: String,
    #[serde(rename = "II_Seller_Identifier")]
    pub ii_seller_identifier: String,
    #[serde(rename = "II_Buyer_Identifier")]
    pub ii_buyer_identifier: String,
}

impl Ecpay {
    /// A query: a non-1 RtnCode is returned verbatim, not raised as an error.
    pub async fn get_invalid(&self, input: &GetInvalidInput) -> Result<GetInvalidOutput> {
        self.call_invoice_api("GetInvalid", input).await
    }
}

// --- CheckLoveCode (捐贈碼驗證) — developers.ecpay.com.tw/7891.md ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckLoveCodeInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LoveCode")]
    pub love_code: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckLoveCodeOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    /// 回應代碼 RtnCode 為 1(成功)時，請再判斷此欄位值 Y:存在 N:不存在
    #[serde(rename = "IsExist")]
    pub is_exist: String,
    /// 僅在 `IsExist="Y"` 時有值。
    #[serde(rename = "OrganName")]
    pub organ_name: String,
}

impl Ecpay {
    /// A query: a non-1 RtnCode is returned verbatim, not raised as an error.
    pub async fn check_love_code(&self, input: &CheckLoveCodeInput) -> Result<CheckLoveCodeOutput> {
        self.call_invoice_api("CheckLoveCode", input).await
    }
}

// --- 折讓(Allowance)系列 ---

/// 折讓專屬的商品明細。欄位集合與 [`Item`] 不同(無 `ItemRemark`)，故獨立
/// 定義以與官方規格逐欄位一致。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceItem {
    #[serde(rename = "ItemSeq")]
    pub item_seq: i64,
    #[serde(rename = "ItemName")]
    pub item_name: String,
    #[serde(rename = "ItemCount", with = "crate::crypto::finite_f64")]
    pub item_count: f64,
    #[serde(rename = "ItemWord")]
    pub item_word: String,
    #[serde(rename = "ItemPrice", with = "crate::crypto::finite_f64")]
    pub item_price: f64,
    #[serde(rename = "ItemTaxType")]
    pub item_tax_type: String,
    #[serde(rename = "ItemAmount", with = "crate::crypto::finite_f64")]
    pub item_amount: f64,
}

// --- Allowance (開立折讓，紙本開立) — developers.ecpay.com.tw/7901.md ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String,
    /// 折讓通知方式 S:簡訊 E:電子郵件 A:皆通知 N:皆不通知
    #[serde(rename = "AllowanceNotify")]
    pub allowance_notify: String,
    #[serde(rename = "CustomerName")]
    pub customer_name: String,
    /// `AllowanceNotify="E"` 時為必填
    #[serde(rename = "NotifyMail")]
    pub notify_mail: String,
    /// `AllowanceNotify="S"` 時為必填
    #[serde(rename = "NotifyPhone")]
    pub notify_phone: String,
    #[serde(rename = "AllowanceAmount")]
    pub allowance_amount: i64,
    #[serde(rename = "Reason")]
    pub reason: String,
    #[serde(rename = "Items")]
    pub items: Option<Vec<AllowanceItem>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    /// 若開立成功則回傳折讓編號；若失敗則為空值。
    #[serde(rename = "IA_Allow_No")]
    pub ia_allow_no: String,
    #[serde(rename = "IA_Invoice_No")]
    pub ia_invoice_no: String,
    #[serde(rename = "IA_Date")]
    pub ia_date: String, // 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "IA_Remain_Allowance_Amt")]
    pub ia_remain_allowance_amt: serde_json::Value,
}

impl Ecpay {
    /// 開立折讓。A command: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn allowance(&self, input: &AllowanceInput) -> Result<AllowanceOutput> {
        let output: AllowanceOutput = self.call_invoice_api("Allowance", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- AllowanceInvalid (作廢折讓) — developers.ecpay.com.tw/7911.md ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String,
    #[serde(rename = "Reason")]
    pub reason: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInvalidOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    /// 若作廢成功則回傳發票號碼；若失敗則為空值。
    #[serde(rename = "IA_Invoice_No")]
    pub ia_invoice_no: String,
}

impl Ecpay {
    /// 作廢折讓。A command: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn allowance_invalid(
        &self,
        input: &AllowanceInvalidInput,
    ) -> Result<AllowanceInvalidOutput> {
        let output: AllowanceInvalidOutput =
            self.call_invoice_api("AllowanceInvalid", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- AllowanceByCollegiate (線上開立折讓/合意折讓，需買受人於
// ReturnURL 頁面確認才會真正生效) — developers.ecpay.com.tw/15391.md ---
//
// 買受人完成確認後，ECPay 會另外對 `return_url` 發出 Server-to-Server 的
// form-urlencoded POST 通知(非 AES 信封，含 CheckMacValue)——那是收件端
// (商店自己的伺服器)要處理的 webhook，屬於官方 PHP 範例
// GetAllowanceByCollegiateResponse.php 說明的範疇，不是這個 SDK 對外發出
// 的呼叫，故本檔不提供剖析該 callback 的型別(與 GetInvoicedResponse.php
// 對應的 DelayIssue 完成通知同理)。

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceByCollegiateInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String,
    /// 固定值 `"E"`。
    #[serde(rename = "AllowanceNotify")]
    pub allowance_notify: String,
    #[serde(rename = "CustomerName")]
    pub customer_name: String,
    #[serde(rename = "NotifyMail")]
    pub notify_mail: String,
    #[serde(rename = "AllowanceAmount")]
    pub allowance_amount: i64,
    #[serde(rename = "Reason")]
    pub reason: String,
    /// 買受人於折讓確認頁完成動作後，ECPay 以 Server-to-Server POST 通知的
    /// 網址(見上方模組註解)。
    #[serde(rename = "ReturnURL")]
    pub return_url: String,
    #[serde(rename = "Items")]
    pub items: Option<Vec<AllowanceItem>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceByCollegiateOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    #[serde(rename = "IA_Allow_No")]
    pub ia_allow_no: String,
    #[serde(rename = "IA_Invoice_No")]
    pub ia_invoice_no: String,
    #[serde(rename = "IA_TempDate")]
    pub ia_temp_date: String, // 建立時間 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "IA_TempExpireDate")]
    pub ia_temp_expire_date: String, // 確認期限 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "IA_Remain_Allowance_Amt")]
    pub ia_remain_allowance_amt: serde_json::Value,
}

impl Ecpay {
    /// 線上開立折讓(合意折讓)。A command: a non-success RtnCode surfaces
    /// as a [`crate::ApiError`] rather than being silently swallowed.
    pub async fn allowance_by_collegiate(
        &self,
        input: &AllowanceByCollegiateInput,
    ) -> Result<AllowanceByCollegiateOutput> {
        let output: AllowanceByCollegiateOutput = self
            .call_invoice_api("AllowanceByCollegiate", input)
            .await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- AllowanceInvalidByCollegiate (取消線上折讓) —
// developers.ecpay.com.tw/7913.md。
//
// 官方 PHP SDK 沒有這支端點的範例(SDK_PHP 只有 AllowanceInvalid.php)，
// 容易誤以為線上折讓也是用 AllowanceInvalid 取消，但規格頁明確記載這是
// 另一個獨立端點 `/B2CInvoice/AllowanceInvalidByCollegiate`。

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInvalidByCollegiateInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String,
    #[serde(rename = "Reason")]
    pub reason: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInvalidByCollegiateOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    /// 若取消成功則回傳發票號碼；若失敗則為空值。
    #[serde(rename = "IA_Invoice_No")]
    pub ia_invoice_no: String,
}

impl Ecpay {
    /// 取消線上折讓(獨立端點 `AllowanceInvalidByCollegiate`,勿用
    /// `allowance_invalid`)。A command: a non-success RtnCode surfaces as a
    /// [`crate::ApiError`] rather than being silently swallowed.
    pub async fn allowance_invalid_by_collegiate(
        &self,
        input: &AllowanceInvalidByCollegiateInput,
    ) -> Result<AllowanceInvalidByCollegiateOutput> {
        let output: AllowanceInvalidByCollegiateOutput = self
            .call_invoice_api("AllowanceInvalidByCollegiate", input)
            .await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}

// --- GetAllowance (查詢折讓明細) — developers.ecpay.com.tw/7928.md ---

/// ECPay 沙盒實測(2026-09,公開測試特店 2000132)與規格頁(7928.md)有兩處
/// 落差：
/// 1. `AllowanceNo` 與 `InvoiceNo` 實測不論 `SearchType` 為何都必填(規格頁
///    只說 `SearchType="0"` 時 `AllowanceNo` 必填、`SearchType="1"/"2"` 時
///    `InvoiceNo` 必填)，任一留空都會被伺服器拒絕(分別回
///    `RtnCode=2014003 折讓編號為必填` 與 `RtnCode=2014001 發票號碼為必填`)。
///    `Date` 未單獨測試是否也強制必填，帶入不影響已驗證過的查詢皆成功。
/// 2. 回應不是規格頁講的 `AllowanceInfo: Array[Object]`，而是把折讓欄位
///    直接攤平在 Data 最外層(單筆查詢，不是清單)——見
///    [`GetAllowanceOutput`] 的欄位設計。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 查詢方式 0:以折讓編號 1:以發票號碼+開立日期 2:以發票號碼+折讓日期
    /// (三種模式沙盒實測皆需同時帶 `AllowanceNo` 與 `InvoiceNo`，見本型別
    /// 的文件註解)
    #[serde(rename = "SearchType")]
    pub search_type: String,
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    /// 格式為 yyyy-MM-dd
    #[serde(rename = "Date")]
    pub date: String,
}

/// [`GetAllowanceOutput::items`] 陣列元素裡的商品明細，欄位集合與
/// [`AllowanceItem`] 不同(多了 `ItemRateAmt`)，故獨立定義。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowanceInfoItem {
    #[serde(rename = "ItemSeq")]
    pub item_seq: i64,
    #[serde(rename = "ItemName")]
    pub item_name: String,
    #[serde(rename = "ItemCount", with = "crate::crypto::finite_f64")]
    pub item_count: f64,
    #[serde(rename = "ItemWord")]
    pub item_word: String,
    #[serde(rename = "ItemPrice", with = "crate::crypto::finite_f64")]
    pub item_price: f64,
    #[serde(rename = "ItemRateAmt")]
    pub item_rate_amt: serde_json::Value,
    #[serde(rename = "ItemTaxType")]
    pub item_tax_type: String,
    #[serde(rename = "ItemAmount", with = "crate::crypto::finite_f64")]
    pub item_amount: f64,
}

/// 查詢折讓明細的回傳參數。
///
/// 規格頁(7928.md)記載欄位包在 `AllowanceInfo: Array[Object]` 底下，但
/// 沙盒實測(2026-09)回應把這些欄位直接攤平在最外層，沒有 `AllowanceInfo`
/// 這個 key——與請求端 `AllowanceNo` 恆為必填的實測結果一致：這支 API
/// 實際上永遠是「查一筆特定折讓單的明細」，不是清單查詢，故用單一物件
/// 而非陣列回傳合理。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    #[serde(rename = "ChannelPartner")]
    pub channel_partner: String,
    #[serde(rename = "IA_Allow_No")]
    pub ia_allow_no: String,
    #[serde(rename = "IA_Check_Send_Mail")]
    pub ia_check_send_mail: String,
    #[serde(rename = "IA_Date")]
    pub ia_date: String,
    #[serde(rename = "Items")]
    pub items: Option<Vec<AllowanceInfoItem>>,
    #[serde(rename = "IA_IP")]
    pub ia_ip: String,
    #[serde(rename = "IA_Identifier")]
    pub ia_identifier: String,
    #[serde(rename = "IA_Invalid_Status")]
    pub ia_invalid_status: serde_json::Value,
    #[serde(rename = "IA_Invoice_Issue_Date")]
    pub ia_invoice_issue_date: String,
    #[serde(rename = "IA_Invoice_No")]
    pub ia_invoice_no: String,
    #[serde(rename = "IA_Mer_ID")]
    pub ia_mer_id: serde_json::Value,
    #[serde(rename = "IA_Send_Mail")]
    pub ia_send_mail: String,
    #[serde(rename = "IA_Send_Phone")]
    pub ia_send_phone: String,
    #[serde(rename = "IA_Tax_Amount")]
    pub ia_tax_amount: serde_json::Value,
    #[serde(rename = "IA_Tax_Type")]
    pub ia_tax_type: String,
    #[serde(rename = "IA_Total_Amount")]
    pub ia_total_amount: serde_json::Value,
    #[serde(rename = "IA_Total_Tax_Amount")]
    pub ia_total_tax_amount: serde_json::Value,
    #[serde(rename = "IA_Upload_Date")]
    pub ia_upload_date: String,
    #[serde(rename = "IA_Upload_Status")]
    pub ia_upload_status: serde_json::Value,
    #[serde(rename = "IIS_Customer_Name")]
    pub iis_customer_name: String,
}

impl Ecpay {
    /// A query: a non-1 RtnCode is returned verbatim, not raised as an error.
    ///
    /// 端點名稱有兩個互相矛盾的官方來源：PHP SDK 範例(`GetAllowance.php`)
    /// 打 `/B2CInvoice/GetAllowance`；規格頁(7928.md)寫
    /// `/B2CInvoice/GetAllowanceList`。沙盒實測確認 `GetAllowance` 是對的
    /// (能收到正常的 JSON 查詢結果，不是 ECPay 的一般錯誤頁)。
    pub async fn get_allowance(&self, input: &GetAllowanceInput) -> Result<GetAllowanceOutput> {
        self.call_invoice_api("GetAllowance", input).await
    }
}

// --- GetAllowanceInvalid (查詢作廢折讓明細) — developers.ecpay.com.tw/7943.md ---

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceInvalidInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "InvoiceNo")]
    pub invoice_no: String,
    #[serde(rename = "AllowanceNo")]
    pub allowance_no: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetAllowanceInvalidOutput {
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    #[serde(rename = "AI_Allow_Date")]
    pub ai_allow_date: String,
    #[serde(rename = "AI_Allow_No")]
    pub ai_allow_no: String,
    #[serde(rename = "AI_Buyer_Identifier")]
    pub ai_buyer_identifier: String,
    #[serde(rename = "AI_Date")]
    pub ai_date: String,
    #[serde(rename = "AI_Invoice_No")]
    pub ai_invoice_no: String,
    /// ECPay 沙盒實測(2026-09)回傳型態是數字，不是規格頁講的字串。
    #[serde(rename = "AI_Mer_ID")]
    pub ai_mer_id: serde_json::Value,
    #[serde(rename = "Reason")]
    pub reason: String,
    #[serde(rename = "AI_Seller_Identifier")]
    pub ai_seller_identifier: String,
    #[serde(rename = "AI_Upload_Date")]
    pub ai_upload_date: String,
    #[serde(rename = "AI_Upload_Status")]
    pub ai_upload_status: serde_json::Value,
}

impl Ecpay {
    /// A query: a non-1 RtnCode is returned verbatim, not raised as an error.
    pub async fn get_allowance_invalid(
        &self,
        input: &GetAllowanceInvalidInput,
    ) -> Result<GetAllowanceInvalidOutput> {
        self.call_invoice_api("GetAllowanceInvalid", input).await
    }
}
