//! The typed B2C e-invoice APIs (Go issue.go, void_with_issue.go, invalid.go,
//! invoice_notify.go, check_barcode.go, get_company_name_by_tax_id.go,
//! get_gov_invoice_word_setting.go, get_invoice_word_setting.go, get_issue.go).
//! JSON field names are ECPay's verbatim spec names — locked by the
//! conformance tests.

use serde::{Deserialize, Serialize};

use crate::error::{api_error, Result};
use crate::Ecpay;

// --- Issue (開立發票) — issue.go ---

/// 開立發票的輸入參數。
/// 欄位與 VoidWithIssueInput 相同，但語意不同（開立 vs 折讓），刻意分開維護。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "RelateNumber")]
    pub relate_number: String, // 特店自訂編號 需為唯一值不可重複使用。 注意事項:請勿使用特殊符號
    #[serde(rename = "CustomerID")]
    pub customer_id: String, // 客戶編號 格式為『英文、數字、下底線』等字元。
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
    pub clearance_mark: String, // 通關方式 1:非經海關出口 2:經海關出口 (TaxType=2 時必填)
    #[serde(rename = "Print")]
    pub print: String, // 列印註記 0:不列印 1:要列印
    #[serde(rename = "Donation")]
    pub donation: String, // 捐贈註記 0:不捐贈 1:要捐贈
    #[serde(rename = "LoveCode")]
    pub love_code: String, // 捐贈碼 (Donation=1 時為必填)
    #[serde(rename = "CarrierType")]
    pub carrier_type: String, // 載具類別 空字串:無載具 1:綠界電子發票載具 2:自然人憑證號碼 3:手機條碼載具
    #[serde(rename = "CarrierNum")]
    pub carrier_num: String, // 載具編號
    #[serde(rename = "TaxType")]
    pub tax_type: String, // 課稅類別 1:應稅 2:零稅率 3:免稅 4:應稅(特種稅率) 9:混合
    #[serde(rename = "SpecialTaxType")]
    pub special_tax_type: i64, // 特種稅額類別
    #[serde(rename = "SalesAmount")]
    pub sales_amount: i64, // 發票總金額(含稅) 金額不可為 0 元。
    #[serde(rename = "InvoiceRemark")]
    pub invoice_remark: String, // 發票備註
    #[serde(rename = "Items")]
    pub items: Option<Vec<Item>>, // 商品 (Go nil slice marshals as null)
    #[serde(rename = "InvType")]
    pub inv_type: String, // 字軌類別 07:一般稅額 08:特種稅額
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
    #[serde(rename = "ItemCount", with = "crate::crypto::go_float")]
    pub item_count: f64, // 商品數量 支援整數 8 位小數 2 位
    #[serde(rename = "ItemWord")]
    pub item_word: String, // 商品單位
    /// 若 vat=0(未稅)，商品金額需為未稅金額 若 vat=1(含稅)，商品金額需為含稅金額
    #[serde(rename = "ItemPrice", with = "crate::crypto::go_float")]
    pub item_price: f64, // 商品單價 支援整數 8 位小數 7 位
    #[serde(rename = "ItemTaxType")]
    pub item_tax_type: String, // 商品課稅別 (TaxType=9 時不可為空)
    #[serde(rename = "ItemAmount", with = "crate::crypto::go_float")]
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
    /// Go `Issue`'s named-return shape: the decoded output ALWAYS comes back
    /// alongside the optional error — the zero output for a transport
    /// failure, but ECPay's real fields (RtnMsg, InvoiceDate) even on a
    /// business-level rejection, which callers persist before surfacing the
    /// error.
    pub async fn issue(&self, input: &IssueInput) -> (IssueOutput, Option<crate::Error>) {
        let output: IssueOutput = match self.call_invoice_api("Issue", input).await {
            Ok(o) => o,
            Err(e) => return (IssueOutput::default(), Some(e)),
        };
        let err = api_error(output.rtn_code, &output.rtn_msg).err();
        (output, err)
    }
}

// --- VoidWithIssue (折讓開立發票) — void_with_issue.go ---

/// 折讓開立發票的輸入參數。
/// 欄位與 IssueInput 相同，但語意不同（折讓 vs 開立），刻意分開維護。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VoidWithIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "RelateNumber")]
    pub relate_number: String,
    #[serde(rename = "CustomerID")]
    pub customer_id: String,
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
    pub clearance_mark: String,
    #[serde(rename = "Print")]
    pub print: String,
    #[serde(rename = "Donation")]
    pub donation: String,
    #[serde(rename = "LoveCode")]
    pub love_code: String,
    #[serde(rename = "CarrierType")]
    pub carrier_type: String,
    #[serde(rename = "CarrierNum")]
    pub carrier_num: String,
    #[serde(rename = "TaxType")]
    pub tax_type: String,
    #[serde(rename = "SpecialTaxType")]
    pub special_tax_type: i64,
    #[serde(rename = "SalesAmount")]
    pub sales_amount: i64,
    #[serde(rename = "InvoiceRemark")]
    pub invoice_remark: String,
    #[serde(rename = "Items")]
    pub items: Option<Vec<Item>>,
    #[serde(rename = "InvType")]
    pub inv_type: String,
    #[serde(rename = "vat")]
    pub vat: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VoidWithIssueOutput {
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
    /// VoidWithIssue (折讓開立) is a command like Issue/Invalid, so a
    /// non-success RtnCode is surfaced as [`crate::ApiError`] rather than
    /// swallowed.
    pub async fn void_with_issue(&self, input: &VoidWithIssueInput) -> Result<VoidWithIssueOutput> {
        let output: VoidWithIssueOutput = self.call_invoice_api("VoidWithIssue", input).await?;
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
    pub reason: String, // 作廢原因
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
    /// VoidWithIssue: a non-success RtnCode surfaces as a
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
    /// 若回應代碼[RtnCode]為 1(成功)時，請再判斷此欄位值 Y:存在 N:不存在
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
    pub inv_type: String, // 字軌類別 07:一般稅額發票 08:特種稅額發票
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
    pub inv_type: String, // 字軌類別 07:一般稅額發票，08:特種稅額發票
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
    pub inv_type: String, // 字軌類別 07:一般稅額發票，08:特種稅額發票
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
    pub async fn get_invoice_word_setting(
        &self,
        input: &GetInvoiceWordSettingInput,
    ) -> Result<GetInvoiceWordSettingOutput> {
        self.call_invoice_api("GetInvoiceWordSetting", input).await
    }
}

// --- GetIssue (查詢發票開立資訊) — get_issue.go ---

/// 查詢發票開立資訊的輸入參數。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetIssueInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String, // 特店編號
    #[serde(rename = "RelateNumber")]
    pub relate_number: String, // 特店自訂編號（即 OrderID）
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
    #[serde(rename = "IIS_Number")]
    pub iis_number: String, // 發票號碼
    #[serde(rename = "IIS_Relate_Number")]
    pub iis_relate_number: String, // 特店自訂編號
    #[serde(rename = "IIS_Create_Date")]
    pub iis_create_date: String, // 發票開立時間 格式為 yyyy-MM-dd HH:mm:ss
    #[serde(rename = "IIS_Award_Flag")]
    pub iis_award_flag: serde_json::Value, // 中獎旗標
    #[serde(rename = "IIS_Invalid_Status")]
    pub iis_invalid_status: serde_json::Value, // 作廢旗標
    #[serde(rename = "IIS_Upload_Status")]
    pub iis_upload_status: serde_json::Value, // 上傳旗標
    #[serde(rename = "IIS_Sales_Amount")]
    pub iis_sales_amount: serde_json::Value, // 發票金額
    #[serde(rename = "IIS_Issue_Status")]
    pub iis_issue_status: serde_json::Value, // 發票開立狀態
    #[serde(rename = "IIS_Category")]
    pub iis_category: serde_json::Value, // 發票種類
}

impl Ecpay {
    /// A query: a non-1 RtnCode (e.g. not-found) is a normal result, NOT an
    /// [`crate::ApiError`] — the caller inspects RtnCode directly.
    pub async fn get_issue(&self, input: &GetIssueInput) -> Result<GetIssueOutput> {
        self.call_invoice_api("GetIssue", input).await
    }
}

impl Ecpay {
    /// [`Self::issue`] with the idiomatic signature: a business-level
    /// rejection surfaces as [`crate::Error::Api`], transport/decode failures
    /// as their own error. The tuple-returning [`Self::issue`] exists for the
    /// reference caller, which persists ECPay's partial output even on
    /// failure.
    pub async fn try_issue(&self, input: &IssueInput) -> Result<IssueOutput> {
        let output: IssueOutput = self.call_invoice_api("Issue", input).await?;
        api_error(output.rtn_code, &output.rtn_msg)?;
        Ok(output)
    }
}
