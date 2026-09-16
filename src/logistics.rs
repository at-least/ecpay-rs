//! The ECPay logistics families, ported from `ECPay/SDK_PHP`'s example
//! files (`example/Logistics/`) and pinned live against the stage server
//! (2026-09, commit ed87553 probes):
//!
//! 1. **國內物流 Domestic** — form POST with CheckMacValue **MD5**
//!    (`EncryptType=0`, the only family that signs with MD5). Server-to-server
//!    calls return a CheckMacValue-signed query string; `Express/Create`'s
//!    response additionally carries a leading `<status>|` segment (live
//!    verified: `1|AllPayLogisticsID=...`) that is NOT part of the signed
//!    data. Browser flows (電子地圖 map, 列印 print, 測試資料 test data) are
//!    auto-submitting forms built by [`LogisticsForm`].
//! 2. **全方位物流 AllInOne v2** — AES-JSON envelope whose RqHeader carries
//!    `Timestamp` + `Revision: "1.0.0"`, signed with the logistics
//!    HashKey/HashIV. Endpoints live under `Express/v2/`.
//! 3. **跨境物流 CrossBorder** — the same AES-JSON envelope under
//!    `CrossBorder/`; the 電子地圖 form is the one browser form posted
//!    WITHOUT a CheckMacValue (official `AutoSubmitFormService`, not
//!    `AutoSubmitFormWithCmvService`).
//!
//! Accounts matter: B2C domestic merchants (stage: 2000132) and C2C
//! (stage: 2000933) have DIFFERENT merchant IDs and keys — configure
//! [`Ecpay::logistics_hash_key`] / [`Ecpay::logistics_hash_iv`] (falls back
//! to the payment pair when empty) and call with the matching merchant.
//! AllInOne v2 / CrossBorder use the logistics AES keys (stage 2000132:
//! `5294y06JbISpM5x9`/`v77hoKGq4kWxNNIS`).
//!
//! Untyped `serde_json::Value` outputs mark endpoints whose response field
//! sets are not yet pinned by live captures; typed ones below are.

use std::collections::{BTreeMap, HashMap};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{render_auto_submit_form, unix_now};
use crate::crypto::{check_mac_value, verify_mac};
use crate::error::{Error, Result};
use crate::Ecpay;

// --- LogisticsForm — the browser auto-submit flow builder ---

/// An auto-submitting HTML form for ECPay's browser flows (電子地圖、列印
/// 交貨便/出貨單、產生測試資料、物流選擇). Render it into a page response;
/// the user's browser POSTs the signed fields to ECPay. Attribute values are
/// HTML-escaped like [`crate::payment::AioCheckOut::html_form`].
#[derive(Debug, Clone)]
pub struct LogisticsForm {
    action: String,
    pairs: Vec<(String, String)>,
}

impl LogisticsForm {
    /// The endpoint the form POSTs to.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The signed field pairs (including `CheckMacValue` when the flow signs).
    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// Auto-submitting HTML form, same contract as the checkout form.
    pub fn html_form(&self) -> String {
        render_auto_submit_form(self.action(), &self.pairs)
    }

    /// Consume into the raw key/value pairs (for your own form rendering).
    pub fn into_pairs(self) -> Vec<(String, String)> {
        self.pairs
    }
}

// --- Shared internals ---

/// Splits a logistics `1|k=v&...` response into the leading status segment
/// (absent for the plain-query responders like
/// `Helper/QueryLogisticsTradeInfo/V2`) and the query fields. The `1|`
/// segment is NOT part of the signed data (live-verified byte-exact against
/// stage: signing the prefixed key never matches).
fn split_status_prefix(body: &str) -> (Option<String>, &str) {
    match body.split_once('|') {
        // A status prefix only exists when the head segment is a short
        // alphanumeric status token (never empty, never carrying '=' —
        // otherwise `1|` would sit inside the first VALUE, not the key).
        Some((head, rest))
            if !head.is_empty()
                && head.len() <= 3
                && !head.contains('=')
                && head.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            (Some(head.to_owned()), rest)
        }
        _ => (None, body),
    }
}

impl Ecpay {
    /// Signs `params` with the logistics keys and MD5 (`EncryptType=0` —
    /// the ONLY service family using MD5), appends CheckMacValue.
    fn sign_logistics(&self, params: &mut HashMap<String, String>) -> Result<()> {
        let (key, iv) = self.logistics_keys();
        let mac = check_mac_value(params, key, iv, 0)?;
        params.insert("CheckMacValue".to_owned(), mac);
        Ok(())
    }

    /// POSTs a signed logistics form call and decodes the response: strips
    /// the optional `1|` status prefix, parses the query string, verifies the
    /// response CheckMacValue (MD5, over the fields as received), and returns
    /// the fields without CheckMacValue.
    async fn post_logistics_form(
        &self,
        endpoint: String,
        mut params: HashMap<String, String>,
    ) -> Result<BTreeMap<String, String>> {
        self.sign_logistics(&mut params)?;
        let (http_status, body) = self.post_form_raw(&endpoint, &params).await?;
        let text = String::from_utf8_lossy(&body);
        let (status, query) = split_status_prefix(&text);
        // Server-truth (2026-09): business errors arrive as a SHORT UNSIGNED
        // string after the status prefix (`0|ReceiverStoreID Is Null`,
        // `0|TimeStamp Is Expired` on HTTP 200; `0|找不到訂單`,
        // `0|CheckMacValue驗證錯誤` on HTTP 500) — no '=' anywhere, so it never
        // parses as a query. It is the protocol's own error shape, so surface
        // it verbatim on any HTTP status, before the non-2xx gate below.
        if status.is_some() && !query.contains('=') {
            let status = status.unwrap_or_default();
            return Err(Error::Message(format!(
                "ecpay logistics: status {status}: {}",
                query.trim()
            )));
        }
        if !(200..300).contains(&http_status) {
            return Err(Error::PaymentStatus {
                status: http_status,
                body: text.into_owned(),
            });
        }
        // An HTML/text error page on a 2xx has no status prefix and no '='
        // (parse_qsl would read it as one valueless key and the missing MAC
        // would then look like a mismatch) — surface the raw body instead.
        if !query.contains('=') {
            return Err(Error::Message(format!(
                "ecpay logistics: response is not a signed query: {text:?}"
            )));
        }
        let mut fields = crate::client::parse_qsl(query);
        // Business errors still come back as a signed query (RtnCode inside);
        // a body with no CheckMacValue at all is an HTML/text error page.
        let got = fields
            .remove("CheckMacValue")
            .filter(|v| !v.is_empty())
            .ok_or(Error::CheckMacValueMismatch)?;
        let (key, iv) = self.logistics_keys();
        if !verify_mac(&got, crate::crypto::str_pairs(&fields), key, iv, 0)? {
            return Err(Error::CheckMacValueMismatch);
        }
        if let Some(status) = status {
            // Keep the status segment reachable without lying about the wire:
            // Express/Create answers `1|...` where `1` means processed.
            fields.insert("_status_prefix".to_owned(), status);
        }
        Ok(fields)
    }

    /// Core AES-JSON call for logistics v2 / CrossBorder: RqHeader carries
    /// `Timestamp` + `Revision: "1.0.0"`, signed with the logistics keys.
    /// `path` is appended to the logistics base verbatim, e.g.
    /// `Express/v2/QueryLogisticsTradeInfo` or `CrossBorder/Create`.
    /// `data_merchant_id` is the input's own `MerchantID` field when its
    /// struct carries one (the official-examples convention): empty or
    /// envelope-mismatched values are refused locally, because ECPay answers
    /// them with an opaque `RtnCode != 1` and no message. Inputs without a
    /// `MerchantID` field pass `None`.
    pub(crate) async fn post_logistics_aes<I: Serialize, O: DeserializeOwned>(
        &self,
        path: &str,
        data_merchant_id: Option<&str>,
        input: &I,
    ) -> Result<O> {
        if let Some(mid) = data_merchant_id {
            self.require_data_merchant_id_with(mid, "")?;
        }
        let endpoint = format!("{}{}", self.logistics_base_url(), path);
        let rq_header = serde_json::json!({
            "Timestamp": unix_now(),
            "Revision": "1.0.0",
        });
        let (key, iv) = self.logistics_keys();
        self.post_aes_json(
            &endpoint,
            rq_header,
            &self.merchant_id,
            input,
            key.as_bytes(),
            iv.as_bytes(),
        )
        .await
    }

    /// The two v2 BROWSER-flow endpoints answer raw text/html (live-captured
    /// 2026-09), not an AES envelope — see [`Self::post_aes_json_raw`].
    /// `data_merchant_id` follows [`Self::post_logistics_aes`].
    pub(crate) async fn post_logistics_aes_raw(
        &self,
        path: &str,
        data_merchant_id: Option<&str>,
        input: &impl Serialize,
    ) -> Result<String> {
        if let Some(mid) = data_merchant_id {
            self.require_data_merchant_id_with(mid, "")?;
        }
        let endpoint = format!("{}{}", self.logistics_base_url(), path);
        let rq_header = serde_json::json!({
            "Timestamp": unix_now(),
            "Revision": "1.0.0",
        });
        let (key, iv) = self.logistics_keys();
        self.post_aes_json_raw(
            &endpoint,
            rq_header,
            &self.merchant_id,
            input,
            key.as_bytes(),
            iv.as_bytes(),
        )
        .await
    }
}

// --- 國內物流 Domestic: server-to-server APIs (CMV-MD5 form) ---

/// `Express/Create` (物流訂單建立) 的輸入。CVS 與宅配(HOME)共用一個端點:
/// CVS 需要 `receiver_store_id`(由電子地圖 [`Ecpay::logistics_map_form`]
/// 取得),宅配需要 `sender_zip_code`/`sender_address`/`receiver_zip_code`/
/// `receiver_address` 與 `temperature`/`distance`/`specification`/
/// `scheduled_*` 家數欄位。欄位限制見官方文件 developers.ecpay.com.tw/7400.md。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogisticsCreateInput {
    /// 特店交易編號 (merchant_trade_no), maxlength 20
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    /// 特店交易時間 yyyy/MM/dd HH:mm:ss (UTC+8)
    #[serde(rename = "MerchantTradeDate")]
    pub merchant_trade_date: String,
    /// 物流類別 CVS:超商取貨 / HOME:宅配
    #[serde(rename = "LogisticsType")]
    pub logistics_type: String,
    /// 物流子類別:CvsType FAMI/UNIMART/HILIFE/OKMART/UNIMARTFREEZE(冷鏈);
    /// 宅配 TCAT(黑貓)/ECAN
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
    /// 商品金額 0 ~ 20,000 元(C2C 部分子類別上限不同,以官方文件為準)
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    /// 商品名稱 maxlength 50
    #[serde(rename = "GoodsName")]
    pub goods_name: String,
    /// 寄件人姓名 maxlength 10(中文 5 個字)
    #[serde(rename = "SenderName")]
    pub sender_name: String,
    /// 寄件人手機 maxlength 20,格式數字(部分子類別需含國碼)
    #[serde(rename = "SenderCellPhone")]
    pub sender_cell_phone: String,
    /// 寄件人郵遞區號(HOME 必填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "SenderZipCode")]
    pub sender_zip_code: Option<String>,
    /// 寄件人地址(HOME 必填)maxlength 60
    #[serde(skip_serializing_if = "Option::is_none", rename = "SenderAddress")]
    pub sender_address: Option<String>,
    /// 收件人姓名 maxlength 10
    #[serde(rename = "ReceiverName")]
    pub receiver_name: String,
    /// 收件人手機 maxlength 20
    #[serde(rename = "ReceiverCellPhone")]
    pub receiver_cell_phone: String,
    /// 收件人郵遞區號(HOME 必填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverZipCode")]
    pub receiver_zip_code: Option<String>,
    /// 收件人地址(HOME 必填)maxlength 60
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverAddress")]
    pub receiver_address: Option<String>,
    /// 門市代號(CVS 必填,由電子地圖回傳)maxlength 6
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverStoreID")]
    pub receiver_store_id: Option<String>,
    /// 溫層 0001:常溫 0002:冷凍 0003:冷鏈(HOME 必填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "Temperature")]
    pub temperature: Option<String>,
    /// 距離 00:同縣市 01:外縣市 02:全島(HOME 必填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "Distance")]
    pub distance: Option<String>,
    /// 規格 0001:常溫 0002:冷凍 0003:冷鏈(HOME 必填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "Specification")]
    pub specification: Option<String>,
    /// 預定取件時段 1:9~12 2:12~17 3:17~19 4:19~21 5:不限(HOME 必填)
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "ScheduledPickupTime"
    )]
    pub scheduled_pickup_time: Option<String>,
    /// 預定送達時段(同上,TCAT 不支援 3)(HOME 必填)
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "ScheduledDeliveryTime"
    )]
    pub scheduled_delivery_time: Option<String>,
    /// 物流狀態回報網址(ServerReplyURL,必填;僅支援 80/443 port)
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
    /// 客戶端回覆網址(僅瀏覽器 form 流程使用,見 [`Ecpay::logistics_create_form`])
    #[serde(skip_serializing_if = "Option::is_none", rename = "ClientReplyURL")]
    pub client_reply_url: Option<String>,
}

/// `Helper/GetStoreList`(門市清單查詢)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GetStoreListInput {
    /// 超商類別 All/FAMI/UNIMART/HILIFE/OKMART/UNIMARTFREEZE
    #[serde(rename = "CvsType")]
    pub cvs_type: String,
}

/// `Helper/QueryLogisticsTradeInfo/V2`(查詢物流訂單)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DomesticQueryInput {
    /// 物流交易編號 (AllPayLogisticsID)
    #[serde(rename = "AllPayLogisticsID")]
    pub all_pay_logistics_id: String,
    /// 時間戳(ECPay 拼法 TimeStamp),防止快取;省略則自動帶入當下時間
    #[serde(skip_serializing_if = "Option::is_none", rename = "TimeStamp")]
    pub time_stamp: Option<i64>,
}

/// `Helper/UpdateShipmentInfo`(更新出貨資訊)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateShipmentInfoInput {
    #[serde(rename = "AllPayLogisticsID")]
    pub all_pay_logistics_id: String,
    /// 出貨(交託宅配)日期 yyyy/MM/dd
    #[serde(rename = "ShipmentDate")]
    pub shipment_date: String,
    /// 收件門市代號 — CVS 訂單**必填**(stage 實測 2026-09:CVS 訂單省略時
    /// 回 `0|ReceiverStoreID Is Null`);宅配(HOME)可省略。
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverStoreID")]
    pub receiver_store_id: Option<String>,
}

/// `Express/UpdateStoreInfo`(C2C 更新門市資訊)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateStoreInfoInput {
    #[serde(rename = "AllPayLogisticsID")]
    pub all_pay_logistics_id: String,
    /// 寄件門市代號 (CVSPaymentNo)
    #[serde(rename = "CVSPaymentNo")]
    pub cvs_payment_no: String,
    /// 寄件門市驗證代碼 (CVSValidationNo)
    #[serde(rename = "CVSValidationNo")]
    pub cvs_validation_no: String,
    /// 門市類型 01:原門市寄返 02:全家超商
    #[serde(rename = "StoreType")]
    pub store_type: String,
    /// 新的收件門市代號
    #[serde(rename = "ReceiverStoreID")]
    pub receiver_store_id: String,
}

/// `Express/CancelC2COrder`(C2C 取消物流訂單)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CancelC2cInput {
    #[serde(rename = "AllPayLogisticsID")]
    pub all_pay_logistics_id: String,
    #[serde(rename = "CVSPaymentNo")]
    pub cvs_payment_no: String,
    #[serde(rename = "CVSValidationNo")]
    pub cvs_validation_no: String,
}

/// `express/ReturnCVS` / `express/ReturnUniMartCVS`(逆物流超商退貨)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReturnCvsInput {
    /// 退貨商品金額
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    /// 逆物流服務類型(官方範例帶 '4')
    #[serde(rename = "ServiceType")]
    pub service_type: String,
    /// 寄件人(退貨人)姓名
    #[serde(rename = "SenderName")]
    pub sender_name: String,
    /// 寄件人手機(萊爾富/OK 需填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "SenderCellPhone")]
    pub sender_cell_phone: Option<String>,
    /// 物流狀態回報網址
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

/// `Express/ReturnHome`(宅配逆物流)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReturnHomeInput {
    /// 原物流交易編號
    #[serde(rename = "AllPayLogisticsID")]
    pub all_pay_logistics_id: String,
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    #[serde(rename = "Temperature")]
    pub temperature: String,
    #[serde(rename = "Distance")]
    pub distance: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Specification")]
    pub specification: Option<String>,
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

// --- 國內物流: browser forms ---

/// `Express/map`(電子地圖,消費者選門市)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MapInput {
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    #[serde(rename = "LogisticsType")]
    pub logistics_type: String,
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
    /// 是否代收付款 Y/N
    #[serde(rename = "IsCollection")]
    pub is_collection: String,
    /// 選好門市後地圖回傳的網址(GetMapResponse;此回呼不帶 CheckMacValue)
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

/// C2C 交貨便列印的目標超商(`Ecpay::logistics_print_c2c_form`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintC2c {
    /// 全家: Express/PrintFAMIC2COrderInfo
    Fami,
    /// 萊爾富: Express/PrintHILIFEC2COrderInfo
    Hilife,
    /// 統一超商: Express/PrintUniMartC2COrderInfo
    UniMart,
    /// OK超商: Express/PrintOKMARTC2COrderInfo
    OkMart,
}

impl PrintC2c {
    fn path(self) -> &'static str {
        match self {
            PrintC2c::Fami => "Express/PrintFAMIC2COrderInfo",
            PrintC2c::Hilife => "Express/PrintHILIFEC2COrderInfo",
            PrintC2c::UniMart => "Express/PrintUniMartC2COrderInfo",
            PrintC2c::OkMart => "Express/PrintOKMARTC2COrderInfo",
        }
    }
}

impl Ecpay {
    /// 物流訂單建立 (`Express/Create`,server-to-server)。成功時欄位含
    /// `RtnCode=300`(訂單處理中)、`AllPayLogisticsID`、`BookingNote`/
    /// `CVSPaymentNo`/`CVSValidationNo`(依子類別),實測自 stage 2026-09。
    pub async fn logistics_create(
        &self,
        input: &LogisticsCreateInput,
    ) -> Result<BTreeMap<String, String>> {
        let endpoint = format!("{}Express/Create", self.logistics_base_url());
        self.post_logistics_form(endpoint, self.domestic_base_params(input)?)
            .await
    }

    /// 查詢物流訂單 (`Helper/QueryLogisticsTradeInfo/V2`)。回應為帶
    /// CheckMacValue 的 query string(MD5 驗證後攤平回傳)。
    pub async fn logistics_query_logistics_trade_info(
        &self,
        input: &DomesticQueryInput,
    ) -> Result<BTreeMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            input.all_pay_logistics_id.clone(),
        );
        m.insert(
            "TimeStamp".to_owned(),
            input.time_stamp.unwrap_or_else(unix_now).to_string(),
        );
        let endpoint = format!(
            "{}Helper/QueryLogisticsTradeInfo/V2",
            self.logistics_base_url()
        );
        self.post_logistics_form(endpoint, m).await
    }

    /// 門市清單查詢 (`Helper/GetStoreList`)。回應為 JSON(不帶
    /// CheckMacValue),故回傳 [`serde_json::Value`]。
    pub async fn logistics_get_store_list(&self, input: &GetStoreListInput) -> Result<Value> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("CvsType".to_owned(), input.cvs_type.clone());
        self.sign_logistics(&mut m)?;
        let endpoint = format!("{}Helper/GetStoreList", self.logistics_base_url());
        let body = self.post_form(&endpoint, &m).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// 更新出貨資訊 (`Helper/UpdateShipmentInfo`)。
    pub async fn logistics_update_shipment_info(
        &self,
        input: &UpdateShipmentInfoInput,
    ) -> Result<BTreeMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            input.all_pay_logistics_id.clone(),
        );
        m.insert("ShipmentDate".to_owned(), input.shipment_date.clone());
        if let Some(store) = &input.receiver_store_id {
            m.insert("ReceiverStoreID".to_owned(), store.clone());
        }
        let endpoint = format!("{}Helper/UpdateShipmentInfo", self.logistics_base_url());
        self.post_logistics_form(endpoint, m).await
    }

    /// C2C 更新門市資訊 (`Express/UpdateStoreInfo`)。C2C 特店請以 C2C
    /// 帳號(stage 2000933)呼叫。
    pub async fn logistics_update_store_info(
        &self,
        input: &UpdateStoreInfoInput,
    ) -> Result<BTreeMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            input.all_pay_logistics_id.clone(),
        );
        m.insert("CVSPaymentNo".to_owned(), input.cvs_payment_no.clone());
        m.insert(
            "CVSValidationNo".to_owned(),
            input.cvs_validation_no.clone(),
        );
        m.insert("StoreType".to_owned(), input.store_type.clone());
        m.insert(
            "ReceiverStoreID".to_owned(),
            input.receiver_store_id.clone(),
        );
        let endpoint = format!("{}Express/UpdateStoreInfo", self.logistics_base_url());
        self.post_logistics_form(endpoint, m).await
    }

    /// C2C 取消物流訂單 (`Express/CancelC2COrder`)。
    pub async fn logistics_cancel_c2c_order(
        &self,
        input: &CancelC2cInput,
    ) -> Result<BTreeMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            input.all_pay_logistics_id.clone(),
        );
        m.insert("CVSPaymentNo".to_owned(), input.cvs_payment_no.clone());
        m.insert(
            "CVSValidationNo".to_owned(),
            input.cvs_validation_no.clone(),
        );
        let endpoint = format!("{}Express/CancelC2COrder", self.logistics_base_url());
        self.post_logistics_form(endpoint, m).await
    }

    /// 全家逆物流退貨 (`express/ReturnCVS`,路徑大小寫依官方範例)。
    pub async fn logistics_return_cvs(
        &self,
        input: &ReturnCvsInput,
    ) -> Result<BTreeMap<String, String>> {
        let endpoint = format!("{}express/ReturnCVS", self.logistics_base_url());
        self.post_logistics_form(endpoint, self.return_cvs_params(input))
            .await
    }

    /// 統一超商逆物流退貨 (`express/ReturnUniMartCVS`)。
    pub async fn logistics_return_unimart_cvs(
        &self,
        input: &ReturnCvsInput,
    ) -> Result<BTreeMap<String, String>> {
        let endpoint = format!("{}express/ReturnUniMartCVS", self.logistics_base_url());
        self.post_logistics_form(endpoint, self.return_cvs_params(input))
            .await
    }

    /// 宅配逆物流退貨 (`Express/ReturnHome`)。
    pub async fn logistics_return_home(
        &self,
        input: &ReturnHomeInput,
    ) -> Result<BTreeMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            input.all_pay_logistics_id.clone(),
        );
        m.insert("GoodsAmount".to_owned(), input.goods_amount.to_string());
        m.insert("Temperature".to_owned(), input.temperature.clone());
        m.insert("Distance".to_owned(), input.distance.clone());
        if let Some(spec) = &input.specification {
            m.insert("Specification".to_owned(), spec.clone());
        }
        m.insert("ServerReplyURL".to_owned(), input.server_reply_url.clone());
        let endpoint = format!("{}Express/ReturnHome", self.logistics_base_url());
        self.post_logistics_form(endpoint, m).await
    }

    fn domestic_base_params(
        &self,
        input: &LogisticsCreateInput,
    ) -> Result<HashMap<String, String>> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "MerchantTradeNo".to_owned(),
            input.merchant_trade_no.clone(),
        );
        m.insert(
            "MerchantTradeDate".to_owned(),
            input.merchant_trade_date.clone(),
        );
        m.insert("LogisticsType".to_owned(), input.logistics_type.clone());
        m.insert(
            "LogisticsSubType".to_owned(),
            input.logistics_sub_type.clone(),
        );
        m.insert("GoodsAmount".to_owned(), input.goods_amount.to_string());
        m.insert("GoodsName".to_owned(), input.goods_name.clone());
        m.insert("SenderName".to_owned(), input.sender_name.clone());
        m.insert(
            "SenderCellPhone".to_owned(),
            input.sender_cell_phone.clone(),
        );
        for (k, v) in [
            ("SenderZipCode", &input.sender_zip_code),
            ("SenderAddress", &input.sender_address),
            ("ReceiverZipCode", &input.receiver_zip_code),
            ("ReceiverAddress", &input.receiver_address),
            ("ReceiverStoreID", &input.receiver_store_id),
            ("Temperature", &input.temperature),
            ("Distance", &input.distance),
            ("Specification", &input.specification),
            ("ScheduledPickupTime", &input.scheduled_pickup_time),
            ("ScheduledDeliveryTime", &input.scheduled_delivery_time),
            ("ClientReplyURL", &input.client_reply_url),
        ] {
            if let Some(v) = v {
                m.insert(k.to_owned(), v.clone());
            }
        }
        m.insert("ReceiverName".to_owned(), input.receiver_name.clone());
        m.insert(
            "ReceiverCellPhone".to_owned(),
            input.receiver_cell_phone.clone(),
        );
        m.insert("ServerReplyURL".to_owned(), input.server_reply_url.clone());
        Ok(m)
    }

    fn return_cvs_params(&self, input: &ReturnCvsInput) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("GoodsAmount".to_owned(), input.goods_amount.to_string());
        m.insert("ServiceType".to_owned(), input.service_type.clone());
        m.insert("SenderName".to_owned(), input.sender_name.clone());
        if let Some(phone) = &input.sender_cell_phone {
            m.insert("SenderCellPhone".to_owned(), phone.clone());
        }
        m.insert("ServerReplyURL".to_owned(), input.server_reply_url.clone());
        m
    }

    // --- 國內物流: browser forms ---

    /// 物流訂單建立的瀏覽器版 (`Express/Create` + `ClientReplyURL`):
    /// 消費者導向綠界頁面完成超商取件付款/選店流程。需要
    /// [`LogisticsCreateInput::client_reply_url`]。
    pub fn logistics_create_form(&self, input: &LogisticsCreateInput) -> Result<LogisticsForm> {
        let mut m = self.domestic_base_params(input)?;
        self.sign_logistics(&mut m)?;
        Ok(LogisticsForm {
            action: format!("{}Express/Create", self.logistics_base_url()),
            pairs: m.into_iter().collect(),
        })
    }

    /// 電子地圖選店 (`Express/map`)。消費者選完門市後,綠界 POST 回
    /// `ServerReplyURL`(此回呼不帶 CheckMacValue,官方 GetMapResponse 範例
    /// 即以未簽章 ArrayResponse 接收)。
    pub fn logistics_map_form(&self, input: &MapInput) -> Result<LogisticsForm> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "MerchantTradeNo".to_owned(),
            input.merchant_trade_no.clone(),
        );
        m.insert("LogisticsType".to_owned(), input.logistics_type.clone());
        m.insert(
            "LogisticsSubType".to_owned(),
            input.logistics_sub_type.clone(),
        );
        m.insert("IsCollection".to_owned(), input.is_collection.clone());
        m.insert("ServerReplyURL".to_owned(), input.server_reply_url.clone());
        self.sign_logistics(&mut m)?;
        Ok(LogisticsForm {
            action: format!("{}Express/map", self.logistics_base_url()),
            pairs: m.into_iter().collect(),
        })
    }

    /// 產生 B2C 測試資料 (`Express/CreateTestData`,僅測試環境):
    /// 產生測試用門市/寄件資訊後 POST 回 `ClientReplyURL`。
    pub fn logistics_create_test_data_form(
        &self,
        logistics_sub_type: &str,
        client_reply_url: &str,
    ) -> Result<LogisticsForm> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("LogisticsSubType".to_owned(), logistics_sub_type.to_owned());
        m.insert("ClientReplyURL".to_owned(), client_reply_url.to_owned());
        self.sign_logistics(&mut m)?;
        Ok(LogisticsForm {
            action: format!("{}Express/CreateTestData", self.logistics_base_url()),
            pairs: m.into_iter().collect(),
        })
    }

    /// 列印 B2C 紙本出貨單 (`helper/printTradeDocument`,路徑大小寫依官方範例)。
    pub fn logistics_print_trade_document_form(
        &self,
        all_pay_logistics_id: &str,
    ) -> Result<LogisticsForm> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            all_pay_logistics_id.to_owned(),
        );
        self.sign_logistics(&mut m)?;
        Ok(LogisticsForm {
            action: format!("{}helper/printTradeDocument", self.logistics_base_url()),
            pairs: m.into_iter().collect(),
        })
    }

    /// 列印 C2C 交貨便標籤(全家/萊爾富/統一/OK 四個端點由 [`PrintC2c`]
    /// 選擇)。C2C 特店請以 C2C 帳號呼叫。
    pub fn logistics_print_c2c_form(
        &self,
        target: PrintC2c,
        all_pay_logistics_id: &str,
        cvs_payment_no: &str,
        cvs_validation_no: Option<&str>,
    ) -> Result<LogisticsForm> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "AllPayLogisticsID".to_owned(),
            all_pay_logistics_id.to_owned(),
        );
        m.insert("CVSPaymentNo".to_owned(), cvs_payment_no.to_owned());
        if let Some(v) = cvs_validation_no {
            m.insert("CVSValidationNo".to_owned(), v.to_owned());
        }
        self.sign_logistics(&mut m)?;
        Ok(LogisticsForm {
            action: format!("{}{}", self.logistics_base_url(), target.path()),
            pairs: m.into_iter().collect(),
        })
    }

    // --- Callbacks ---

    /// 驗證國內物流回呼(ServerReplyURL 等)的 CheckMacValue:與金流回呼
    /// 不同,物流回呼一律 **MD5** 且用物流 HashKey/HashIV。
    pub fn verify_logistics_check_mac_value(&self, params: &HashMap<String, String>) -> bool {
        let got = match params.get("CheckMacValue") {
            Some(v) if !v.is_empty() => v,
            _ => return false,
        };
        let (key, iv) = self.logistics_keys();
        verify_mac(got, crate::crypto::str_pairs(params), key, iv, 0).unwrap_or(false)
    }

    /// 解密全方位物流 v2 / 跨境物流的 ServerReplyURL 回呼(整包 JSON POST,
    /// `Data` 為 AES 加密)。`T` 通常接 [`serde_json::Value`] 或自訂型別。
    ///
    /// 錯誤形狀:body 不是帶 `TransCode` 鍵的 JSON 物件(或鍵存在但值不符
    /// 信封型別)時回 [`crate::Error::Message`]——訊息只引用有界、跳脫過的
    /// body 節錄,回呼 body 來自公開端點,不可原樣回灌到 log;`TransCode != 1`
    /// 回 [`crate::Error::TransCode`];解密失敗的**內容相關**分支
    /// (padding/UTF-8/JSON/URL-escape)一律收斂為同一則固定訊息(防 CBC
    /// padding oracle——此端點解密攻擊者可篡改的密文,詳見
    /// [`crate::crypto`] 與 README 回呼處理清單;商戶 handler 應對所有錯誤
    /// 回同一回應並加 rate limit);僅 base64/長度/金鑰長度錯誤保持原樣。
    pub fn decrypt_logistics_callback<T: serde::de::DeserializeOwned>(
        &self,
        posted_json: &str,
    ) -> Result<T> {
        let (key, iv) = self.logistics_keys();
        Self::decode_envelope_opaque(posted_json, key.as_bytes(), iv.as_bytes())
    }

    /// 全方位物流 v2 狀態通知的應答體:綠界要求以同格式(AES 加密 JSON)
    /// 回 `{"RtnCode":"1","RtnMsg":""}`,否則視為失敗重發。回傳值即
    /// HTTP response body(Content-Type: application/json)。
    pub fn logistics_notify_reply(&self) -> Result<String> {
        let (key, iv) = self.logistics_keys();
        let data = crate::crypto::encrypt_data(
            &serde_json::json!({"RtnCode": "1", "RtnMsg": ""}),
            key.as_bytes(),
            iv.as_bytes(),
        )?;
        Ok(serde_json::json!({
            "MerchantID": self.merchant_id,
            "RqHeader": {"Timestamp": unix_now()},
            "TransCode": "1",
            "TransMsg": "",
            "Data": data,
        })
        .to_string())
    }

    /// 解密全方位物流 v2 `ClientReplyURL` 的 `ResultData` 欄位
    /// (TempTradeEstablishedResponse)。前端 form POST 會把 AES JSON 信封
    /// urlencode 進 `ResultData`,此處先做 form 解碼再拆信封、驗 TransCode、
    /// 解密 `Data`。錯誤形狀與 [`Self::decrypt_logistics_callback`] 相同:
    /// 內容相關的解密失敗收斂為同一則固定訊息(padding oracle 防護);
    /// form 解碼失敗(`ResultData` 本身的 % 轉義)回
    /// [`crate::Error::UrlEscape`]——該字串由送出方原樣寫下,攻擊者已知,
    /// 不洩漏明文資訊。
    pub fn decrypt_temp_trade_established<T: serde::de::DeserializeOwned>(
        &self,
        result_data: &str,
    ) -> Result<T> {
        let envelope = crate::crypto::query_unescape(result_data)?;
        self.decrypt_logistics_callback(&envelope)
    }
}

// --- 全方位物流 AllInOne v2 (AES-JSON, Express/v2/) ---

/// `Express/v2/CreateByTempTrade`(以暫存物流訂單建立正式訂單)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateByTempTradeInput {
    /// 暫存物流交易編號 (TempLogisticsID,由 RedirectToLogisticsSelection 流程建立)
    #[serde(rename = "TempLogisticsID")]
    pub temp_logistics_id: String,
}

/// `Express/v2/CreateTestData`(產生 B2C 測試資料,僅測試環境)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneCreateTestDataInput {
    /// 特店編號(官方範例將 MerchantID 放在 Data 內,依樣保留)
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 物流子類別 FAMI/UNIMART/HILIFE/OKMART/UNIMARTFREEZE/TCAT...
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
}

/// `Express/v2/QueryLogisticsTradeInfo`(查詢物流訂單)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneQueryInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 物流交易編號 (LogisticsID)
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
}

/// `Express/v2/UpdateTempTrade`(更新暫存物流訂單)的輸入;僅帶要修改的欄位。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateTempTradeInput {
    #[serde(rename = "TempLogisticsID")]
    pub temp_logistics_id: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "SenderName")]
    pub sender_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "SenderCellPhone")]
    pub sender_cell_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverName")]
    pub receiver_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverCellPhone")]
    pub receiver_cell_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "GoodsAmount")]
    pub goods_amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Temperature")]
    pub temperature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Distance")]
    pub distance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Specification")]
    pub specification: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "ScheduledPickupTime"
    )]
    pub scheduled_pickup_time: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "ScheduledDeliveryTime"
    )]
    pub scheduled_delivery_time: Option<String>,
}

/// `Express/v2/UpdateShipmentInfo` 的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneUpdateShipmentInfoInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
    /// 出貨日期 yyyy/MM/dd
    #[serde(rename = "ShipmentDate")]
    pub shipment_date: String,
}

/// `Express/v2/UpdateStoreInfo`(C2C 更新門市)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneUpdateStoreInfoInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
    #[serde(rename = "CVSPaymentNo")]
    pub cvs_payment_no: String,
    #[serde(rename = "CVSValidationNo")]
    pub cvs_validation_no: String,
    /// 門市類型 01/02
    #[serde(rename = "StoreType")]
    pub store_type: String,
    #[serde(rename = "ReceiverStoreID")]
    pub receiver_store_id: String,
}

/// `Express/v2/CancelC2COrder` 的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneCancelC2cInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
    #[serde(rename = "CVSPaymentNo")]
    pub cvs_payment_no: String,
    #[serde(rename = "CVSValidationNo")]
    pub cvs_validation_no: String,
}

/// `Express/v2/ReturnCVS` / `ReturnHilifeCVS` / `ReturnUniMartCVS` 的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneReturnCvsInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    /// 逆物流服務類型(官方範例帶 '4')
    #[serde(rename = "ServiceType")]
    pub service_type: String,
    #[serde(rename = "SenderName")]
    pub sender_name: String,
    /// 萊爾富需帶 SenderPhone(官方 ReturnHilifeCVS 範例)
    #[serde(skip_serializing_if = "Option::is_none", rename = "SenderPhone")]
    pub sender_phone: Option<String>,
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

/// `Express/v2/ReturnHome` 的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneReturnHomeInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    #[serde(rename = "Temperature")]
    pub temperature: String,
    #[serde(rename = "Distance")]
    pub distance: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Specification")]
    pub specification: Option<String>,
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

/// `Express/v2/PrintTradeDocument` 的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOnePrintTradeDocumentInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 物流交易編號清單(官方範例為陣列)
    #[serde(rename = "LogisticsID")]
    pub logistics_ids: Vec<String>,
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
}

/// `Express/v2/RedirectToLogisticsSelection`(物流選擇頁,消費者選擇門市/
/// 建立暫存物流訂單)的輸入。回應 Data 為導轉頁 HTML(`body` 欄位),
/// 需輸出給瀏覽器。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllInOneRedirectInput {
    /// 暫存物流交易編號,新訂單帶字串 "0"
    #[serde(rename = "TempLogisticsID")]
    pub temp_logistics_id: String,
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    #[serde(rename = "GoodsName")]
    pub goods_name: String,
    #[serde(rename = "SenderName")]
    pub sender_name: String,
    #[serde(rename = "SenderZipCode")]
    pub sender_zip_code: String,
    #[serde(rename = "SenderAddress")]
    pub sender_address: String,
    /// 溫層 0001/0002/0003(冷鏈子類別必填,如 RedirectWithUnimartFreeze 帶 0003)
    #[serde(skip_serializing_if = "Option::is_none", rename = "Temperature")]
    pub temperature: Option<String>,
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
    #[serde(rename = "ClientReplyURL")]
    pub client_reply_url: String,
}

impl Ecpay {
    /// 以暫存物流訂單建立正式訂單 (`Express/v2/CreateByTempTrade`)。
    pub async fn allinone_create_by_temp_trade(
        &self,
        input: &CreateByTempTradeInput,
    ) -> Result<Value> {
        self.post_logistics_aes("Express/v2/CreateByTempTrade", None, input)
            .await
    }

    /// 產生全方位物流 B2C 測試資料 (`Express/v2/CreateTestData`,僅測試環境)。
    pub async fn allinone_create_test_data(
        &self,
        input: &AllInOneCreateTestDataInput,
    ) -> Result<Value> {
        self.post_logistics_aes("Express/v2/CreateTestData", Some(&input.merchant_id), input)
            .await
    }

    /// 查詢物流訂單 (`Express/v2/QueryLogisticsTradeInfo`)。
    pub async fn allinone_query_logistics_trade_info(
        &self,
        input: &AllInOneQueryInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "Express/v2/QueryLogisticsTradeInfo",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// 更新暫存物流訂單 (`Express/v2/UpdateTempTrade`)。
    pub async fn allinone_update_temp_trade(&self, input: &UpdateTempTradeInput) -> Result<Value> {
        self.post_logistics_aes("Express/v2/UpdateTempTrade", None, input)
            .await
    }

    /// 更新出貨資訊 (`Express/v2/UpdateShipmentInfo`)。
    pub async fn allinone_update_shipment_info(
        &self,
        input: &AllInOneUpdateShipmentInfoInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "Express/v2/UpdateShipmentInfo",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// C2C 更新門市資訊 (`Express/v2/UpdateStoreInfo`)。
    pub async fn allinone_update_store_info(
        &self,
        input: &AllInOneUpdateStoreInfoInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "Express/v2/UpdateStoreInfo",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// C2C 取消物流訂單 (`Express/v2/CancelC2COrder`)。
    pub async fn allinone_cancel_c2c_order(&self, input: &AllInOneCancelC2cInput) -> Result<Value> {
        self.post_logistics_aes("Express/v2/CancelC2COrder", Some(&input.merchant_id), input)
            .await
    }

    /// 全家逆物流退貨 (`Express/v2/ReturnCVS`)。
    pub async fn allinone_return_cvs(&self, input: &AllInOneReturnCvsInput) -> Result<Value> {
        self.post_logistics_aes("Express/v2/ReturnCVS", Some(&input.merchant_id), input)
            .await
    }

    /// 萊爾富逆物流退貨 (`Express/v2/ReturnHilifeCVS`)。
    pub async fn allinone_return_hilife_cvs(
        &self,
        input: &AllInOneReturnCvsInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "Express/v2/ReturnHilifeCVS",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// 統一超商逆物流退貨 (`Express/v2/ReturnUniMartCVS`)。
    pub async fn allinone_return_unimart_cvs(
        &self,
        input: &AllInOneReturnCvsInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "Express/v2/ReturnUniMartCVS",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// 宅配逆物流退貨 (`Express/v2/ReturnHome`)。
    pub async fn allinone_return_home(&self, input: &AllInOneReturnHomeInput) -> Result<Value> {
        self.post_logistics_aes("Express/v2/ReturnHome", Some(&input.merchant_id), input)
            .await
    }

    /// 列印紙本出貨單 (`Express/v2/PrintTradeDocument`)。⚠ server 真相
    /// (stage 實測 2026-09):回應是 **text/html 的自動提交表單**,內含整筆
    /// 交易記錄(MD5 CheckMacValue)並自動 POST 到
    /// `Helper/PrintTradeDocument` 顯示列印頁 —— 不是 AES 信封。把回傳的
    /// HTML 原文輸出給瀏覽器即可(官方 PHP `echo $response['body']`)。
    pub async fn allinone_print_trade_document(
        &self,
        input: &AllInOnePrintTradeDocumentInput,
    ) -> Result<String> {
        self.post_logistics_aes_raw(
            "Express/v2/PrintTradeDocument",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// 物流選擇頁 (`Express/v2/RedirectToLogisticsSelection`)。⚠ server
    /// 真相(stage 實測 2026-09):回應是 **text/html 的自動提交表單**,
    /// 把整個 AES 選店請求包在隱藏欄位 `d` 內自動 POST 到
    /// `Express/v2/LogisticsSelection` —— 不是 AES 信封。把回傳的 HTML
    /// 原文輸出給瀏覽器;消費者選完門市後,結果以 `TempTradeEstablished`
    /// 形式 POST 到 `ClientReplyURL`(見
    /// [`Self::decrypt_temp_trade_established`])。
    pub async fn allinone_redirect_to_logistics_selection(
        &self,
        input: &AllInOneRedirectInput,
    ) -> Result<String> {
        self.post_logistics_aes_raw("Express/v2/RedirectToLogisticsSelection", None, input)
            .await
    }
}

// --- 跨境物流 CrossBorder (AES-JSON, CrossBorder/) ---

/// `CrossBorder/Create` 的輸入(兩個子類別共用:UNIMARTCBCVS 超商 /
/// UNIMARTCBHOME 宅配;宅配不需 receiver_store_id,超商必需)。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrossBorderCreateInput {
    /// 特店編號。官方 PHP 範例(`example/Logistics/CrossBorder/
    /// CreateUnimartCvsOrder.php`)把它放在 `Data` 的第一個欄位(信封也帶),
    /// 本結構照做。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 特店交易時間 yyyy/MM/dd HH:mm:ss (UTC+8)
    #[serde(rename = "MerchantTradeDate")]
    pub merchant_trade_date: String,
    /// 特店交易編號 maxlength 20
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    /// 物流類別,固定 "CB"
    #[serde(rename = "LogisticsType")]
    pub logistics_type: String,
    /// 物流子類別 UNIMARTCBCVS / UNIMARTCBHOME
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
    /// 商品金額
    #[serde(rename = "GoodsAmount")]
    pub goods_amount: i64,
    /// 商品重量(公斤,支援小數)
    #[serde(rename = "GoodsWeight", with = "crate::crypto::finite_f64")]
    pub goods_weight: f64,
    /// 商品英文名稱 maxlength 50
    #[serde(rename = "GoodsEnglishName")]
    pub goods_english_name: String,
    /// 收件人國別 ISO 3166-1 alpha-2(如 SG/HK/MO)
    #[serde(rename = "ReceiverCountry")]
    pub receiver_country: String,
    /// 收件人姓名(英文)maxlength 50
    #[serde(rename = "ReceiverName")]
    pub receiver_name: String,
    /// 收件人手機(含國碼)
    #[serde(rename = "ReceiverCellPhone")]
    pub receiver_cell_phone: String,
    /// 收件門市代號(UNIMARTCBCVS 必填,如 711_1)
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverStoreID")]
    pub receiver_store_id: Option<String>,
    /// 收件人郵遞區號
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverZipCode")]
    pub receiver_zip_code: Option<String>,
    /// 收件人地址(UNIMARTCBHOME 必填)
    #[serde(skip_serializing_if = "Option::is_none", rename = "ReceiverAddress")]
    pub receiver_address: Option<String>,
    /// 收件人電子郵件
    #[serde(rename = "ReceiverEmail")]
    pub receiver_email: String,
    /// 寄件人姓名
    #[serde(rename = "SenderName")]
    pub sender_name: String,
    /// 寄件人手機(含國碼)
    #[serde(rename = "SenderCellPhone")]
    pub sender_cell_phone: String,
    /// 寄件人地址
    #[serde(rename = "SenderAddress")]
    pub sender_address: String,
    /// 寄件人電子郵件
    #[serde(rename = "SenderEmail")]
    pub sender_email: String,
    /// 備註
    #[serde(skip_serializing_if = "Option::is_none", rename = "Remark")]
    pub remark: Option<String>,
    /// 物流狀態回報網址
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

/// `CrossBorder/CreateTestData`(僅測試環境)的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrossBorderCreateTestDataInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 測試目標國別(如 SG)
    #[serde(rename = "Country")]
    pub country: String,
    /// 固定 "CB"
    #[serde(rename = "LogisticsType")]
    pub logistics_type: String,
    /// UNIMARTCBCVS / UNIMARTCBHOME
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
}

/// `CrossBorder/QueryLogisticsTradeInfo` / `CrossBorder/Print` 的輸入。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrossBorderRefInput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    #[serde(rename = "LogisticsID")]
    pub logistics_id: String,
}

/// 跨境電子地圖(`CrossBorder/Map`)的輸入。⚠ 官方此表單**不帶
/// CheckMacValue**(AutoSubmitFormService 而非 WithCmv 版),為全服務唯一。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrossBorderMapInput {
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    /// 固定 "CB"
    #[serde(rename = "LogisticsType")]
    pub logistics_type: String,
    /// UNIMARTCBCVS
    #[serde(rename = "LogisticsSubType")]
    pub logistics_sub_type: String,
    /// 目標國別(如 SG)
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "ServerReplyURL")]
    pub server_reply_url: String,
}

impl Ecpay {
    /// 建立跨境物流訂單 (`CrossBorder/Create`)。
    pub async fn crossborder_create(&self, input: &CrossBorderCreateInput) -> Result<Value> {
        self.post_logistics_aes("CrossBorder/Create", Some(&input.merchant_id), input)
            .await
    }

    /// 產生跨境物流測試資料 (`CrossBorder/CreateTestData`,僅測試環境)。
    pub async fn crossborder_create_test_data(
        &self,
        input: &CrossBorderCreateTestDataInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "CrossBorder/CreateTestData",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// 查詢跨境物流訂單 (`CrossBorder/QueryLogisticsTradeInfo`)。
    pub async fn crossborder_query_logistics_trade_info(
        &self,
        input: &CrossBorderRefInput,
    ) -> Result<Value> {
        self.post_logistics_aes(
            "CrossBorder/QueryLogisticsTradeInfo",
            Some(&input.merchant_id),
            input,
        )
        .await
    }

    /// 列印跨境物流標籤 (`CrossBorder/Print`)。
    pub async fn crossborder_print(&self, input: &CrossBorderRefInput) -> Result<Value> {
        self.post_logistics_aes("CrossBorder/Print", Some(&input.merchant_id), input)
            .await
    }

    /// 跨境電子地圖選店表單(`CrossBorder/Map`,**不帶 CheckMacValue**)。
    pub fn crossborder_map_form(&self, input: &CrossBorderMapInput) -> Result<LogisticsForm> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert(
            "MerchantTradeNo".to_owned(),
            input.merchant_trade_no.clone(),
        );
        m.insert("LogisticsType".to_owned(), input.logistics_type.clone());
        m.insert(
            "LogisticsSubType".to_owned(),
            input.logistics_sub_type.clone(),
        );
        m.insert("Destination".to_owned(), input.destination.clone());
        m.insert("ServerReplyURL".to_owned(), input.server_reply_url.clone());
        Ok(LogisticsForm {
            action: format!("{}CrossBorder/Map", self.logistics_base_url()),
            pairs: m.into_iter().collect(),
        })
    }
}
