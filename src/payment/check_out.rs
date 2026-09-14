//! `CreateOrder.create_order` (產生 All-in-One 訂單) — the typed port.
//!
//! The official SDK takes a free-form dict, merges in the parameter groups
//! selected by `ChoosePayment`/invoice, validates, and signs. Here the groups
//! are typed [`Option`] fields: `None` is the "absent" that the SDK's filter
//! stage deletes, and required fields are non-`Option` `String`/`i64`/enum
//! values checked for emptiness/length at runtime (same messages as the
//! SDK).
//!
//! Two intentional deviations, both documented in the README: fields set for
//! a payment method they do not belong to are a validation error (the SDK
//! silently signs and sends them), and the invoice text fields are urlencoded
//! without lowercasing (the SDK's `.lower()` corrupts ASCII letter case in
//! customer data; ECPay url-decodes the value either way).

use crate::client::render_auto_submit_form;
use std::collections::{BTreeMap, HashMap};

use super::params::{
    insert_optional_int, insert_optional_int_seq, insert_optional_str, insert_optional_str_seq,
    optional_str, py_len, required_code, required_str,
};
use super::{CarruerType, ClearanceMark, Donation, InvType, PeriodType, PrintMark, TaxType};
use crate::crypto::query_escape;
use crate::error::{Error, Result};
use crate::payment::ChoosePayment;
use crate::Ecpay;

/// ECPay `MerchantTradeDate` 的日期時間格式（chrono 格式字串）：
/// `yyyy/MM/dd HH:mm:ss`。付款查詢回應的 `PaymentDate`/`TradeDate`
/// 也是同一樣式。⚠️ ECPay 要求 **UTC+8（台灣時間）** — 海外或 UTC 伺服器
/// 必須先轉換，超過允許時差的訂單會被拒絕。
///
/// 注意：這是「文件性」常數 — crate 本身不格式化日期
/// （`merchant_trade_date` 由呼叫端自備），提供它是為了讓 chrono 使用者
/// 不必重抄樣式。`time` crate 的使用者請自行對應
/// （`[year]/[month]/[day] [hour]:[minute]:[second]`）。
///
/// # Example
///
/// ```
/// use chrono::TimeZone;
///
/// let taipei = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
/// let dt = taipei.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
/// assert_eq!(
///     dt.format(ecpay::MERCHANT_TRADE_DATE_FORMAT).to_string(),
///     "2024/01/01 12:00:00",
/// );
/// ```
pub const MERCHANT_TRADE_DATE_FORMAT: &str = "%Y/%m/%d %H:%M:%S";

/// The All-in-One checkout parameters (`AioCheckOutParam`). Required fields
/// are non-`Option`; optional fields are `None`-absent and only sent when
/// set (strings non-empty, ints `>= 0`, exactly like the SDK's filter stage).
#[derive(Debug, Clone)]
pub struct AioCheckOutParams {
    // --- 訂單基本參數 (ORDER_REQUIRED_PARAMETERS) ---
    /// 特店交易編號。特店產生不重複的交易編號(最大 20 字元,不可與已成交訂單重複)。
    pub merchant_trade_no: String,
    /// 特店旗下店舖代號(最大 10 字元,英數大小寫混合)。
    pub store_id: Option<String>,
    /// 特店交易時間,格式為 yyyy/MM/dd HH:mm:ss(最大 20 字元)。
    pub merchant_trade_date: String,
    /// 交易金額,僅限新台幣(整數)。
    pub total_amount: i64,
    /// 交易描述(最大 200 字元)。
    pub trade_desc: String,
    /// 商品名稱,多筆以 `#` 分隔(最大 400 字元;超過會被截斷,易生亂碼導致
    /// 檢查碼錯誤、掉單 — 見官方「產生訂單」規格)。
    pub item_name: String,
    /// 付款結果通知 URL(最大 200 字元)。
    pub return_url: String,
    /// 付款方式。
    pub choose_payment: ChoosePayment,
    /// 用戶取消或付款失敗時要返回的 URL(最大 200 字元)。
    pub client_back_url: Option<String>,
    /// 商品銷售網址(最大 200 字元)。
    pub item_url: Option<String>,
    /// 備註(最大 100 字元)。平台特店合作模式時不可使用。
    pub remark: Option<String>,
    /// 付款方式子項目(見 [`crate::payment::choose_sub_payment`] 常數,最大 20 字元)。
    pub choose_sub_payment: Option<String>,
    /// 用戶於付款完成頁要返回的 URL(最大 200 字元)。
    pub order_result_url: Option<String>,
    /// 是否需要額外的付款資訊:`Y`/`N`(見 [`crate::payment::need_extra_paid_info`])。
    pub need_extra_paid_info: Option<String>,
    /// 裝置來源;請帶空值由系統自動判定(預設不送出)。
    pub device_source: Option<String>,
    /// 隱藏付款方式,如 `WebATM#ATM`(最大 100 字元)。
    pub ignore_payment: Option<String>,
    /// 平台特店合作專用(最大 10 字元)。
    pub platform_id: Option<String>,
    /// 自訂名稱欄位 1(最大 50 字元)。
    pub custom_field1: Option<String>,
    /// 自訂名稱欄位 2(最大 50 字元)。
    pub custom_field2: Option<String>,
    /// 自訂名稱欄位 3(最大 50 字元)。
    pub custom_field3: Option<String>,
    /// 自訂名稱欄位 4(最大 50 字元)。
    pub custom_field4: Option<String>,
    /// CheckMacValue 加密類別:1 = SHA-256(預設)、0 = MD5(ECPay 已淘汰)。
    pub encrypt_type: i64,
    /// 電子發票開立註記:`Y` 或 `N`(官方 sample 明確帶 `N`)。`None` 時不送出;
    /// [`Self::invoice`] 有值而此欄位為 `None` 時自動帶 `Y`。
    pub invoice_mark: Option<String>,

    // --- ATM 延伸參數 (ALL 或 ATM) ---
    /// ATM 付款有效繳費期限(天),最小 1 天、最大 60 天。
    pub expire_date: Option<i64>,
    /// ATM/CVS/BARCODE:付款人繳費資訊通知 URL(最大 200 字元)。
    pub payment_info_url: Option<String>,
    /// ATM/CVS/BARCODE:付款人於超商/ATM 付款完成後導回的 URL(最大 200 字元)。
    pub client_redirect_url: Option<String>,

    // --- CVS / BARCODE 延伸參數 (ALL 或 CVS 或 BARCODE) ---
    /// 超商繳費有效期限(分鐘或天數,依規格)。
    pub store_expire_date: Option<i64>,
    /// 超商繳費資訊顯示用欄位 1(最大 20 字元)。
    pub desc_1: Option<String>,
    /// 超商繳費資訊顯示用欄位 2(最大 20 字元)。
    pub desc_2: Option<String>,
    /// 超商繳費資訊顯示用欄位 3(最大 20 字元)。
    pub desc_3: Option<String>,
    /// 超商繳費資訊顯示用欄位 4(最大 20 字元)。
    pub desc_4: Option<String>,

    // --- 信用卡延伸參數 (ALL 或 Credit) ---
    /// 是否綁卡:1 = 綁卡。
    pub binding_card: Option<i64>,
    /// 特店會員編號(最大 30 字元),使用記憶卡號功能時必填。
    pub merchant_member_id: Option<String>,
    /// 語系設定 `CHT`(預設)/`ENG`/`KOR`/`JPN`/`CHI`(最大 3 字元;
    /// 現行規格為所有付款方式的共同選填參數)。
    pub language: Option<String>,
    /// 一次付清:紅利折抵 `Y`/`N`(最大 1 字元)。
    pub redeem: Option<String>,
    /// 銀聯卡交易選項(見 [`crate::payment::union_pay`])。
    pub union_pay: Option<i64>,
    /// 分期付款期數,如 `3,6,12`(最大 20 字元)。
    pub credit_installment: Option<String>,
    /// 定期定額:每次要付費的金額。
    pub period_amount: Option<i64>,
    /// 定期定額:週期種類(見 [`crate::payment::PeriodType`])。
    pub period_type: Option<PeriodType>,
    /// 定期定額:執行頻率,每幾個週期。
    pub frequency: Option<i64>,
    /// 定期定額:總執行次數。
    pub exec_times: Option<i64>,
    /// 定期定額:每次執行時的付款結果通知 URL(最大 200 字元)。
    pub period_return_url: Option<String>,

    // --- 電子發票延伸參數 (InvoiceMark = Y) ---
    /// 需要開立電子發票時填寫;設定後自動帶 `InvoiceMark=Y` 並套用發票欄位驗證。
    pub invoice: Option<InvoiceExtend>,

    /// Escape hatch for parameters this SDK version does not model yet
    /// (ECPay adds fields over time). These are signed and sent as-is; a key
    /// colliding with a modeled field is a validation error.
    pub extra: BTreeMap<String, String>,
}

impl Default for AioCheckOutParams {
    /// The official SDK's defaults: EncryptType=1 is always present
    /// (`create_default_dict` + schema defaults; PaymentType is likewise
    /// always `aio` but is no longer a field — it is fixed on the wire);
    /// everything else starts absent.
    fn default() -> Self {
        Self {
            merchant_trade_no: Default::default(),
            store_id: Default::default(),
            merchant_trade_date: Default::default(),
            total_amount: Default::default(),
            trade_desc: Default::default(),
            item_name: Default::default(),
            return_url: Default::default(),
            choose_payment: Default::default(),
            client_back_url: Default::default(),
            item_url: Default::default(),
            remark: Default::default(),
            choose_sub_payment: Default::default(),
            order_result_url: Default::default(),
            need_extra_paid_info: Default::default(),
            device_source: Default::default(),
            ignore_payment: Default::default(),
            platform_id: Default::default(),
            custom_field1: Default::default(),
            custom_field2: Default::default(),
            custom_field3: Default::default(),
            custom_field4: Default::default(),
            encrypt_type: 1,
            invoice_mark: Default::default(),
            expire_date: Default::default(),
            payment_info_url: Default::default(),
            client_redirect_url: Default::default(),
            store_expire_date: Default::default(),
            desc_1: Default::default(),
            desc_2: Default::default(),
            desc_3: Default::default(),
            desc_4: Default::default(),
            binding_card: Default::default(),
            merchant_member_id: Default::default(),
            language: Default::default(),
            redeem: Default::default(),
            union_pay: Default::default(),
            credit_installment: Default::default(),
            period_amount: Default::default(),
            period_type: Default::default(),
            frequency: Default::default(),
            exec_times: Default::default(),
            period_return_url: Default::default(),
            invoice: Default::default(),
            extra: Default::default(),
        }
    }
}

/// 電子發票延伸參數 (`INVOICE_EXTEND_PARAMETERS`)。欄位規則與官方 SDK 的
/// create_order 驗證一致(統一編號、列印/捐贈互斥、載具限制、Email/手機
/// 至少一個)。
#[derive(Debug, Clone, Default)]
pub struct InvoiceExtend {
    /// 特店自訂編號,該筆交易的發票唯一識別(必填,最大 30 字元)。
    pub relate_number: String,
    /// 客戶編號(最大 20 字元)。
    pub customer_id: Option<String>,
    /// 統一編號(固定 8 碼數字;有值時 Print=1、Donation=0、不得填載具)。
    pub customer_identifier: Option<String>,
    /// 客戶名稱(最大 30 字元;Print=1 或有統一編號時必填)。
    pub customer_name: Option<String>,
    /// 客戶地址(最大 200 字元;Print=1 時必填)。
    pub customer_addr: Option<String>,
    /// 客戶手機號碼(最大 20 字元;與 Email 至少一個)。
    pub customer_phone: Option<String>,
    /// 客戶電子信箱(最大 200 字元;與手機號碼至少一個)。
    pub customer_email: Option<String>,
    /// 通關方式(TaxType 為零稅率時必填,見 [`crate::payment::ClearanceMark`])。
    pub clearance_mark: Option<ClearanceMark>,
    /// 課稅類別(必填,見 [`crate::payment::TaxType`])。
    pub tax_type: TaxType,
    /// 載具類別(見 [`crate::payment::CarruerType`];`None`=無載具)。
    pub carruer_type: Option<CarruerType>,
    /// 載具編號(最大 64 字元;CarruerType 為 2/3 時必填)。
    pub carruer_num: Option<String>,
    /// 捐贈註記(必填,見 [`crate::payment::Donation`])。
    pub donation: Donation,
    /// 捐贈碼(3~7 碼;Donation=1 時必填)。
    pub love_code: Option<String>,
    /// 列印註記(必填,見 [`crate::payment::PrintMark`])。
    pub print: PrintMark,
    /// 商品名稱,多筆以 `#` 分隔(必填,最大 100 字元)。
    pub invoice_item_name: String,
    /// 商品數量,多筆以 `#` 分隔(必填)。
    pub invoice_item_count: String,
    /// 商品單位,多筆以 `#` 分隔(必填)。
    pub invoice_item_word: String,
    /// 商品單價,多筆以 `#` 分隔(必填)。
    pub invoice_item_price: String,
    /// 商品課稅別,多筆以 `#` 分隔(TaxType=9 時必填)。
    pub invoice_item_tax_type: Option<String>,
    /// 發票備註。
    pub invoice_remark: Option<String>,
    /// 延遲天數,0 為立即開立(必填;若延遲,最長依法規限制)。
    pub delay_day: i64,
    /// 字軌類別(必填,見 [`crate::payment::InvType`])。
    pub inv_type: InvType,
}

/// The signed All-in-One checkout payload `aio_check_out` returns: the
/// final parameters (sorted by key, `CheckMacValue` included, ready to POST)
/// plus helpers to render them.
#[derive(Debug, Clone)]
pub struct AioCheckOut {
    params: Vec<(String, String)>,
    action: String,
}

impl AioCheckOut {
    /// The final POST parameters, sorted by key, `CheckMacValue` included.
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// The signed `CheckMacValue`.
    pub fn check_mac_value(&self) -> &str {
        &self
            .params
            .iter()
            .find(|(k, _)| k == "CheckMacValue")
            .expect("aio_check_out always appends CheckMacValue")
            .1
    }

    /// The checkout endpoint the form posts to (follows the client's
    /// `payment_api_url`, production by default).
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Port of `ExtendFunction.gen_html_post_form`: an auto-submitting HTML
    /// form that sends the browser to ECPay's payment page. Attribute values
    /// are HTML-escaped (the official SDK does not, which breaks on `"` and
    /// is an injection vector).
    pub fn html_form(&self) -> String {
        render_auto_submit_form(self.action(), &self.params)
    }

    /// Consume into the raw key/value pairs.
    pub fn into_pairs(self) -> Vec<(String, String)> {
        self.params
    }
}

impl Ecpay {
    /// `CreateOrder.create_order`: validate `params`, fill the client's
    /// MerchantID and the defaults (PaymentType=aio, EncryptType=1,
    /// InvoiceMark=Y when an invoice is present), sign with CheckMacValue,
    /// and return the ready-to-POST payload. No network is performed — the
    /// caller renders [`AioCheckOut::html_form`] and the user's browser does
    /// the POST.
    pub fn aio_check_out(&self, p: &AioCheckOutParams) -> Result<AioCheckOut> {
        // --- 訂單基本參數 ---
        required_str("MerchantTradeNo", &p.merchant_trade_no, 20)?;
        required_str("MerchantTradeDate", &p.merchant_trade_date, 20)?;
        required_str("TradeDesc", &p.trade_desc, 200)?;
        required_str("ItemName", &p.item_name, 400)?;
        required_str("ReturnURL", &p.return_url, 200)?;
        optional_str("StoreID", &p.store_id, 10)?;
        optional_str("ClientBackURL", &p.client_back_url, 200)?;
        optional_str("ItemURL", &p.item_url, 200)?;
        optional_str("Remark", &p.remark, 100)?;
        optional_str("ChooseSubPayment", &p.choose_sub_payment, 20)?;
        optional_str("OrderResultURL", &p.order_result_url, 200)?;
        optional_str("NeedExtraPaidInfo", &p.need_extra_paid_info, 1)?;
        optional_str("DeviceSource", &p.device_source, 10)?;
        optional_str("IgnorePayment", &p.ignore_payment, 100)?;
        optional_str("PlatformID", &p.platform_id, 10)?;
        optional_str("CustomField1", &p.custom_field1, 50)?;
        optional_str("CustomField2", &p.custom_field2, 50)?;
        optional_str("CustomField3", &p.custom_field3, 50)?;
        optional_str("CustomField4", &p.custom_field4, 50)?;

        // 付款子方式 WebATM 大眾銀行跟永豐銀行已經無法使用
        if let Some(sub) = &p.choose_sub_payment {
            if sub == crate::payment::choose_sub_payment::web_atm::TACHONG
                || sub == crate::payment::choose_sub_payment::web_atm::SINOPAC
            {
                return Err(Error::Validation(
                    "ChooseSubPayment is not supported with TACHONG or SINOPAC.".into(),
                ));
            }
        }

        // --- 付款方式延伸參數:組別歸屬檢查 ---
        validate_groups(p)?;

        // --- 電子發票延伸參數 ---
        // InvoiceMark: `Y` 開立發票 / `N` 不開立 (official samples send `N`
        // explicitly); an invoice struct with no mark auto-fills `Y`.
        let mark = p.invoice_mark.as_deref().unwrap_or("");
        optional_str("InvoiceMark", &p.invoice_mark, 1)?;
        match (&p.invoice, mark) {
            (Some(_), "N") => {
                return Err(Error::Validation(
                    "InvoiceMark=N conflicts with the invoice fields; drop one of them.".into(),
                ))
            }
            (None, "Y") => {
                return Err(Error::Validation(
                    "InvoiceMark=Y requires the invoice fields (InvoiceExtend).".into(),
                ))
            }
            _ => {}
        }

        let mut m = build_base_map(p, &self.merchant_id);
        add_group_fields(&mut m, p);
        add_invoice_fields(&mut m, p, mark)?;
        merge_extras(&mut m, &p.extra)?;

        let mac = self.generate_check_value(&m)?;
        m.insert("CheckMacValue".to_owned(), mac);

        let mut pairs: Vec<(String, String)> = m.into_iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let action = format!("{}AioCheckOut/V5", self.payment_base_url());
        Ok(AioCheckOut {
            params: pairs,
            action,
        })
    }
}

/// Which parameter groups the chosen `ChoosePayment` activates (`All`
/// activates every group). `validate_groups` and `add_group_fields` must
/// agree on this — one shared predicate, not two copies.
fn groups(p: &AioCheckOutParams) -> (bool, bool, bool) {
    let is_all_or =
        |a: ChoosePayment| p.choose_payment == ChoosePayment::All || p.choose_payment == a;
    (
        is_all_or(ChoosePayment::Atm),
        is_all_or(ChoosePayment::Cvs) || is_all_or(ChoosePayment::Barcode),
        is_all_or(ChoosePayment::Credit),
    )
}

/// 組別歸屬檢查:the official SDK merges exactly one group set per
/// ChoosePayment; a field set for an inactive group would be silently signed
/// and sent, so the typed API rejects it loudly instead.
fn validate_groups(p: &AioCheckOutParams) -> Result<()> {
    let (atm_group, cvs_barcode_group, credit_group) = groups(p);

    let group = |name: &str| -> Error {
        Error::Validation(format!(
            "{name} is only valid with its ChoosePayment group (the official SDK would not send it)."
        ))
    };
    if p.expire_date.is_some() && !atm_group {
        return Err(group("ExpireDate"));
    }
    let cvs_fields_set = p.store_expire_date.is_some()
        || p.desc_1.is_some()
        || p.desc_2.is_some()
        || p.desc_3.is_some()
        || p.desc_4.is_some();
    if cvs_fields_set && !cvs_barcode_group {
        return Err(group(
            "a CVS/BARCODE extend field (StoreExpireDate/Desc_1..4)",
        ));
    }
    if (p.payment_info_url.is_some() || p.client_redirect_url.is_some())
        && !atm_group
        && !cvs_barcode_group
    {
        return Err(group(
            "PaymentInfoURL/ClientRedirectURL (ATM/CVS/BARCODE groups)",
        ));
    }

    // --- 信用卡延伸參數 (三擇一) ---
    let one_off = p.redeem.is_some() || p.union_pay.is_some(); // 一次付清
    let installment = p.credit_installment.is_some(); // 分期付款
    let periodic = p.period_amount.is_some()
        || p.period_type.is_some()
        || p.frequency.is_some()
        || p.exec_times.is_some()
        || p.period_return_url.is_some(); // 定期定額
    if (p.binding_card.is_some() || p.merchant_member_id.is_some()) && !credit_group {
        return Err(group(
            "a Credit bind-card field (BindingCard/MerchantMemberID)",
        ));
    }
    if (one_off || installment || periodic) && !credit_group {
        return Err(group(
            "a Credit payment-plan field (Redeem/UnionPay/CreditInstallment/Period*)",
        ));
    }
    // The official SDK picks one plan group via an if/elif chain; setting
    // more than one silently signs the mixture. Reject it instead.
    if [one_off, installment, periodic]
        .iter()
        .filter(|b| **b)
        .count()
        > 1
    {
        return Err(Error::Validation(
            "choose only one of Redeem/UnionPay (一次付清), CreditInstallment (分期付款), or the Period* group (定期定額).".into(),
        ));
    }
    Ok(())
}

/// The base (payment-method-independent) request fields.
fn build_base_map(p: &AioCheckOutParams, merchant_id: &str) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::new();
    m.insert("MerchantID".to_owned(), merchant_id.to_owned());
    m.insert("MerchantTradeNo".to_owned(), p.merchant_trade_no.clone());
    insert_optional_str(&mut m, "StoreID", &p.store_id);
    m.insert(
        "MerchantTradeDate".to_owned(),
        p.merchant_trade_date.clone(),
    );
    // The AIO cashier only ever accepts PaymentType=aio; fixed, not a field.
    m.insert("PaymentType".to_owned(), "aio".to_owned());
    m.insert("TotalAmount".to_owned(), p.total_amount.to_string());
    m.insert("TradeDesc".to_owned(), p.trade_desc.clone());
    m.insert("ItemName".to_owned(), p.item_name.clone());
    m.insert("ReturnURL".to_owned(), p.return_url.clone());
    m.insert(
        "ChoosePayment".to_owned(),
        p.choose_payment.as_str().to_owned(),
    );
    insert_optional_str(&mut m, "ClientBackURL", &p.client_back_url);
    insert_optional_str(&mut m, "ItemURL", &p.item_url);
    insert_optional_str(&mut m, "Remark", &p.remark);
    insert_optional_str(&mut m, "ChooseSubPayment", &p.choose_sub_payment);
    insert_optional_str(&mut m, "OrderResultURL", &p.order_result_url);
    insert_optional_str(&mut m, "NeedExtraPaidInfo", &p.need_extra_paid_info);
    insert_optional_str(&mut m, "DeviceSource", &p.device_source);
    insert_optional_str(&mut m, "IgnorePayment", &p.ignore_payment);
    insert_optional_str(&mut m, "PlatformID", &p.platform_id);
    insert_optional_str(&mut m, "CustomField1", &p.custom_field1);
    insert_optional_str(&mut m, "CustomField2", &p.custom_field2);
    insert_optional_str(&mut m, "CustomField3", &p.custom_field3);
    insert_optional_str(&mut m, "CustomField4", &p.custom_field4);
    m.insert("EncryptType".to_owned(), p.encrypt_type.to_string());
    m
}

/// The active payment-method group's extend fields, plus the common
/// `Language` param (CHT/ENG/KOR/JPN/CHI, valid for every payment method).
fn add_group_fields(m: &mut HashMap<String, String>, p: &AioCheckOutParams) {
    let (atm_group, cvs_barcode_group, credit_group) = groups(p);

    if atm_group {
        insert_optional_int(m, "ExpireDate", &p.expire_date);
    }
    if cvs_barcode_group {
        insert_optional_int(m, "StoreExpireDate", &p.store_expire_date);
        insert_optional_str(m, "Desc_1", &p.desc_1);
        insert_optional_str(m, "Desc_2", &p.desc_2);
        insert_optional_str(m, "Desc_3", &p.desc_3);
        insert_optional_str(m, "Desc_4", &p.desc_4);
    }
    // PaymentInfoURL/ClientRedirectURL are shared by the ATM and the
    // CVS/BARCODE groups.
    if atm_group || cvs_barcode_group {
        insert_optional_str(m, "PaymentInfoURL", &p.payment_info_url);
        insert_optional_str(m, "ClientRedirectURL", &p.client_redirect_url);
    }
    if credit_group {
        insert_optional_int(m, "BindingCard", &p.binding_card);
        insert_optional_str(m, "MerchantMemberID", &p.merchant_member_id);
        if let Some(plan) = credit_plan_pairs(p) {
            for (k, v) in plan {
                m.insert(k, v);
            }
        }
    }
    insert_optional_str(m, "Language", &p.language);
}

/// `InvoiceMark` (when set explicitly) plus the invoice block: validate, then
/// build the invoice fields. The six free-text invoice fields are urlencoded
/// before signing (the official SDK does too), but NOT lowercased — see
/// README.
fn add_invoice_fields(
    m: &mut HashMap<String, String>,
    p: &AioCheckOutParams,
    mark: &str,
) -> Result<()> {
    if p.invoice_mark.is_some() && !mark.is_empty() {
        m.insert("InvoiceMark".to_owned(), mark.to_owned());
    }
    if let Some(inv) = &p.invoice {
        validate_invoice(inv)?;
        if mark != "Y" {
            // invoice present with no explicit mark: auto-fill Y.
            m.insert(
                "InvoiceMark".to_owned(),
                crate::payment::INVOICE_MARK.to_owned(),
            );
        }
        m.insert("RelateNumber".to_owned(), inv.relate_number.clone());
        insert_optional_str(m, "CustomerID", &inv.customer_id);
        insert_optional_str(m, "CustomerIdentifier", &inv.customer_identifier);
        insert_escaped(m, "CustomerName", &inv.customer_name);
        insert_escaped(m, "CustomerAddr", &inv.customer_addr);
        insert_optional_str(m, "CustomerPhone", &inv.customer_phone);
        insert_escaped(m, "CustomerEmail", &inv.customer_email);
        insert_optional_str(m, "ClearanceMark", &inv.clearance_mark);
        m.insert("TaxType".to_owned(), inv.tax_type.as_str().to_owned());
        insert_optional_str(m, "CarruerType", &inv.carruer_type);
        insert_optional_str(m, "CarruerNum", &inv.carruer_num);
        m.insert("Donation".to_owned(), inv.donation.as_str().to_owned());
        insert_optional_str(m, "LoveCode", &inv.love_code);
        m.insert("Print".to_owned(), inv.print.as_str().to_owned());
        m.insert(
            "InvoiceItemName".to_owned(),
            query_escape(&inv.invoice_item_name),
        );
        m.insert(
            "InvoiceItemCount".to_owned(),
            inv.invoice_item_count.clone(),
        );
        m.insert(
            "InvoiceItemWord".to_owned(),
            query_escape(&inv.invoice_item_word),
        );
        m.insert(
            "InvoiceItemPrice".to_owned(),
            inv.invoice_item_price.clone(),
        );
        insert_optional_str(m, "InvoiceItemTaxType", &inv.invoice_item_tax_type);
        insert_escaped(m, "InvoiceRemark", &inv.invoice_remark);
        m.insert("DelayDay".to_owned(), inv.delay_day.to_string());
        m.insert("InvType".to_owned(), inv.inv_type.as_str().to_owned());
    }
    Ok(())
}

/// Reject `extra` parameters that collide with a modeled field or would
/// forge a signature.
fn merge_extras(m: &mut HashMap<String, String>, extra: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in extra {
        if m.contains_key(k) || k == "CheckMacValue" {
            return Err(Error::Validation(format!(
                "extra parameter {k:?} collides with a modeled field"
            )));
        }
        m.insert(k.clone(), v.clone());
    }
    Ok(())
}

/// The active Credit plan group's wire pairs (Python's if/elif chain over
/// `__CREDIT_EXTEND_PARAMETERS_3/4/5`).
fn credit_plan_pairs(p: &AioCheckOutParams) -> Option<Vec<(String, String)>> {
    if p.redeem.is_some() || p.union_pay.is_some() {
        let mut v = Vec::new();
        insert_optional_str_seq(&mut v, "Redeem", &p.redeem);
        insert_optional_int_seq(&mut v, "UnionPay", &p.union_pay);
        return Some(v);
    }
    if let Some(installment) = &p.credit_installment {
        return Some(vec![("CreditInstallment".to_owned(), installment.clone())]);
    }
    if p.period_amount.is_some()
        || p.period_type.is_some()
        || p.frequency.is_some()
        || p.exec_times.is_some()
        || p.period_return_url.is_some()
    {
        let mut v = Vec::new();
        insert_optional_int_seq(&mut v, "PeriodAmount", &p.period_amount);
        insert_optional_str_seq(&mut v, "PeriodType", &p.period_type);
        insert_optional_int_seq(&mut v, "Frequency", &p.frequency);
        insert_optional_int_seq(&mut v, "ExecTimes", &p.exec_times);
        insert_optional_str_seq(&mut v, "PeriodReturnURL", &p.period_return_url);
        return Some(v);
    }
    None
}

/// Free-text invoice fields: urlencoded (Python `quote_plus` semantics via
/// [`query_escape`]) but NOT lowercased — the official SDK's `.lower()`
/// corrupts ASCII letter case in customer data, and ECPay url-decodes the
/// value either way.
fn insert_escaped(m: &mut HashMap<String, String>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        if !v.is_empty() {
            m.insert(key.to_owned(), query_escape(v));
        }
    }
}

fn validate_invoice(inv: &InvoiceExtend) -> Result<()> {
    required_str("RelateNumber", &inv.relate_number, 30)?;
    optional_str("CustomerID", &inv.customer_id, 20)?;
    optional_str("CustomerIdentifier", &inv.customer_identifier, 8)?;
    optional_str("CustomerName", &inv.customer_name, 30)?;
    optional_str("CustomerAddr", &inv.customer_addr, 200)?;
    optional_str("CustomerPhone", &inv.customer_phone, 20)?;
    optional_str("CustomerEmail", &inv.customer_email, 200)?;
    optional_str("CarruerNum", &inv.carruer_num, 64)?;
    optional_str("LoveCode", &inv.love_code, 7)?;
    // enum 欄位:只檢查「有填」,值本身(含 Other 穿隧的新代碼)由綠界裁定
    required_code("TaxType", &inv.tax_type)?;
    required_code("Donation", &inv.donation)?;
    required_code("Print", &inv.print)?;
    required_str("InvoiceItemName", &inv.invoice_item_name, 100)?;
    required_str("InvoiceItemCount", &inv.invoice_item_count, usize::MAX)?;
    required_str("InvoiceItemWord", &inv.invoice_item_word, usize::MAX)?;
    required_str("InvoiceItemPrice", &inv.invoice_item_price, usize::MAX)?;
    optional_str("InvoiceItemTaxType", &inv.invoice_item_tax_type, usize::MAX)?;
    optional_str("InvoiceRemark", &inv.invoice_remark, usize::MAX)?;
    required_code("InvType", &inv.inv_type)?;

    // 該參數有值時，請帶固定長度為數字 8 碼
    let customer_identifier = inv.customer_identifier.as_deref().unwrap_or("");
    if !customer_identifier.is_empty() && py_len(customer_identifier) != 8 {
        return Err(Error::Validation(
            "CustomerIdentifier have to fill fixed length of 8 digits.".into(),
        ));
    }
    // 若統一編號 CustomerIdentifier 有值時，不可以有載具
    let has_carruer = inv.carruer_type.as_ref().is_some_and(|c| !c.is_unset());
    if !customer_identifier.is_empty() && has_carruer {
        return Err(Error::Validation(
            "CarruerType do not fill any value, when CustomerIdentifier have value.".into(),
        ));
    }
    // 統一編號 CustomerIdentifier 有值時，一定要列印
    if !customer_identifier.is_empty() && inv.print == PrintMark::No {
        return Err(Error::Validation(
            "Print have to fill \"1\", when CustomerIdentifier have value.".into(),
        ));
    }
    // 統一編號 CustomerIdentifier 有值時，Donation 要為不捐贈(SDK 訊息寫 "0"，
    // 判斷為 AIO 語彙的不可捐贈 '1')
    if !customer_identifier.is_empty() && inv.donation == Donation::Yes {
        return Err(Error::Validation(
            "Donation have to fill \"0\", when CustomerIdentifier have value.".into(),
        ));
    }

    // 當列印註記 Print 為 1 (列印)時，CustomerName 與 CustomerAddr 必須有值
    if inv.print == PrintMark::Yes {
        if inv.customer_name.as_deref().unwrap_or("").is_empty() {
            return Err(Error::Validation("CustomerName have to fill value.".into()));
        }
        if inv.customer_addr.as_deref().unwrap_or("").is_empty() {
            return Err(Error::Validation("CustomerAddr have to fill value.".into()));
        }
        if has_carruer {
            return Err(Error::Validation(
                "CarruerType do not fill any value, when Print is \"1\".".into(),
            ));
        }
    }

    // 當客戶電子信箱為空字串時，CustomerPhone 必須有值；反之亦然
    // (the official SDK has two redundant checks that net to this rule)
    if inv.customer_email.as_deref().unwrap_or("").is_empty()
        && inv.customer_phone.as_deref().unwrap_or("").is_empty()
    {
        return Err(Error::Validation(
            "CustomerPhone have to fill value.".into(),
        ));
    }

    // 當 Donation 為捐贈時，Print 要為不列印，且 LoveCode 須有值
    if inv.donation == Donation::Yes {
        if inv.print == PrintMark::Yes {
            return Err(Error::Validation(
                "Print have to fill \"0\", when Donation is \"1\".".into(),
            ));
        }
        if inv.love_code.as_deref().unwrap_or("").is_empty() {
            return Err(Error::Validation(
                "LoveCode have to fill value, when Donation is \"1\".".into(),
            ));
        }
    }
    if let Some(love_code) = &inv.love_code {
        let len = py_len(love_code);
        if !(3..=7).contains(&len) {
            return Err(Error::Validation(
                "LoveCode have to fill fixed length of 3~7 digits.".into(),
            ));
        }
    }
    Ok(())
}
