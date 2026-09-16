//! The official payment SDK's surface: the wire constants (付款方式、課稅類別
//! …), the All-in-One checkout builder ([`aio_check_out`]), the seven
//! server-side APIs the official Python SDK exposes (order_search,
//! credit_do_action, …), plus [`Ecpay::query_payment_info`] — not in the
//! Python SDK, ported from `ECPay/SDK_PHP`'s `QueryPaymentInfo.php` example.
//!
//! [`aio_check_out`]: crate::Ecpay::aio_check_out

pub mod check_out;
mod params;

pub use check_out::{AioCheckOut, AioCheckOutParams, InvoiceExtend, MERCHANT_TRADE_DATE_FORMAT};

use std::collections::{BTreeMap, HashMap};

use crate::client::parse_qsl;
use crate::error::{Error, Result};
use crate::wire::wire_enum;
use crate::Ecpay;
use params::{insert_optional_str, optional_str, required_code, required_str};

/// 付款方式 (`ChoosePayment`)。`as_str()` 為送給 ECPay 的 wire 值。
///
/// 與其他代碼欄位(`TaxType`、`CarruerType` 等,由 `wire_enum!` 生成、
/// 以 `Other` 穿隧未知值)不同,這是封閉 enum:它決定 `aio_check_out`
/// 啟用哪組延伸參數(SDK 內部邏輯分支),未建模的付款方式無法正確組參。
/// `#[non_exhaustive]`:本 crate 日後可能新增變體。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ChoosePayment {
    /// 信用卡及 GooglePay
    Credit,
    /// GooglePay (若為PC版時不支援)
    GooglePay,
    /// 網路 ATM (若為手機版時不支援)
    WebATM,
    /// 自動櫃員機
    Atm,
    /// 超商代碼
    Cvs,
    /// 超商條碼 (若為手機版時不支援)
    Barcode,
    /// ApplePay (僅支援Safari瀏覽器)
    ApplePay,
    /// BNPL無卡分期(裕富/中租)
    Bnpl,
    /// 數位支付(街口支付/一卡通)
    DigitalPayment,
    /// 歐付寶TWQR行動支付
    Twqr,
    /// 微信支付
    WeiXin,
    /// 不指定付款方式，由綠界顯示付款方式選擇頁面。
    #[default]
    All,
}

impl ChoosePayment {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChoosePayment::Credit => "Credit",
            ChoosePayment::GooglePay => "GooglePay",
            ChoosePayment::WebATM => "WebATM",
            ChoosePayment::Atm => "ATM",
            ChoosePayment::Cvs => "CVS",
            ChoosePayment::Barcode => "BARCODE",
            ChoosePayment::ApplePay => "ApplePay",
            ChoosePayment::Bnpl => "BNPL",
            ChoosePayment::DigitalPayment => "DigitalPayment",
            ChoosePayment::Twqr => "TWQR",
            ChoosePayment::WeiXin => "WeiXin",
            ChoosePayment::All => "ALL",
        }
    }
}

/// 付款方式子項目 (`ChooseSubPayment`)。wire 值為各常數字串本身;
/// WebATM 的大眾(TACHONG)與永豐(SINOPAC)已停用,`aio_check_out` 會拒絕。
pub mod choose_sub_payment {
    /// 網路 ATM 銀行代碼
    pub mod web_atm {
        pub const TAISHIN: &str = "TAISHIN"; // 台新銀行
        pub const ESUN: &str = "ESUN"; // 玉山銀行
        pub const BOT: &str = "BOT"; // 台灣銀行
        pub const FUBON: &str = "FUBON"; // 台北富邦
        pub const CHINATRUST: &str = "CHINATRUST"; // 中國信託
        pub const FIRST: &str = "FIRST"; // 第一銀行
        pub const CATHAY: &str = "CATHAY"; // 國泰世華
        pub const MEGA: &str = "MEGA"; // 兆豐銀行
        pub const LAND: &str = "LAND"; // 土地銀行
        pub const TACHONG: &str = "TACHONG"; // 大眾銀行(已停用)
        pub const SINOPAC: &str = "SINOPAC"; // 永豐銀行(已停用)
    }
    /// ATM 銀行代碼
    pub mod atm {
        pub const TAISHIN: &str = "TAISHIN"; // 台新銀行
        pub const ESUN: &str = "ESUN"; // 玉山銀行
        pub const BOT: &str = "BOT"; // 台灣銀行
        pub const FUBON: &str = "FUBON"; // 台北富邦
        pub const CHINATRUST: &str = "CHINATRUST"; // 中國信託
        pub const FIRST: &str = "FIRST"; // 第一銀行
        pub const LAND: &str = "LAND"; // 土地銀行
        pub const CATHAY: &str = "CATHAY"; // 國泰世華銀行
        pub const TACHONG: &str = "TACHONG"; // 大眾銀行(已停用)
    }
    /// 超商代碼
    pub mod cvs {
        pub const CVS: &str = "CVS"; // 超商代碼繳款
        pub const OK: &str = "OK"; // OK 超商代碼繳款
        pub const FAMILY: &str = "FAMILY"; // 全家超商代碼繳款
        pub const HILIFE: &str = "HILIFE"; // 萊爾富超商代碼繳款
        pub const IBON: &str = "IBON"; // 7-11 ibon 代碼繳款
    }
    /// BNPL 無卡分期
    pub mod bnpl {
        pub const URICH: &str = "URICH"; // 裕富數位無卡分期
        pub const ZINGALA: &str = "ZINGALA"; // 中租銀角零卡
    }
    /// 數位支付
    pub mod digital_payment {
        pub const JKOPAY: &str = "Jkopay"; // 街口支付
        pub const IPASS: &str = "iPASS"; // 一卡通電子支付 iPASS MONEY (即將支援)
    }
    /// 超商條碼繳款
    pub const BARCODE: &str = "BARCODE";
    /// 信用卡 (MasterCard/JCB/VISA)
    pub const CREDIT: &str = "Credit";
    /// GooglePay
    pub const GOOGLE_PAY: &str = "GooglePay";
    /// ApplePay(子項目為空字串)
    pub const APPLE_PAY: &str = "";
    /// 歐付寶TWQR行動支付(子項目為空字串)
    pub const TWQR: &str = "";
    /// 微信支付(子項目為空字串)
    pub const WEI_XIN: &str = "";
}

/// 額外付款資訊 (`NeedExtraPaidInfo`)
pub mod need_extra_paid_info {
    pub const YES: &str = "Y"; // 需要額外付款資訊
    pub const NO: &str = "N"; // 不需要額外付款資訊
}

/// 裝置來源:請帶空值，由系統自動判定。
pub const DEVICE_SOURCE: &str = "";

wire_enum! {
    /// 信用卡關帳/退刷/取消/放棄 (`Action`,C/R/E/N)。
    CreditAction {
        /// 關帳 (C)
        Close => "C",
        /// 退刷 (R)
        Refund => "R",
        /// 取消 (E)
        Cancel => "E",
        /// 放棄 (N)
        Abandon => "N",
    }
}

wire_enum! {
    /// 定期定額的週期種類 (`PeriodType`,Y/M/D)。
    PeriodType {
        /// 以年為週期 (Y)
        Year => "Y",
        /// 以月為週期 (M)
        Month => "M",
        /// 以天為週期 (D)
        Day => "D",
    }
}

/// 電子發票開立註記 (`InvoiceMark`):需要開立電子發票
pub const INVOICE_MARK: &str = "Y";

wire_enum! {
    /// AIO 付款附帶發票的載具類別 (`CarruerType`,1/2/3)。「無載具」不設此欄位
    /// (`None`)——wire 上本來就是省略,而非送空字串。
    CarruerType {
        /// 特店載具 (1)
        Member => "1",
        /// 買受人自然人憑證 (2)
        Citizen => "2",
        /// 買受人手機條碼 (3)
        Cellphone => "3",
    }
}

wire_enum! {
    /// AIO 訂單附帶發票的捐贈註記 (`Donation`) — **AIO 舊版語彙:`'1'` 捐贈/
    /// `'2'` 不捐贈**,與 B2C 電子發票 API 的 [`crate::invoice::Donation`]
    /// (`'0'`/`'1'`)語意相反,型別刻意分開 so 兩套無法互抄。
    Donation {
        /// 捐贈 (1;需要 LoveCode)
        Yes => "1",
        /// 不捐贈 (2;統一編號有值時亦為不捐贈)
        No => "2",
    }
}

wire_enum! {
    /// AIO 訂單附帶發票的列印註記 (`Print`,0/1)。
    PrintMark {
        /// 不列印 (0;捐贈註記為捐贈時亦不列印)
        No => "0",
        /// 列印 (1;統一編號有值時必為列印)
        Yes => "1",
    }
}

wire_enum! {
    /// AIO 訂單附帶發票的通關方式 (`ClearanceMark`,TaxType 為零稅率時必填)。
    /// ⚠ 官方文件間存在歧義:AIO 世代文件(官方 Python SDK)記 `'1'`=經海關出口、
    /// `'2'`=非經海關出口;現行 B2C 發票指南記法相反。上線前請以你的應用場景
    /// 向綠界確認;此 enum 依 AIO/Python SDK 語彙命名。
    ClearanceMark {
        /// 經海關出口 (1;AIO 世代文件語彙——B2C 發票指南相反,見型別文件)
        ViaCustoms => "1",
        /// 非經海關出口 (2;AIO 世代文件語彙——B2C 發票指南相反,見型別文件)
        NotViaCustoms => "2",
    }
}

wire_enum! {
    /// AIO 訂單附帶發票的課稅類別 (`TaxType`,1/2/3/9——沒有 B2C 發票 API 的
    /// 特種稅率 `'4'`,與 [`crate::invoice::TaxType`]、
    /// [`crate::invoice_b2b::TaxType`] 值域不同,型別刻意分開)。
    TaxType {
        /// 應稅 (1)
        Dutiable => "1",
        /// 零稅率 (2;需 ClearanceMark)
        ZeroRate => "2",
        /// 免稅 (3)
        Free => "3",
        /// 應稅與免稅混合 (9;限收銀機發票無法分辨時使用,且需申請核可)
        Mixed => "9",
    }
}

wire_enum! {
    /// AIO 訂單附帶發票的字軌類別 (`InvType`,07/08)。
    InvType {
        /// 一般稅額 (07)
        General => "07",
        /// 特種稅額 (08)
        Special => "08",
    }
}

/// 銀聯卡交易選項 (`UnionPay`)
pub mod union_pay {
    pub const SELECT: i64 = 0; // 消費者於交易頁面可選擇是否使用銀聯交易
    pub const ONLY: i64 = 1; // 只使用銀聯卡交易, 且綠界會將交易頁面直接導到銀聯網站
    pub const HIDDEN: i64 = 2; // 不可使用銀聯卡, 綠界會將交易頁面隱藏銀聯選項
}

/// 回覆付款方式 (`ReplyPaymentType`):ECPay 回傳的 PaymentType 代碼對應的
/// 中文說明。未知名稱回傳 `None`。
pub fn reply_payment_type(code: &str) -> Option<&'static str> {
    Some(match code {
        "WebATM_TAISHIN" => "台新銀行 WebATM",
        "WebATM_ESUN" => "玉山銀行 WebATM",
        "WebATM_BOT" => "台灣銀行 WebATM",
        "WebATM_FUBON" => "台北富邦 WebATM",
        "WebATM_CHINATRUST" => "中國信託 WebATM",
        "WebATM_FIRST" => "第一銀行 WebATM",
        "WebATM_CATHAY" => "國泰世華 WebATM",
        "WebATM_MEGA" => "兆豐銀行 WebATM",
        "WebATM_LAND" => "土地銀行 WebATM",
        "WebATM_TACHONG" => "元大銀行 WebATM",
        "WebATM_SINOPAC" => "永豐銀行 WebATM",
        "ATM_TAISHIN" => "台新銀行 ATM",
        "ATM_ESUN" => "玉山銀行 ATM",
        "ATM_BOT" => "台灣銀行 ATM",
        "ATM_FUBON" => "台北富邦 ATM",
        "ATM_CHINATRUST" => "中國信託 ATM",
        "ATM_FIRST" => "第一銀行 ATM",
        "ATM_LAND" => "土地銀行 ATM",
        "ATM_CATHAY" => "國泰世華銀行 ATM",
        "ATM_TACHONG" => "元大銀行 ATM",
        "CVS_CVS" => "超商代碼繳款",
        "CVS_OK" => "OK 超商代碼繳款",
        "CVS_FAMILY" => "全家超商代碼繳款",
        "CVS_HILIFE" => "萊爾富超商代碼繳款",
        "CVS_IBON" => "7-11 ibon 代碼繳款",
        "BARCODE_BARCODE" => "超商條碼繳款",
        "Credit_CreditCard" => "信用卡",
        "GooglePay" => "GooglePay",
        "ApplePay" => "ApplePay",
        "BNPL_URICH" => "裕富數位無卡分期",
        "BNPL_ZINGALA" => "中租銀角零卡",
        "DigitalPayment_Jkopay" => "街口支付",
        "DigitalPayment_iPASS" => "一卡通電子支付",
        "TWQR" => "歐付寶TWQR行動支付",
        "WeiXin" => "微信支付",
        _ => return None,
    })
}

// --- 伺服器端 API 參數結構 ---

/// `OrderSearch.order_search`(查詢訂單資訊,QueryTradeInfo/V5)。
#[derive(Debug, Clone, Default)]
pub struct OrderSearchParams {
    /// 特店交易編號(必填,最大 20 字元)。
    pub merchant_trade_no: String,
    /// 查詢時間(TimeStamp),Unix 秒數整數(必填)。
    pub time_stamp: i64,
    /// 平台特店合作專用(最大 10 字元)。
    pub platform_id: Option<String>,
}

/// `OrderSearchPeriodic.order_search_period`(查詢信用卡定期定額訂單,
/// QueryCreditCardPeriodInfo)。
#[derive(Debug, Clone, Default)]
pub struct OrderSearchPeriodParams {
    /// 特店交易編號(必填,最大 20 字元)。
    pub merchant_trade_no: String,
    /// 查詢時間,Unix 秒數整數(必填)。
    pub time_stamp: i64,
}

/// `CreditDoAction.credit_do_action`(信用卡關帳/退刷/取消/放棄,DoAction)。
#[derive(Debug, Clone, Default)]
pub struct CreditDoActionParams {
    /// 特店交易編號(必填,最大 20 字元)。
    pub merchant_trade_no: String,
    /// 綠界的交易編號(必填,最大 20 字元)。
    pub trade_no: String,
    /// 執行動作 `C`/`R`/`E`/`N`(必填,見 [`CreditAction`])。
    pub action: CreditAction,
    /// 交易金額(必填)。
    pub total_amount: i64,
    /// 平台特店合作專用(最大 10 字元)。
    pub platform_id: Option<String>,
}

/// `DownloadMerchantBalance.download_merchant_balance`
/// (下載特店餘額明細檔,TradeNoAio)。回傳為 Big5 編碼的 CSV 文字。
#[derive(Debug, Clone, Default)]
pub struct DownloadMerchantBalanceParams {
    /// 查詢類型 `1`~`5`(必填,最大 1 字元)。
    pub date_type: String,
    /// 查詢開始日期,yyyy-MM-dd(必填,最大 10 字元)。
    pub begin_date: String,
    /// 查詢結束日期,yyyy-MM-dd(必填,最大 10 字元)。
    pub end_date: String,
    /// 付款方式篩選(最大 2 字元)。
    pub payment_type: Option<String>,
    /// 平台資訊篩選(最大 1 字元)。
    pub platform_status: Option<String>,
    /// 付款狀態篩選(最大 1 字元)。
    pub payment_status: Option<String>,
    /// 撥款狀態篩選(最大 1 字元)。
    pub allocate_status: Option<String>,
    /// 憑證格式 `Y`/`N`(必填,最大 1 字元)。
    pub media_formated: String,
}

/// `SearchSingleTransaction.search_single_transaction`
/// (單筆交易查詢,CreditDetail/QueryTrade/V2)。
#[derive(Debug, Clone, Default)]
pub struct SearchSingleTransactionParams {
    /// 信用卡授權單號 CreditRefundId(必填)。
    pub credit_refund_id: i64,
    /// 信用卡金額 CreditAmount(必填)。
    pub credit_amount: i64,
    /// 信用卡檢查碼 CreditCheckCode(必填)。
    pub credit_check_code: i64,
}

/// `DownloadDisbursementBalance.download_disbursement_balance`
/// (下載撥款明細,FundingReconDetail)。回傳為 Big5 編碼的 CSV 文字。
#[derive(Debug, Clone, Default)]
pub struct DownloadDisbursementBalanceParams {
    /// 撥款日期類型(必填,最大 10 字元)。
    pub pay_date_type: String,
    /// 開始日期,yyyy-MM-dd(必填,最大 10 字元)。
    pub start_date: String,
    /// 結束日期,yyyy-MM-dd(必填,最大 10 字元)。
    pub end_date: String,
}

/// `CreditCardPeriodAction.credit_card_period_action`
/// (信用卡定期定額訂單狀態作業,CreditCardPeriodAction)。
#[derive(Debug, Clone, Default)]
pub struct CreditCardPeriodActionParams {
    /// 特店交易編號(必填,最大 20 字元)。
    pub merchant_trade_no: String,
    /// 訂單狀態處理動作(必填)。
    pub action: CreditAction,
    /// 查詢時間,Unix 秒數整數(必填)。
    pub time_stamp: i64,
    /// 平台特店合作專用(最大 10 字元)。
    pub platform_id: Option<String>,
}

impl Ecpay {
    /// Signs `m` with `CheckMacValue`, POSTs it to `endpoint`, verifies the
    /// response's own `CheckMacValue` (raising [`Error::CheckMacValueMismatch`]
    /// on mismatch or absence), and returns the response fields with
    /// CheckMacValue stripped (blank values kept, like
    /// `parse_qsl(keep_blank_values=True)`). Shared by [`Self::order_search`],
    /// [`Self::query_payment_info`], and [`Self::query_trade_info`], which
    /// only differ in endpoint and request fields.
    async fn post_cmv_verified(
        &self,
        endpoint: &str,
        mut m: HashMap<String, String>,
    ) -> Result<BTreeMap<String, String>> {
        // Verify with the digest the REQUEST was signed under (its own
        // EncryptType field, defaulting to SHA-256) — never the response's:
        // a verifier must not take its algorithm selector from the very
        // message it is verifying.
        let encrypt_type =
            crate::crypto::parse_encrypt_type(m.get("EncryptType").map(String::as_str));
        let mac = self.generate_check_value(&m)?;
        m.insert("CheckMacValue".to_owned(), mac);

        let body = self.post_form(endpoint, &m).await?;
        let mut query = parse_qsl(&String::from_utf8_lossy(&body));

        let got = query
            .remove("CheckMacValue")
            .filter(|v| !v.is_empty())
            .ok_or(Error::CheckMacValueMismatch)?;
        // Recompute over exactly the fields the server sent, unmodified —
        // unlike generate_check_value (for signing OUR outbound requests,
        // where forcing MerchantID to the configured client ID is correct),
        // a response must be hashed as received. ECPay's "trade not found"
        // reply for QueryPaymentInfo echoes MerchantID="" (confirmed live
        // against stage, 2026-09); forcing it to self.merchant_id before
        // recomputing produced a different hash than the server actually
        // signed, a false-positive CheckMacValueMismatch that order_search's
        // equivalent "not found" reply never exposed only because it happens
        // to echo the real MerchantID back.
        if !crate::crypto::verify_mac(
            &got,
            crate::crypto::str_pairs(&query),
            &self.hash_key,
            &self.hash_iv,
            encrypt_type,
        )? {
            return Err(Error::CheckMacValueMismatch);
        }
        Ok(query)
    }

    /// Signs `m` in place with `CheckMacValue` and POSTs it to `endpoint`;
    /// callers decode the raw body themselves (JSON / query-string / Big5).
    async fn post_signed_form(
        &self,
        endpoint: String,
        m: &mut HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let mac = self.generate_check_value(m)?;
        m.insert("CheckMacValue".to_owned(), mac);
        self.post_form(&endpoint, m).await
    }

    /// Shared request map for [`Self::order_search`] and
    /// [`Self::query_payment_info`], which take the same `OrderSearchParams`
    /// and only differ in endpoint.
    fn order_search_request(&self, p: &OrderSearchParams) -> Result<HashMap<String, String>> {
        required_str("MerchantTradeNo", &p.merchant_trade_no, 20)?;
        optional_str("PlatformID", &p.platform_id, 10)?;

        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("MerchantTradeNo".to_owned(), p.merchant_trade_no.clone());
        m.insert("TimeStamp".to_owned(), p.time_stamp.to_string());
        insert_optional_str(&mut m, "PlatformID", &p.platform_id);
        Ok(m)
    }

    /// `OrderSearch.order_search`(查詢訂單):signs the request, POSTs to
    /// `QueryTradeInfo/V5`, verifies the response CheckMacValue (raising
    /// [`Error::CheckMacValueMismatch`] on mismatch), and returns the
    /// response fields without CheckMacValue (blank values kept, like
    /// `parse_qsl(keep_blank_values=True)`).
    pub async fn order_search(&self, p: &OrderSearchParams) -> Result<BTreeMap<String, String>> {
        let m = self.order_search_request(p)?;
        let endpoint = format!("{}QueryTradeInfo/V5", self.payment_base_url());
        self.post_cmv_verified(&endpoint, m).await
    }

    /// `QueryPaymentInfo.query_payment_info`(查詢 ATM/CVS/BARCODE 取號結果,
    /// `Cashier/QueryPaymentInfo`,developers.ecpay.com.tw/5615.md)。請求參數
    /// 與 [`Self::order_search`] 相同,依付款方式回傳不同欄位子集(ATM:
    /// BankCode/vAccount/ExpireDate;CVS: PaymentNo/PaymentURL/ExpireDate;
    /// BARCODE: Barcode1~3/ExpireDate),故沿用 `BTreeMap<String, String>`
    /// 而非強型別回傳,與 [`Self::order_search`] 一致。
    pub async fn query_payment_info(
        &self,
        p: &OrderSearchParams,
    ) -> Result<BTreeMap<String, String>> {
        let m = self.order_search_request(p)?;
        let endpoint = format!("{}QueryPaymentInfo", self.payment_base_url());
        self.post_cmv_verified(&endpoint, m).await
    }

    /// `OrderSearchPeriodic.order_search_period`(查詢信用卡定期定額訂單):
    /// signs the request, POSTs to `QueryCreditCardPeriodInfo`, and returns
    /// the raw JSON reply (the official SDK also hands back the parsed JSON).
    pub async fn order_search_period(
        &self,
        p: &OrderSearchPeriodParams,
    ) -> Result<serde_json::Value> {
        required_str("MerchantTradeNo", &p.merchant_trade_no, 20)?;

        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("MerchantTradeNo".to_owned(), p.merchant_trade_no.clone());
        m.insert("TimeStamp".to_owned(), p.time_stamp.to_string());
        let endpoint = format!("{}QueryCreditCardPeriodInfo", self.payment_base_url());
        let body = self.post_signed_form(endpoint, &mut m).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// `CreditDoAction.credit_do_action`(信用卡關帳/退刷/取消/放棄):
    /// POSTs to `CreditDetail/DoAction` and returns the response fields.
    pub async fn credit_do_action(
        &self,
        p: &CreditDoActionParams,
    ) -> Result<BTreeMap<String, String>> {
        required_str("MerchantTradeNo", &p.merchant_trade_no, 20)?;
        required_str("TradeNo", &p.trade_no, 20)?;
        required_code("Action", &p.action)?;
        optional_str("PlatformID", &p.platform_id, 10)?;

        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("MerchantTradeNo".to_owned(), p.merchant_trade_no.clone());
        m.insert("TradeNo".to_owned(), p.trade_no.clone());
        m.insert("Action".to_owned(), p.action.as_str().to_owned());
        m.insert("TotalAmount".to_owned(), p.total_amount.to_string());
        insert_optional_str(&mut m, "PlatformID", &p.platform_id);
        let endpoint = format!("{}DoAction", self.credit_base_url());
        let body = self.post_signed_form(endpoint, &mut m).await?;
        Ok(parse_qsl(&String::from_utf8_lossy(&body)))
    }

    /// `DownloadMerchantBalance.download_merchant_balance`(下載特店餘額明細):
    /// POSTs to the vendor `TradeNoAio` endpoint and returns the response
    /// decoded from Big5 (the official SDK sets `response.encoding='big5'`).
    /// Undecodable bytes become U+FFFD rather than an error.
    pub async fn download_merchant_balance(
        &self,
        p: &DownloadMerchantBalanceParams,
    ) -> Result<String> {
        required_str("DateType", &p.date_type, 1)?;
        required_str("BeginDate", &p.begin_date, 10)?;
        required_str("EndDate", &p.end_date, 10)?;
        optional_str("PaymentType", &p.payment_type, 2)?;
        optional_str("PlatformStatus", &p.platform_status, 1)?;
        optional_str("PaymentStatus", &p.payment_status, 1)?;
        optional_str("AllocateStatus", &p.allocate_status, 1)?;
        required_str("MediaFormated", &p.media_formated, 1)?;

        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("DateType".to_owned(), p.date_type.clone());
        m.insert("BeginDate".to_owned(), p.begin_date.clone());
        m.insert("EndDate".to_owned(), p.end_date.clone());
        insert_optional_str(&mut m, "PaymentType", &p.payment_type);
        insert_optional_str(&mut m, "PlatformStatus", &p.platform_status);
        insert_optional_str(&mut m, "PaymentStatus", &p.payment_status);
        insert_optional_str(&mut m, "AllocateStatus", &p.allocate_status);
        m.insert("MediaFormated".to_owned(), p.media_formated.clone());
        let endpoint = format!("{}TradeNoAio", self.vendor_base_url());
        let body = self.post_signed_form(endpoint, &mut m).await?;
        Ok(decode_big5(&body))
    }

    /// `SearchSingleTransaction.search_single_transaction`(單筆交易查詢):
    /// POSTs to `CreditDetail/QueryTrade/V2` and returns the raw JSON reply.
    pub async fn search_single_transaction(
        &self,
        p: &SearchSingleTransactionParams,
    ) -> Result<serde_json::Value> {
        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("CreditRefundId".to_owned(), p.credit_refund_id.to_string());
        m.insert("CreditAmount".to_owned(), p.credit_amount.to_string());
        m.insert(
            "CreditCheckCode".to_owned(),
            p.credit_check_code.to_string(),
        );
        let endpoint = format!("{}QueryTrade/V2", self.credit_base_url());
        let body = self.post_signed_form(endpoint, &mut m).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// `DownloadDisbursementBalance.download_disbursement_balance`
    /// (下載撥款明細): POSTs to `CreditDetail/FundingReconDetail` and
    /// returns the response decoded from Big5.
    pub async fn download_disbursement_balance(
        &self,
        p: &DownloadDisbursementBalanceParams,
    ) -> Result<String> {
        required_str("PayDateType", &p.pay_date_type, 10)?;
        required_str("StartDate", &p.start_date, 10)?;
        required_str("EndDate", &p.end_date, 10)?;

        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("PayDateType".to_owned(), p.pay_date_type.clone());
        m.insert("StartDate".to_owned(), p.start_date.clone());
        m.insert("EndDate".to_owned(), p.end_date.clone());
        let endpoint = format!("{}FundingReconDetail", self.credit_base_url());
        let body = self.post_signed_form(endpoint, &mut m).await?;
        Ok(decode_big5(&body))
    }

    /// `CreditCardPeriodAction.credit_card_period_action`(信用卡定期定額訂單
    /// 狀態作業): POSTs to `Cashier/CreditCardPeriodAction` and returns the
    /// response fields.
    pub async fn credit_card_period_action(
        &self,
        p: &CreditCardPeriodActionParams,
    ) -> Result<BTreeMap<String, String>> {
        required_str("MerchantTradeNo", &p.merchant_trade_no, 20)?;
        required_code("Action", &p.action)?;
        optional_str("PlatformID", &p.platform_id, 10)?;

        let mut m = HashMap::new();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        m.insert("MerchantTradeNo".to_owned(), p.merchant_trade_no.clone());
        m.insert("Action".to_owned(), p.action.as_str().to_owned());
        m.insert("TimeStamp".to_owned(), p.time_stamp.to_string());
        insert_optional_str(&mut m, "PlatformID", &p.platform_id);
        let endpoint = format!("{}CreditCardPeriodAction", self.payment_base_url());
        let body = self.post_signed_form(endpoint, &mut m).await?;
        Ok(parse_qsl(&String::from_utf8_lossy(&body)))
    }
}

/// The official SDK sets `response.encoding='big5'` for the download
/// endpoints. Undecodable bytes become U+FFFD rather than an error.
fn decode_big5(body: &[u8]) -> String {
    let (text, _, _) = encoding_rs::BIG5.decode(body);
    text.into_owned()
}

// --- Go-port compatibility surface (QueryTradeInfo with a typed output) ---

/// Go `query_trade_info.go`'s typed QueryTradeInfo output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QueryTradeInfoOutput {
    pub merchant_id: String,             // 特店編號
    pub merchant_trade_no: String,       // 特店交易編號
    pub store_id: String,                // 特店旗下店舖代號
    pub trade_no: String,                // 綠界的交易編號
    pub trade_amt: String,               // 交易金額
    pub payment_date: String,            // 格式為yyyy/MM/dd HH:mm:ss
    pub payment_type: String,            // 特店選擇的付款方式
    pub handling_charge: String,         // 手續費合計
    pub payment_type_charge_fee: String, // 交易手續費金額
    pub trade_date: String,              // 訂單成立時間 格式為yyyy/MM/dd HH:mm:ss
    /// 若為0時，代表交易訂單成立未付款
    /// 若為1時，代表交易訂單成立已付款
    /// 若為 10200095時，代表交易訂單未成立，消費者未完成付款作業，故交易失敗。
    pub trade_status: String, // 交易狀態
    pub custom_field1: String,           // 自訂名稱欄位1
    pub custom_field2: String,           // 自訂名稱欄位2
    pub custom_field3: String,           // 自訂名稱欄位3
    pub custom_field4: String,           // 自訂名稱欄位4
}

impl Ecpay {
    /// Go `query_trade_info.go`'s typed query, on the crate's verification
    /// contract: same endpoint, request shape, and response CheckMacValue
    /// verification as [`Self::order_search`] (raising
    /// [`Error::CheckMacValueMismatch`] on mismatch or absence) — a query
    /// response is never trusted unsigned. Formerly the Go port's
    /// verify-less variant; the divergence was closed in 0.4.
    pub async fn query_trade_info(&self, order_id: &str) -> Result<QueryTradeInfoOutput> {
        let m = self.order_search_request(&OrderSearchParams {
            merchant_trade_no: order_id.to_owned(),
            time_stamp: crate::client::unix_now(),
            platform_id: None,
        })?;
        let endpoint = format!("{}QueryTradeInfo/V5", self.payment_base_url());
        let ss = self.post_cmv_verified(&endpoint, m).await?;
        let get = |k: &str| ss.get(k).cloned().unwrap_or_default();
        Ok(QueryTradeInfoOutput {
            merchant_id: get("MerchantID"),
            merchant_trade_no: get("MerchantTradeNo"),
            store_id: get("StoreID"),
            trade_no: get("TradeNo"),
            trade_amt: get("TradeAmt"),
            payment_date: get("PaymentDate"),
            payment_type: get("PaymentType"),
            handling_charge: get("HandlingCharge"),
            payment_type_charge_fee: get("PaymentTypeChargeFee"),
            trade_date: get("TradeDate"),
            trade_status: get("TradeStatus"),
            custom_field1: get("CustomField1"),
            custom_field2: get("CustomField2"),
            custom_field3: get("CustomField3"),
            custom_field4: get("CustomField4"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::decode_big5;

    #[test]
    fn big5_decodes_chinese_and_passes_ascii() {
        assert_eq!(decode_big5(b"hello"), "hello");
        // "X bef" — the word 全中文 in Big5.
        let big5_quan_zhong_wen = [0xA5, 0xFE, 0xA4, 0xA4, 0xA4, 0xE5];
        assert_eq!(
            decode_big5(&big5_quan_zhong_wen),
            "\u{5168}\u{4E2D}\u{6587}"
        );
    }

    #[test]
    fn big5_invalid_bytes_become_replacement_chars() {
        // 0x81/0xFF have no Big5 mapping on their own; encoding_rs yields
        // U+FFFD. (A leading 0xFF 0xFE pair is instead the UTF-16LE BOM and
        // gets stripped by decode() — BOM sniffing, not Big5 decoding.)
        assert_eq!(decode_big5(&[0x81]), "\u{FFFD}");
        assert_eq!(decode_big5(&[0xFF]), "\u{FFFD}");
    }
}
