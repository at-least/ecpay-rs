//! Rust port of ECPay's (綠界科技) official All-in-One payment SDK
//! ([ECPayAIO_Python]), extended — from the official PHP SDK examples and
//! live stage probing — with the B2C e-invoice (電子發票) AES-JSON APIs from
//! the reference Go SDK port, ECPG 站內付 2.0, B2B e-invoice, and the three
//! logistics families (domestic, AllInOne v2, cross-border).
//!
//! The CheckMacValue signing, AES envelope, and every wire field name are
//! pinned against ECPay's official test vectors; see the README for the
//! documented deviations from the Python SDK's literal behavior.
//!
//! [ECPayAIO_Python]: https://github.com/ECPay/ECPayAIO_Python
//!
//! # Example: build an All-in-One checkout form
//!
//! ```no_run
//! use ecpay::payment::{AioCheckOutParams, ChoosePayment};
//! use ecpay::Ecpay;
//!
//! // 金流 stage 測試帳號(公開測試用;正式環境請用自己的特店帳號與金鑰)。
//! let client = Ecpay {
//!     merchant_id: "3002607".into(),
//!     hash_key: "pwFHCqoQZGmho4w6".into(),
//!     hash_iv: "EkRm7iFT261dpevs".into(),
//!     ..Default::default()
//! };
//! let checkout = client
//!     .aio_check_out(&AioCheckOutParams {
//!         merchant_trade_no: "order-123".into(),
//!         merchant_trade_date: "2024/01/01 12:00:00".into(),
//!         total_amount: 100,
//!         trade_desc: "totality".into(),
//!         item_name: "商品 x1".into(),
//!         return_url: "https://example.com/ecpay/return".into(),
//!         choose_payment: ChoosePayment::Credit,
//!         ..Default::default()
//!     })
//!     .unwrap();
//! println!("{}", checkout.html_form()); // auto-submitting POST form
//! ```
//!
//! # Example: verify a payment-result callback
//!
//! ```
//! use std::collections::HashMap;
//! use ecpay::Ecpay;
//!
//! let client = Ecpay {
//!     merchant_id: "3002607".into(),
//!     hash_key: "pwFHCqoQZGmho4w6".into(),
//!     hash_iv: "EkRm7iFT261dpevs".into(),
//!     ..Default::default()
//! };
//! let mut params: HashMap<String, String> = [
//!     ("MerchantID", "3002607"),
//!     ("MerchantTradeNo", "Test1234567890"),
//!     ("RtnCode", "1"),
//!     ("RtnMsg", "Succeeded"),
//!     ("TradeNo", "2301011234567890"),
//!     ("TradeAmt", "100"),
//!     ("PaymentDate", "2025/01/01 12:05:00"),
//!     ("PaymentType", "Credit_CreditCard"),
//!     ("TradeDate", "2025/01/01 12:00:00"),
//!     ("SimulatePaid", "0"),
//!     (
//!         "CheckMacValue",
//!         "2AB536D86AFF8E1086744D59175040A32538C96B1C28C4135B551BD728E913B8",
//!     ),
//! ]
//! .into_iter()
//! .map(|(k, v)| (k.to_owned(), v.to_owned()))
//! .collect();
//! assert!(client.verify_check_mac_value(&params));
//! ```

use std::collections::HashMap;

pub mod client;
pub mod crypto;
pub mod ecpg;
pub mod error;
pub mod invoice;
pub mod invoice_b2b;
pub mod logistics;
pub mod payment;
mod wire;

pub use crypto::{
    check_mac_value, decrypt, decrypt_data, encrypt, encrypt_data, hash_mac, unmarshal, url_encode,
    EncryptType,
};
pub use ecpg::{
    AtmInfo, BarcodeInfo, CardInfo, ConsumerInfo, CreateBindCardInput, CreatePaymentInput,
    CreatePaymentWithCardIdInput, CvsInfo, DeleteMemberBindCardInput, EcpgDoActionInput,
    EcpgPeriodActionInput, EcpgTradeRefInput, GetMemberBindCardInput, GetTokenbyBindingCardInput,
    GetTokenbyTradeInput, GetTokenbyTradeOutput, GetTokenbyUserInput, OrderInfo,
    QueryTradeMediaInput, UnionPayInfo,
};
pub use error::{ApiError, Error, Result, Service};
pub use invoice::{
    AllowanceByCollegiateInput, AllowanceByCollegiateOutput, AllowanceInfoItem, AllowanceInput,
    AllowanceInvalidByCollegiateInput, AllowanceInvalidByCollegiateOutput, AllowanceInvalidInput,
    AllowanceInvalidOutput, AllowanceItem, AllowanceOutput, CancelDelayIssueInput,
    CancelDelayIssueOutput, CheckBarcodeInput, CheckBarcodeOutput, CheckLoveCodeInput,
    CheckLoveCodeOutput, DelayIssueInput, DelayIssueOutput, GetAllowanceInput,
    GetAllowanceInvalidInput, GetAllowanceInvalidOutput, GetAllowanceOutput,
    GetCompanyNameByTaxIDInput, GetCompanyNameByTaxIDOutput, GetGovInvoiceWordSettingInput,
    GetGovInvoiceWordSettingOutput, GetInvalidInput, GetInvalidOutput, GetInvoiceWordSettingInput,
    GetInvoiceWordSettingOutput, GetIssueInput, GetIssueOutput, GovInvoiceInfo, InvalidInput,
    InvalidOutput, InvoiceInfo, InvoiceNotifyInput, InvoiceNotifyOutput, IssueInput, IssueModel,
    IssueOutput, Item, TriggerIssueInput, TriggerIssueOutput, VoidModel, VoidWithReIssueInput,
    VoidWithReIssueOutput,
};
// The B2B invoice types without a same-named B2C counterpart, at the root
// like every other module's types. The seven that WOULD collide
// (`AllowanceInput`, `InvalidInput`, `GetIssueInput`, `GetInvalidInput`,
// `GetAllowanceInput`, `GetAllowanceInvalidInput`,
// `GetInvoiceWordSettingInput`) stay at `ecpay::invoice_b2b` — the same
// rule as the `_b2b` method suffixes.
pub use invoice_b2b::{
    AllowanceConfirmInput, B2bAllowanceDetail, B2bIssueOutput, B2bItem,
    CancelAllowanceConfirmInput, CancelAllowanceInput, GetAllowanceConfirmInput,
    GetAllowanceInvalidConfirmInput, GetInvalidConfirmInput, GetIssueConfirmInput,
    GetRejectConfirmInput, GetRejectInput, InvalidConfirmInput, IssueB2bInput, IssueConfirmInput,
    MaintainMerchantCustomerDataInput, NotifyInput, RejectConfirmInput, RejectInput,
};
pub use logistics::{
    AllInOneCancelC2cInput, AllInOneCreateTestDataInput, AllInOnePrintTradeDocumentInput,
    AllInOneQueryInput, AllInOneRedirectInput, AllInOneReturnCvsInput, AllInOneReturnHomeInput,
    AllInOneUpdateShipmentInfoInput, AllInOneUpdateStoreInfoInput, CancelC2cInput,
    CreateByTempTradeInput, CrossBorderCreateInput, CrossBorderCreateTestDataInput,
    CrossBorderMapInput, CrossBorderRefInput, DomesticQueryInput, GetStoreListInput,
    LogisticsCreateInput, LogisticsForm, MapInput, PrintC2c, ReturnCvsInput, ReturnHomeInput,
    UpdateShipmentInfoInput, UpdateStoreInfoInput, UpdateTempTradeInput,
};
pub use payment::{
    AioCheckOut, AioCheckOutParams, ChoosePayment, CreditCardPeriodActionParams,
    CreditDoActionParams, DownloadDisbursementBalanceParams, DownloadMerchantBalanceParams,
    OrderSearchParams, OrderSearchPeriodParams, QueryTradeInfoOutput,
    SearchSingleTransactionParams, MERCHANT_TRADE_DATE_FORMAT,
};

/// AIO payment (Cashier) base, production. Signed form/API calls
/// (`aio_check_out`, `order_search`, `query_trade_info`, …) POST here;
/// the credit actions (`credit_do_action`, `search_single_transaction`,
/// `download_*_balance`) live under [`CREDIT_API_URL_PRODUCTION`] and the
/// vendor path instead.
pub const PAYMENT_API_URL_PRODUCTION: &str = "https://payment.ecpay.com.tw/Cashier/";
/// AIO payment (Cashier) base, stage (public test merchant `3002607`).
pub const PAYMENT_API_URL_STAGE: &str = "https://payment-stage.ecpay.com.tw/Cashier/";

/// B2C e-invoice base, production (the AES-JSON envelope speaks
/// `Revision: "3.0.0"`).
pub const INVOICE_API_URL_PRODUCTION: &str = "https://einvoice.ecpay.com.tw/B2CInvoice/";
/// B2C e-invoice base, stage (public test merchant `2000132`).
pub const INVOICE_API_URL_STAGE: &str = "https://einvoice-stage.ecpay.com.tw/B2CInvoice/";

/// B2B invoice base. Same domain as B2C, different path; the RqHeader also
/// carries `RqID` + `Revision: "1.0.0"` (B2C uses `Revision: "3.0.0"`, no
/// RqID). HashKey/HashIV are the invoice ones (official PHP B2B examples
/// reuse `ejCk326UnaZWKisg`/`q9jcZX8Ib9LM8wYk` for 2000132).
pub const B2B_INVOICE_API_URL_PRODUCTION: &str = "https://einvoice.ecpay.com.tw/B2BInvoice/";
pub const B2B_INVOICE_API_URL_STAGE: &str = "https://einvoice-stage.ecpay.com.tw/B2BInvoice/";

/// Domestic + AllInOne-v2 + CrossBorder logistics base. All three families
/// live on one host under different paths (`Express/`, `Express/v2/`,
/// `CrossBorder/`, `Helper/`). CheckMacValue here is **MD5** (EncryptType=0).
pub const LOGISTICS_API_URL_PRODUCTION: &str = "https://logistics.ecpay.com.tw/";
pub const LOGISTICS_API_URL_STAGE: &str = "https://logistics-stage.ecpay.com.tw/";

/// 站內付 2.0 (ECPG): token/order creation lives here (`Merchant/*`).
/// The AES envelope's RqHeader carries ONLY `Timestamp` (no Revision).
pub const ECPG_API_URL_PRODUCTION: &str = "https://ecpg.ecpay.com.tw/Merchant/";
pub const ECPG_API_URL_STAGE: &str = "https://ecpg-stage.ecpay.com.tw/Merchant/";

/// 站內付 2.0 queries/actions live on a SECOND domain (`1.0.0/*`) — mixing
/// the two is the classic 404 trap. HashKey/HashIV are the payment ones.
pub const ECPAYMENT_API_URL_PRODUCTION: &str = "https://ecpayment.ecpay.com.tw/1.0.0/";
pub const ECPAYMENT_API_URL_STAGE: &str = "https://ecpayment-stage.ecpay.com.tw/1.0.0/";

/// The CreditDetail endpoints (credit_do_action, search_single_transaction,
/// download_disbursement_balance) live under their own path. Production base,
/// verbatim from the official SDK's hardcoded URLs.
pub const CREDIT_API_URL_PRODUCTION: &str = "https://payment.ecpay.com.tw/CreditDetail/";

/// The CreditDetail endpoints' stage base (same host as the payment stage).
pub const CREDIT_API_URL_STAGE: &str = "https://payment-stage.ecpay.com.tw/CreditDetail/";

/// The vendor (特店後台) endpoints (download_merchant_balance). Production
/// base, verbatim from the official SDK's hardcoded URL.
pub const VENDOR_API_URL_PRODUCTION: &str = "https://vendor.ecpay.com.tw/PaymentMedia/";

/// The vendor (特店後台) endpoints' stage base (特店後台 stage host).
pub const VENDOR_API_URL_STAGE: &str = "https://vendor-stage.ecpay.com.tw/PaymentMedia/";

/// The configured client (Go `type Ecpay struct`; the official Python SDK's
/// `ECPayPaymentSdk(MerchantID, HashKey, HashIV)` constructor). The zero
/// value is valid: empty API URLs fall back to the production endpoints.
///
/// `Debug` is hand-written and redacts every signing secret (`hash_key`,
/// `hash_iv`, `invoice_hash_key`, `invoice_hash_iv`, `logistics_hash_key`,
/// `logistics_hash_iv`) so a stray `{:?}` on the client never logs them.
/// Key material can additionally be scrubbed from memory explicitly via
/// [`Self::zeroize_signing_keys`] (automatic zeroize-on-drop is impossible
/// here: a `Drop` impl would break the `..Default::default()` construction
/// idiom — see that method's docs).
#[derive(Clone, Default)]
pub struct Ecpay {
    pub platform_id: String,
    pub merchant_id: String,
    pub hash_key: String,
    pub hash_iv: String,
    pub payment_api_url: String,
    pub invoice_api_url: String,
    pub invoice_hash_key: String,
    pub invoice_hash_iv: String,
    /// 特店自訂編號。⚠ **從未被讀取**（同 [`Self::return_url`] 的說明）：
    /// 發票自訂編號要設在各請求參數上，例如
    /// [`crate::payment::InvoiceExtend::relate_number`]、
    /// [`crate::invoice::IssueInput::relate_number`]。
    ///
    /// 與 [`Self::return_url`] 同款的 `compile_fail` 釘住：
    ///
    /// ```compile_fail
    /// # use ecpay::Ecpay;
    /// #[deny(deprecated)]
    /// fn client_fields_must_not_silently_noop() {
    ///     let _ = Ecpay {
    ///         relate_number: "Tea0001".into(),
    ///         ..Default::default()
    ///     };
    /// }
    /// # fn main() { client_fields_must_not_silently_noop() }
    /// ```
    #[deprecated(
        since = "0.5.0",
        note = "this field is never read; set the request params instead (e.g. AioCheckOutParams / InvoiceExtend / IssueInput)"
    )]
    pub relate_number: String,
    /// ⚠ **從未被讀取**（全庫審查 2026-09 的發現）：client 級欄位在本 crate
    /// 沒有任何程式路徑使用——回呼網址要設在**各請求參數**上，例如
    /// [`crate::payment::AioCheckOutParams::return_url`]、
    /// [`crate::ecpg::OrderInfo::return_url`]、
    /// [`crate::logistics::LogisticsCreateInput::server_reply_url`]。
    /// 從官方 SDK 移植時若把網址留在 client 上，簽出的請求會靜默帶空回呼。
    ///
    /// 這個 doc test 釘住「欄位帶 deprecated」：若有人移除 `#[deprecated]`
    /// 而沒有真的讓欄位生效，此測試會失敗（編譯成功 = 設定值依舊無效）。
    ///
    /// ```compile_fail
    /// # use ecpay::Ecpay;
    /// #[deny(deprecated)]
    /// fn client_fields_must_not_silently_noop() {
    ///     let _ = Ecpay {
    ///         return_url: "https://example.com/callback".into(),
    ///         ..Default::default()
    ///     };
    /// }
    /// # fn main() { client_fields_must_not_silently_noop() }
    /// ```
    #[deprecated(
        since = "0.5.0",
        note = "this field is never read; set AioCheckOutParams::return_url (or the request params') instead"
    )]
    pub return_url: String,
    /// ⚠ **從未被讀取**：同 [`Self::return_url`]——付款人繳費通知網址要設在
    /// [`crate::payment::AioCheckOutParams::payment_info_url`]。
    ///
    /// 與 [`Self::return_url`] 同款的 `compile_fail` 釘住：
    ///
    /// ```compile_fail
    /// # use ecpay::Ecpay;
    /// #[deny(deprecated)]
    /// fn client_fields_must_not_silently_noop() {
    ///     let _ = Ecpay {
    ///         payment_info_url: "https://example.com/notify".into(),
    ///         ..Default::default()
    ///     };
    /// }
    /// # fn main() { client_fields_must_not_silently_noop() }
    /// ```
    #[deprecated(
        since = "0.5.0",
        note = "this field is never read; set AioCheckOutParams::payment_info_url instead"
    )]
    pub payment_info_url: String,
    /// Base URL for the CreditDetail endpoints; empty = production.
    pub credit_api_url: String,
    /// Base URL for the vendor (特店後台) endpoints; empty = production.
    pub vendor_api_url: String,
    /// Logistics base (`Express/`, `Express/v2/`, `CrossBorder/`, `Helper/`
    /// are appended); empty = production.
    pub logistics_api_url: String,
    /// Logistics HashKey/HashIV. Domestic 物流特店 usually gets its OWN keys
    /// (stage B2C: 2000132/`5294y06JbISpM5x9`; C2C: 2000933/`XBERn1YOvpM9nfZc`),
    /// so unlike the invoice pair these fall back to `hash_key`/`hash_iv`
    /// when left empty.
    pub logistics_hash_key: String,
    pub logistics_hash_iv: String,
    /// 站內付 2.0 token/order-creation base (`Merchant/*` appended); empty =
    /// production. Uses the PAYMENT HashKey/HashIV.
    pub ecpg_api_url: String,
    /// 站內付 2.0 query/action base (`1.0.0/*` paths appended, e.g.
    /// `1.0.0/Cashier/QueryTrade` is `{base}Cashier/QueryTrade`); empty =
    /// production.
    pub ecpayment_api_url: String,
    /// B2B invoice base (`Issue`, `Allowance`, … appended); empty =
    /// production. Uses the INVOICE HashKey/HashIV.
    pub b2b_invoice_api_url: String,
    /// B2B envelope `RqHeader.RqID` — a GUID-format request ID you generate.
    /// ECPay does not dedupe on it (proven on stage: one fixed RqID issued
    /// two distinct invoices), but production integrations should still make
    /// it unique per request for their own auditing. The field lives on the
    /// client, so per-request uniqueness is a clone-and-set away:
    /// `let mut c = client.clone(); c.b2b_rq_id = new_guid();`.
    /// **Required**: every B2B call is refused locally when this is empty
    /// (the official PHP examples always send an RqID; whether the stage
    /// accepts an empty one is unverified, and the crate will not gamble
    /// the request on it).
    pub b2b_rq_id: String,
    /// Optional injected HTTP client (your own pooling/timeout policy, or a
    /// mock in tests). `None` (the default) uses the crate's shared hardened
    /// client: no redirect following, 10s connect / 30s overall timeouts, no
    /// idle-connection pooling. An injected client is used **as-is** — the
    /// hardening is not (and cannot be) applied to it.
    pub http: Option<reqwest::Client>,
}

impl Ecpay {
    /// Zeroes the six signing-key buffers in place ([`zeroize`] semantics:
    /// bytes become 0 and each `String` truncates), for callers that want
    /// key material scrubbed from memory — e.g. before process exit.
    ///
    /// ⚠ Why **explicit** and not `Drop`: an automatic zeroize-on-drop
    /// would forbid moving out of an `Ecpay` (E0509), breaking the crate's
    /// documented `Ecpay { .., ..Default::default() }` construction idiom
    /// at every call site. Scrubbing is therefore a choice the embedder
    /// makes.
    ///
    /// ⚠ **Best effort, not a guarantee**: only the CURRENT buffers are
    /// scrubbed — `Ecpay` is `Clone`, so every clone keeps its own live
    /// copy (zeroize each clone too), and a `String` that ever reallocated
    /// may leave stale heap copies this cannot reach. Beyond the fields,
    /// every signing/verification call builds transient unzeroed buffers
    /// that contain key bytes (the CheckMacValue preimage and its
    /// url-encoded copy, AES/base64 work buffers) — inherent to the
    /// string-based protocol and unreachable from here. Also note a
    /// zeroized client is not defensively unusable: `logistics_keys()`
    /// falls back to the (now empty) payment pair, so reusing it signs
    /// with an empty key and ships a MAC the server will reject. Zeroize,
    /// then drop.
    pub fn zeroize_signing_keys(&mut self) {
        use zeroize::Zeroize;
        self.hash_key.zeroize();
        self.hash_iv.zeroize();
        self.invoice_hash_key.zeroize();
        self.invoice_hash_iv.zeroize();
        self.logistics_hash_key.zeroize();
        self.logistics_hash_iv.zeroize();
    }
}

impl std::fmt::Debug for Ecpay {
    // The three deprecated legacy fields are still debug-printed: they carry
    // whatever the caller configured, and hiding them would make a stray
    // config harder to spot. Reading them here is not a use that changes
    // behavior (nothing else reads them — see the field docs).
    #[allow(deprecated)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Ecpay");
        s.field("platform_id", &self.platform_id)
            .field("merchant_id", &self.merchant_id)
            .field("hash_key", &"***")
            .field("hash_iv", &"***")
            .field("payment_api_url", &self.payment_api_url)
            .field("invoice_api_url", &self.invoice_api_url)
            .field("invoice_hash_key", &"***")
            .field("invoice_hash_iv", &"***")
            .field("relate_number", &self.relate_number)
            .field("return_url", &self.return_url)
            .field("payment_info_url", &self.payment_info_url)
            .field("credit_api_url", &self.credit_api_url)
            .field("vendor_api_url", &self.vendor_api_url)
            .field("logistics_api_url", &self.logistics_api_url)
            .field("logistics_hash_key", &"***")
            .field("logistics_hash_iv", &"***")
            .field("ecpg_api_url", &self.ecpg_api_url)
            .field("ecpayment_api_url", &self.ecpayment_api_url)
            .field("b2b_invoice_api_url", &self.b2b_invoice_api_url)
            .field("b2b_rq_id", &self.b2b_rq_id)
            // The client carries no secrets but also nothing worth dumping.
            .field("http", &self.http.as_ref().map(|_| "client"));
        s.finish()
    }
}

impl Ecpay {
    /// A stage (sandbox) client: the credentials plus EVERY service base URL
    /// set to its stage endpoint in one call.
    ///
    /// Why this exists: each `*_api_url` field independently falls back to
    /// its PRODUCTION endpoint when left empty, so a client configured for
    /// stage field by field silently sends signed production traffic the
    /// moment one field is missed — and payment APIs move real money.
    /// `Ecpay::stage` removes the per-field trap: the struct is built
    /// field-by-field WITHOUT `..Default::default()`, so adding a future
    /// URL field to `Ecpay` breaks this constructor's compilation until it
    /// gains a stage entry (the test pins all eight current fields).
    ///
    /// The credentials are still yours to supply (ECPay's public stage test
    /// accounts are published in the official docs); the invoice/logistics
    /// key pairs (`invoice_hash_key`/`invoice_hash_iv`,
    /// `logistics_hash_key`/`logistics_hash_iv`) and the B2B `b2b_rq_id`
    /// remain per-service settings on top of this base, exactly like on a
    /// hand-built client.
    // The struct literal names every field, including the three deprecated
    // legacy ones — zero-value init keeps the literal exhaustive against
    // future fields (see above).
    #[allow(deprecated)]
    pub fn stage(
        merchant_id: impl Into<String>,
        hash_key: impl Into<String>,
        hash_iv: impl Into<String>,
    ) -> Self {
        // Every field explicit — no `..Default::default()`, on purpose (see
        // the doc above): a newly added field must be decided here, not
        // silently defaulted to "" (= the production endpoint).
        Self {
            platform_id: String::new(),
            merchant_id: merchant_id.into(),
            hash_key: hash_key.into(),
            hash_iv: hash_iv.into(),
            payment_api_url: PAYMENT_API_URL_STAGE.to_owned(),
            invoice_api_url: INVOICE_API_URL_STAGE.to_owned(),
            invoice_hash_key: String::new(),
            invoice_hash_iv: String::new(),
            relate_number: String::new(),
            return_url: String::new(),
            payment_info_url: String::new(),
            credit_api_url: CREDIT_API_URL_STAGE.to_owned(),
            vendor_api_url: VENDOR_API_URL_STAGE.to_owned(),
            logistics_api_url: LOGISTICS_API_URL_STAGE.to_owned(),
            logistics_hash_key: String::new(),
            logistics_hash_iv: String::new(),
            ecpg_api_url: ECPG_API_URL_STAGE.to_owned(),
            ecpayment_api_url: ECPAYMENT_API_URL_STAGE.to_owned(),
            b2b_invoice_api_url: B2B_INVOICE_API_URL_STAGE.to_owned(),
            b2b_rq_id: String::new(),
            http: None,
        }
    }

    /// The Cashier base (`{payment_api_url}{Action}/V5`), defaulting to
    /// production when unset.
    pub(crate) fn payment_base_url(&self) -> &str {
        if self.payment_api_url.is_empty() {
            PAYMENT_API_URL_PRODUCTION
        } else {
            &self.payment_api_url
        }
    }

    /// The B2CInvoice base, defaulting to production when unset.
    pub(crate) fn invoice_base_url(&self) -> &str {
        if self.invoice_api_url.is_empty() {
            INVOICE_API_URL_PRODUCTION
        } else {
            &self.invoice_api_url
        }
    }

    /// The CreditDetail base, defaulting to production when unset.
    pub(crate) fn credit_base_url(&self) -> &str {
        if self.credit_api_url.is_empty() {
            CREDIT_API_URL_PRODUCTION
        } else {
            &self.credit_api_url
        }
    }

    /// The vendor base, defaulting to production when unset.
    pub(crate) fn vendor_base_url(&self) -> &str {
        if self.vendor_api_url.is_empty() {
            VENDOR_API_URL_PRODUCTION
        } else {
            &self.vendor_api_url
        }
    }

    /// The logistics base, defaulting to production when unset.
    pub(crate) fn logistics_base_url(&self) -> &str {
        if self.logistics_api_url.is_empty() {
            LOGISTICS_API_URL_PRODUCTION
        } else {
            &self.logistics_api_url
        }
    }

    /// Logistics signing keys, falling back to the payment HashKey/HashIV.
    pub(crate) fn logistics_keys(&self) -> (&str, &str) {
        let key = if self.logistics_hash_key.is_empty() {
            &self.hash_key
        } else {
            &self.logistics_hash_key
        };
        let iv = if self.logistics_hash_iv.is_empty() {
            &self.hash_iv
        } else {
            &self.logistics_hash_iv
        };
        (key, iv)
    }

    /// Invoice (B2C + B2B) AES keys as bytes — the single `as_bytes()` site
    /// for these fields.
    pub(crate) fn invoice_keys(&self) -> (&[u8], &[u8]) {
        (
            self.invoice_hash_key.as_bytes(),
            self.invoice_hash_iv.as_bytes(),
        )
    }

    /// 站內付 2.0 token base (`Merchant/*`), defaulting to production.
    pub(crate) fn ecpg_base_url(&self) -> &str {
        if self.ecpg_api_url.is_empty() {
            ECPG_API_URL_PRODUCTION
        } else {
            &self.ecpg_api_url
        }
    }

    /// 站內付 2.0 query base (`1.0.0/*`), defaulting to production.
    pub(crate) fn ecpayment_base_url(&self) -> &str {
        if self.ecpayment_api_url.is_empty() {
            ECPAYMENT_API_URL_PRODUCTION
        } else {
            &self.ecpayment_api_url
        }
    }

    /// B2B invoice base, defaulting to production when unset.
    pub(crate) fn b2b_base_url(&self) -> &str {
        if self.b2b_invoice_api_url.is_empty() {
            B2B_INVOICE_API_URL_PRODUCTION
        } else {
            &self.b2b_invoice_api_url
        }
    }

    /// VerifyCheckMacValue recomputes the CheckMacValue over every parameter
    /// except CheckMacValue itself (with the payment HashKey/HashIV) and
    /// reports, in constant time, whether it matches the supplied one. ECPay
    /// requires this on inbound payment-result callbacks. `params` is the
    /// posted form, including the "CheckMacValue" field; a missing/empty value
    /// verifies as false. (SHA-256 only: EncryptType=0 is retired.)
    ///
    /// Verification does NOT bind `MerchantID` (or the amount): a signature
    /// computed with your keys over another order's params passes. Before
    /// fulfilling, compare the posted `MerchantID`/`TradeAmt` against your
    /// own records — multi-tenant deployments especially (see the README's
    /// callback checklist).
    pub fn verify_check_mac_value(&self, params: &HashMap<String, String>) -> bool {
        // An unconfigured client must never "verify": whoever knows the param
        // set can compute the empty-key MAC themselves, so accepting it would
        // turn this into a forged-callback oracle, not a check.
        if self.hash_key.is_empty() || self.hash_iv.is_empty() {
            return false;
        }
        let got = match params.get("CheckMacValue") {
            Some(v) if !v.is_empty() => v,
            _ => return false,
        };
        // SHA-256 only: EncryptType=0 is retired. A caller-supplied
        // EncryptType field is deliberately ignored here.
        crypto::verify_mac(
            got,
            crypto::str_pairs(params),
            &self.hash_key,
            &self.hash_iv,
            crypto::EncryptType::Sha256,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_signing_keys_empties_all_six_key_buffers() {
        // The pinned contract of the public scrub API: after it runs, none
        // of the six key `String`s may retain their bytes (zeroize zeroes
        // the buffer and truncates). This is the only safely observable
        // part — zeroize-on-DROP itself is not observable in safe Rust.
        let mut client = Ecpay {
            merchant_id: "3002607".into(),
            hash_key: "pwFHCqoQZGmho4w6".into(),
            hash_iv: "EkRm7iFT261dpevs".into(),
            invoice_hash_key: "ejCk326UnaZWKisg".into(),
            invoice_hash_iv: "q9jcZX8Ib9LM8wYk".into(),
            logistics_hash_key: "5294y06JbISpM5x9".into(),
            logistics_hash_iv: "v77hoKGq4kWxNNIS".into(),
            ..Default::default()
        };
        client.zeroize_signing_keys();
        for (name, key) in [
            ("hash_key", &client.hash_key),
            ("hash_iv", &client.hash_iv),
            ("invoice_hash_key", &client.invoice_hash_key),
            ("invoice_hash_iv", &client.invoice_hash_iv),
            ("logistics_hash_key", &client.logistics_hash_key),
            ("logistics_hash_iv", &client.logistics_hash_iv),
        ] {
            assert!(key.is_empty(), "{name} must be zeroized, got {key:?}");
        }
    }

    #[test]
    fn debug_redacts_the_signing_secrets() {
        let client = Ecpay {
            merchant_id: "3002607".into(),
            hash_key: "pwFHCqoQZGmho4w6".into(),
            hash_iv: "EkRm7iFT261dpevs".into(),
            invoice_hash_key: "ejCk326UnaZWKisg".into(),
            invoice_hash_iv: "q9jcZX8Ib9LM8wYk".into(),
            logistics_hash_key: "5294y06JbISpM5x9".into(),
            logistics_hash_iv: "v77hoKGq4kWxNNIS".into(),
            ..Default::default()
        };
        let dumped = format!("{client:?}");
        for secret in [
            "pwFHCqoQZGmho4w6",
            "EkRm7iFT261dpevs",
            "ejCk326UnaZWKisg",
            "q9jcZX8Ib9LM8wYk",
            "5294y06JbISpM5x9",
            "v77hoKGq4kWxNNIS",
        ] {
            assert!(!dumped.contains(secret), "Debug leaked {secret}: {dumped}");
        }
        assert!(dumped.contains("hash_key: \"***\""), "{dumped}");
        assert!(dumped.contains("merchant_id: \"3002607\""), "{dumped}");
    }

    #[test]
    fn verify_check_mac_value_is_sha256_only_ignoring_encrypt_type_field() {
        let client = Ecpay {
            merchant_id: "3002607".into(),
            hash_key: "pwFHCqoQZGmho4w6".into(),
            hash_iv: "EkRm7iFT261dpevs".into(),
            ..Default::default()
        };
        // A posted form that carries EncryptType=0: verification must still
        // recompute with SHA-256 (EncryptType=0 is retired) and therefore
        // match the SHA-256 mac over the same fields.
        let mut posted = HashMap::new();
        posted.insert("MerchantID".to_owned(), "3002607".to_owned());
        posted.insert("EncryptType".to_owned(), "0".to_owned());
        let sha = crypto::check_mac_value(
            &posted,
            &client.hash_key,
            &client.hash_iv,
            crypto::EncryptType::Sha256,
        );
        posted.insert("CheckMacValue".to_owned(), sha);
        assert!(client.verify_check_mac_value(&posted));

        // And an MD5 mac fails verification even when EncryptType=0 claims
        // MD5 — the field is never honored on inbound verification.
        let md5 = crypto::check_mac_value(
            &posted,
            &client.hash_key,
            &client.hash_iv,
            crypto::EncryptType::Md5,
        );
        posted.insert("CheckMacValue".to_owned(), md5);
        assert!(!client.verify_check_mac_value(&posted));
    }
}
