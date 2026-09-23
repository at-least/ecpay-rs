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
//! use ecpay::{Ecpay, Env, Keys};
//!
//! // 金流 stage 測試帳號(公開測試用;正式環境請用自己的特店帳號與金鑰)。
//! let client = Ecpay::new("3002607", Env::Production).unwrap()
//!     .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs").unwrap());
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
//! use ecpay::{Ecpay, Env, Keys};
//!
//! let client = Ecpay::new("3002607", Env::Production).unwrap()
//!     .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs").unwrap());
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

pub use client::parse_form;
pub use crypto::{
    check_mac_value, decrypt, decrypt_data, encrypt, encrypt_data, hash_mac, unmarshal, url_encode,
    EncryptType,
};
pub use ecpg::{
    AtmInfo, BarcodeInfo, CardInfo, ConsumerInfo, CreateBindCardInput, CreatePaymentInput,
    CreatePaymentWithCardIdInput, CvsInfo, DeleteMemberBindCardInput, EcpgCreditAction,
    EcpgDoActionInput, EcpgPeriodActionInput, EcpgTradeRefInput, GetMemberBindCardInput,
    GetTokenbyBindingCardInput, GetTokenbyTradeInput, GetTokenbyTradeOutput, GetTokenbyUserInput,
    OrderInfo, QueryTradeMediaInput, UnionPayInfo,
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

/// A validated HashKey/HashIV pair (one ECPay service family's signing
/// keys). Constructed only through [`Keys::new`], which refuses empty
/// halves and wrong BYTE lengths (AES needs a 16/24/32-byte key and
/// exactly a 16-byte IV) — a typo'd config fails at construction instead
/// of as an opaque server error.
///
/// Dropping a `Keys` zeroizes its buffers ([`zeroize`] semantics); the
/// pairs are whole by construction, so a key from one pair can never be
/// mixed with another pair's IV.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Keys {
    key: String,
    iv: String,
}

impl Keys {
    /// Validates and stores a HashKey/HashIV pair. Byte lengths, not
    /// chars: ECPay issues 16-byte pairs, and the AES envelope paths
    /// (invoice/B2B/ECPG/logistics v2) require the key to be a valid
    /// AES-128/192/256 key and the IV exactly one 16-byte AES block.
    pub fn new(key: impl Into<String>, iv: impl Into<String>) -> Result<Self> {
        let key = key.into();
        let iv = iv.into();
        if key.is_empty() || iv.is_empty() {
            return Err(Error::Validation(
                "HashKey and HashIV must both be set — an empty pair signs nothing".into(),
            ));
        }
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(Error::Validation(format!(
                "HashKey must be 16, 24, or 32 bytes for AES (got {} bytes)",
                key.len()
            )));
        }
        if iv.len() != 16 {
            return Err(Error::Validation(format!(
                "HashIV must be exactly 16 bytes for AES-CBC (got {} bytes)",
                iv.len()
            )));
        }
        Ok(Self { key, iv })
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn iv(&self) -> &str {
        &self.iv
    }
}

impl std::fmt::Debug for Keys {
    // Redacted like the client's own Debug: key material must never reach
    // a log line through a stray {:?}.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("key", &"***")
            .field("iv", &"***")
            .finish()
    }
}

/// A base URL validated ONCE at construction: **https** only, `http`
/// allowed for loopback hosts (`127.0.0.1`, `localhost`, `::1` — the
/// hermetic test servers and local development bind there). Everything
/// else — a mistyped `http://` production base, another scheme, a
/// schemeless string, a lookalike host (`127.0.0.1.evil.com`), or a URL
/// carrying userinfo (`127.0.0.1:80@evil.com`) — is refused here, before
/// any signed payload exists to ship in cleartext. The same rule also
/// runs at request time as defense in depth.
#[derive(Clone, PartialEq, Eq)]
pub struct BaseUrl(String);

impl BaseUrl {
    /// Validates the scheme/host rule and stores the base URL. Base URLs
    /// are path prefixes: endpoints join as `{base}{action}` and a missing
    /// trailing `/` is normalized at the join.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        crate::client::ensure_https(&url)?;
        Ok(Self(url))
    }

    /// The stored base URL, verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Per-family base URLs for [`Env::Custom`] — every family you intend to
/// call must be `Some`; a family left `None` refuses LOUDLY at that
/// family's call site (never a silent fallback to production). `Default`
/// plus functional-update syntax (`Urls { payment: Some(..),
/// ..Default::default() }`) is the supported construction idiom and is
/// forward-compatible with new fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Urls {
    /// AIO payment (Cashier) base: `aio_check_out`, `order_search`,
    /// `query_trade_info`, …
    pub payment: Option<BaseUrl>,
    /// B2C e-invoice base (AES-JSON envelope, `Revision: "3.0.0"`).
    pub invoice: Option<BaseUrl>,
    /// CreditDetail base (`credit_do_action`,
    /// `search_single_transaction`, `download_disbursement_balance`).
    pub credit: Option<BaseUrl>,
    /// Vendor (特店後台) base (`download_merchant_balance`).
    pub vendor: Option<BaseUrl>,
    /// Logistics base — domestic (`Express/`), AllInOne v2 (`Express/v2/`),
    /// cross-border (`CrossBorder/`), helpers (`Helper/`).
    pub logistics: Option<BaseUrl>,
    /// ECPG token/order-creation base (`Merchant/*`).
    pub ecpg: Option<BaseUrl>,
    /// ECPG query/action base (`1.0.0/*`) — a SECOND domain; mixing the
    /// two is the classic 404 trap.
    pub ecpayment: Option<BaseUrl>,
    /// B2B invoice base (`Issue`, `Allowance`, …).
    pub b2b_invoice: Option<BaseUrl>,
}

/// Which endpoints a client talks to. `Stage` and `Production` configure
/// EVERY family at once; `Custom` takes exactly what you set and nothing
/// more. There is deliberately no empty-field-means-production fallback
/// anywhere: a family you did not configure is an error, not a guess —
/// payment APIs move real money.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Env {
    /// ECPay's stage (sandbox) endpoints for every family.
    Stage,
    /// ECPay's production endpoints for every family.
    Production,
    /// Your own per-family bases (proxies, test doubles): every `Some`
    /// field is used as given; every `None` family refuses at call time.
    Custom(Urls),
}

impl Env {
    fn resolve(&self) -> Urls {
        // The stage/production constants are crate-controlled https URLs;
        // `BaseUrl`'s field stays private so no caller can smuggle an
        // unvalidated one in through Env either.
        fn trusted(url: &'static str) -> Option<BaseUrl> {
            Some(BaseUrl(url.to_owned()))
        }
        fn set(env: Env) -> Urls {
            let stage = matches!(env, Env::Stage);
            let pick = |s: &'static str, p: &'static str| trusted(if stage { s } else { p });
            Urls {
                payment: pick(PAYMENT_API_URL_STAGE, PAYMENT_API_URL_PRODUCTION),
                invoice: pick(INVOICE_API_URL_STAGE, INVOICE_API_URL_PRODUCTION),
                credit: pick(CREDIT_API_URL_STAGE, CREDIT_API_URL_PRODUCTION),
                vendor: pick(VENDOR_API_URL_STAGE, VENDOR_API_URL_PRODUCTION),
                logistics: pick(LOGISTICS_API_URL_STAGE, LOGISTICS_API_URL_PRODUCTION),
                ecpg: pick(ECPG_API_URL_STAGE, ECPG_API_URL_PRODUCTION),
                ecpayment: pick(ECPAYMENT_API_URL_STAGE, ECPAYMENT_API_URL_PRODUCTION),
                b2b_invoice: pick(B2B_INVOICE_API_URL_STAGE, B2B_INVOICE_API_URL_PRODUCTION),
            }
        }
        match self {
            Env::Stage | Env::Production => set(self.clone()),
            Env::Custom(urls) => urls.clone(),
        }
    }
}

/// The configured client. Invalid states are unrepresentable by
/// construction: [`Ecpay::new`] requires a merchant ID and an [`Env`]
/// (URLs https-validated once, no silent production fallback for a family
/// you did not configure), and each family's [`Keys`] enter only through
/// the `with_*_keys` setters after [`Keys::new`] validated them. A family
/// whose keys or URL were never configured refuses LOUDLY at that
/// family's call site, before anything is sent.
///
/// ```no_run
/// # fn main() -> ecpay::Result<()> {
/// use ecpay::{Ecpay, Env, Keys};
/// let client = Ecpay::new("3002607", Env::Stage)?
///     .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs")?);
/// # Ok(())
/// # }
/// ```
///
/// `Debug` redacts every signing secret; dropping the client (or calling
/// [`Self::zeroize_signing_keys`]) scrubbs the key bytes — the pairs are
/// whole `Keys` values that zeroize on drop, and the explicit call
/// additionally clears their presence so a scrubbed client refuses
/// further calls instead of signing with empty bytes.
#[derive(Clone)]
pub struct Ecpay {
    merchant_id: String,
    platform_id: String,
    payment: Option<Keys>,
    invoice: Option<Keys>,
    logistics: Option<Keys>,
    urls: Urls,
    b2b_rq_id: String,
    /// Optional injected HTTP client (your own pooling/timeout policy, or a
    /// mock in tests). `None` uses the crate's shared hardened client: no
    /// redirect following, 10s connect / 30s overall timeouts, no
    /// idle-connection pooling. An injected client is used **as-is** — the
    /// hardening is not (and cannot be) applied to it.
    http: Option<reqwest::Client>,
}

impl Ecpay {
    /// Builds a client for `merchant_id` against `env`'s endpoints. The
    /// only construction path: URLs are resolved and (for
    /// [`Env::Custom`]) https-validated here, and no field carries a
    /// silent default. Key pairs are attached afterwards with the
    /// `with_*_keys` setters — see the struct docs.
    pub fn new(merchant_id: impl Into<String>, env: Env) -> Result<Self> {
        let merchant_id = merchant_id.into();
        if merchant_id.is_empty() {
            return Err(Error::Validation(
                "MerchantID must be set — an empty merchant signs nothing ECPay accepts".into(),
            ));
        }
        Ok(Self {
            merchant_id,
            platform_id: String::new(),
            payment: None,
            invoice: None,
            logistics: None,
            urls: env.resolve(),
            b2b_rq_id: String::new(),
            http: None,
        })
    }

    /// Attaches the payment family's keys (AIO 金流 + ECPG 站內付, and the
    /// whole-pair fallback for domestic logistics when no dedicated pair
    /// is set).
    pub fn with_payment_keys(mut self, keys: Keys) -> Self {
        self.payment = Some(keys);
        self
    }

    /// Attaches the B2C/B2B e-invoice family's keys.
    pub fn with_invoice_keys(mut self, keys: Keys) -> Self {
        self.invoice = Some(keys);
        self
    }

    /// Attaches a dedicated logistics pair. Omit it when your logistics
    /// keys equal the payment pair — the fallback then takes the ENTIRE
    /// payment pair (a wrong-pair fallback surfaces as a server MAC
    /// error, not a local one).
    pub fn with_logistics_keys(mut self, keys: Keys) -> Self {
        self.logistics = Some(keys);
        self
    }

    /// B2B envelope `RqHeader.RqID` — a GUID-format request ID you
    /// generate. ECPay does not dedupe on it (proven on stage: one fixed
    /// RqID issued two distinct invoices), but production integrations
    /// should still make it unique per request for their own auditing:
    /// `client.clone().with_b2b_rq_id(new_guid())`. **Required**: every
    /// B2B call is refused locally when this is empty.
    pub fn with_b2b_rq_id(mut self, rq_id: impl Into<String>) -> Self {
        self.b2b_rq_id = rq_id.into();
        self
    }

    /// 平台商 `PlatformID`（AIO 金流的 `AioCheckOutParams::platform_id`
    /// 以外的共用信封層；B2C 發票信封也帶）。
    pub fn with_platform_id(mut self, platform_id: impl Into<String>) -> Self {
        self.platform_id = platform_id.into();
        self
    }

    /// Injects your own HTTP client; see the field docs.
    pub fn with_http(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// The resolved per-family base URLs (from the [`Env`] given to
    /// [`Ecpay::new`]) — for inspection and logging.
    pub fn urls(&self) -> &Urls {
        &self.urls
    }

    /// 特店編號(read-only;每個請求與信封都帶)。Invalid states stay
    /// unrepresentable: there is no mutating route.
    pub fn merchant_id(&self) -> &str {
        &self.merchant_id
    }

    /// Scrubs the signing-key pairs and their presence: after this call
    /// the client refuses every signing/verification request loudly
    /// (`Error::Validation`) instead of holding scrubbed-but-present
    /// pairs. Dropping the client scrubs the bytes the same way (each
    /// [`Keys`] zeroizes on drop); this method is for scrubbing BEFORE a
    /// long-lived drop, e.g. on config rotation.
    ///
    /// ⚠ **Best effort, not a guarantee**: `Ecpay` is `Clone`, so every
    /// clone keeps its own live copy (scrub each clone too), and a
    /// `String` that ever reallocated may leave stale heap copies this
    /// cannot reach. Beyond the pairs, every signing/verification call
    /// builds transient unzeroed buffers that contain key bytes (the
    /// CheckMacValue preimage and its url-encoded copy, AES/base64 work
    /// buffers) — inherent to the string-based protocol and unreachable
    /// from here. Scrub, then drop.
    pub fn zeroize_signing_keys(&mut self) {
        self.payment = None;
        self.invoice = None;
        self.logistics = None;
    }
}

impl std::fmt::Debug for Ecpay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |k: &Option<Keys>| k.as_ref().map(|_| "***");
        f.debug_struct("Ecpay")
            .field("merchant_id", &self.merchant_id)
            .field("platform_id", &self.platform_id)
            .field("payment_keys", &redact(&self.payment))
            .field("invoice_keys", &redact(&self.invoice))
            .field("logistics_keys", &redact(&self.logistics))
            .field("urls", &self.urls)
            .field("b2b_rq_id", &self.b2b_rq_id)
            // The client carries no secrets but also nothing worth dumping.
            .field("http", &self.http.as_ref().map(|_| "client"))
            .finish()
    }
}

impl Ecpay {
    fn family_url<'a>(family: &str, url: &'a Option<BaseUrl>) -> Result<&'a str> {
        url.as_ref().map(BaseUrl::as_str).ok_or_else(|| {
            Error::Validation(format!(
                "the {family} API base URL was never configured — Env::Stage/Production \
                 set every family, Env::Custom needs `{family}`; refusing to guess an \
                 endpoint for signed traffic"
            ))
        })
    }

    /// The Cashier base (`{payment_api_url}{Action}/V5`).
    pub(crate) fn payment_base_url(&self) -> Result<&str> {
        Self::family_url("payment", &self.urls.payment)
    }

    /// The B2CInvoice base.
    pub(crate) fn invoice_base_url(&self) -> Result<&str> {
        Self::family_url("invoice", &self.urls.invoice)
    }

    /// The CreditDetail base.
    pub(crate) fn credit_base_url(&self) -> Result<&str> {
        Self::family_url("CreditDetail (credit)", &self.urls.credit)
    }

    /// The vendor base.
    pub(crate) fn vendor_base_url(&self) -> Result<&str> {
        Self::family_url("vendor", &self.urls.vendor)
    }

    /// The logistics base.
    pub(crate) fn logistics_base_url(&self) -> Result<&str> {
        Self::family_url("logistics", &self.urls.logistics)
    }

    /// 站內付 2.0 token base (`Merchant/*`).
    pub(crate) fn ecpg_base_url(&self) -> Result<&str> {
        Self::family_url("ECPG (ecpg)", &self.urls.ecpg)
    }

    /// 站內付 2.0 query base (`1.0.0/*`).
    pub(crate) fn ecpayment_base_url(&self) -> Result<&str> {
        Self::family_url("ECPG ecpayment", &self.urls.ecpayment)
    }

    /// B2B invoice base.
    pub(crate) fn b2b_base_url(&self) -> Result<&str> {
        Self::family_url("B2B invoice", &self.urls.b2b_invoice)
    }

    fn family_keys<'a>(family: &str, keys: &'a Option<Keys>) -> Result<(&'a str, &'a str)> {
        keys.as_ref().map(|k| (k.key(), k.iv())).ok_or_else(|| {
            Error::Validation(format!(
                "the {family} HashKey/HashIV were never configured — call \
                 with_{}_keys(Keys::new(..)?) on the client; refusing to sign or \
                 MAC-verify with an unconfigured family",
                family.replace(' ', "_")
            ))
        })
    }

    /// Payment (AIO + ECPG) keys.
    pub(crate) fn payment_keys(&self) -> Result<(&str, &str)> {
        Self::family_keys("payment", &self.payment)
    }

    /// Invoice (B2C + B2B) keys.
    pub(crate) fn invoice_keys(&self) -> Result<(&str, &str)> {
        Self::family_keys("invoice", &self.invoice)
    }

    /// Logistics signing keys: the dedicated logistics pair when present,
    /// otherwise the ENTIRE payment pair (whole-pair fallback — never a
    /// key from one pair and an IV from another; a wrong-pair fallback
    /// surfaces as a server MAC error, not a local one).
    pub(crate) fn logistics_keys(&self) -> Result<(&str, &str)> {
        match self.logistics.as_ref().or(self.payment.as_ref()) {
            Some(k) => Ok((k.key(), k.iv())),
            None => Err(Error::Validation(
                "neither the logistics nor the payment HashKey/HashIV is configured — \
                 call with_logistics_keys(..) or with_payment_keys(..); refusing to \
                 sign or MAC-verify with an unconfigured client"
                    .into(),
            )),
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
        let (key, iv) = match self.payment_keys() {
            Ok(pair) => pair,
            Err(_) => return false,
        };
        let got = match params.get("CheckMacValue") {
            Some(v) if !v.is_empty() => v,
            _ => return false,
        };
        // SHA-256 only: EncryptType=0 is retired. A caller-supplied
        // EncryptType field is deliberately ignored here.
        crypto::verify_mac(
            got,
            crypto::str_pairs(params),
            key,
            iv,
            crypto::EncryptType::Sha256,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_all_three_pairs() -> Ecpay {
        Ecpay::new("3002607", Env::Production)
            .unwrap()
            .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs").unwrap())
            .with_invoice_keys(Keys::new("ejCk326UnaZWKisg", "q9jcZX8Ib9LM8wYk").unwrap())
            .with_logistics_keys(Keys::new("5294y06JbISpM5x9", "v77hoKGq4kWxNNIS").unwrap())
    }

    #[test]
    fn zeroize_signing_keys_clears_every_pairs_presence() {
        // The pinned contract of the public scrub API: after it runs, none
        // of the three families' pairs remain configured — the client
        // refuses every signing/verification call loudly instead of
        // holding scrubbed-but-present pairs. (The bytes themselves are
        // zeroized by Keys' ZeroizeOnDrop when the cleared pairs drop.)
        let mut client = client_with_all_three_pairs();
        client.zeroize_signing_keys();
        assert!(client.payment_keys().is_err(), "payment pair must be gone");
        assert!(client.invoice_keys().is_err(), "invoice pair must be gone");
        assert!(
            client.logistics_keys().is_err(),
            "logistics pair must be gone"
        );
    }

    #[test]
    fn debug_redacts_the_signing_secrets() {
        let client = client_with_all_three_pairs();
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
        assert!(dumped.contains("payment_keys: Some(\"***\")"), "{dumped}");
        assert!(dumped.contains("merchant_id: \"3002607\""), "{dumped}");
    }

    #[test]
    fn verify_check_mac_value_is_sha256_only_ignoring_encrypt_type_field() {
        let client = Ecpay::new("3002607", Env::Production)
            .unwrap()
            .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs").unwrap());
        let (key, iv) = client.payment_keys().unwrap();
        // A posted form that carries EncryptType=0: verification must still
        // recompute with SHA-256 (EncryptType=0 is retired) and therefore
        // match the SHA-256 mac over the same fields.
        let mut posted = HashMap::new();
        posted.insert("MerchantID".to_owned(), "3002607".to_owned());
        posted.insert("EncryptType".to_owned(), "0".to_owned());
        let sha = crypto::check_mac_value(&posted, key, iv, crypto::EncryptType::Sha256);
        posted.insert("CheckMacValue".to_owned(), sha);
        assert!(client.verify_check_mac_value(&posted));

        // And an MD5 mac fails verification even when EncryptType=0 claims
        // MD5 — the field is never honored on inbound verification.
        let md5 = crypto::check_mac_value(&posted, key, iv, crypto::EncryptType::Md5);
        posted.insert("CheckMacValue".to_owned(), md5);
        assert!(!client.verify_check_mac_value(&posted));
    }
}
