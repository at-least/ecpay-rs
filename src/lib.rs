//! Rust port of ECPay's (綠界科技) official All-in-One payment SDK
//! ([ECPayAIO_Python]), extended with the B2C e-invoice (電子發票) AES-JSON
//! APIs from the reference Go SDK port.
//!
//! The CheckMacValue signing, AES envelope, and every wire field name are
//! pinned against ECPay's official test vectors; see the README for the
//! three documented deviations from the Python SDK's literal behavior.
//!
//! [ECPayAIO_Python]: https://github.com/ECPay/ECPayAIO_Python
//!
//! # Example: build an All-in-One checkout form
//!
//! ```no_run
//! use ecpay::payment::{AioCheckOutParams, ChoosePayment};
//! use ecpay::Ecpay;
//!
//! let client = Ecpay {
//!     merchant_id: "2000132".into(),
//!     hash_key: "5294y06JbISpM5x9".into(),
//!     hash_iv: "v77hoKGq4kWxNNIS".into(),
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

pub use crypto::{
    check_mac_value, decrypt, decrypt_data, encrypt, encrypt_data, hash_mac, unmarshal, url_encode,
};
pub use ecpg::{
    AtmInfo, BarcodeInfo, CardInfo, ConsumerInfo, CreateBindCardInput, CreatePaymentInput,
    CreatePaymentWithCardIdInput, CvsInfo, DeleteMemberBindCardInput, EcpgDoActionInput,
    EcpgPeriodActionInput, EcpgTradeRefInput, GetMemberBindCardInput, GetTokenbyBindingCardInput,
    GetTokenbyTradeInput, GetTokenbyTradeOutput, GetTokenbyUserInput, OrderInfo,
    QueryTradeMediaInput, UnionPayInfo,
};
pub use error::{ApiError, Error, Result};
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
    SearchSingleTransactionParams,
};

pub const PAYMENT_API_URL_PRODUCTION: &str = "https://payment.ecpay.com.tw/Cashier/";
pub const PAYMENT_API_URL_STAGE: &str = "https://payment-stage.ecpay.com.tw/Cashier/";

pub const INVOICE_API_URL_PRODUCTION: &str = "https://einvoice.ecpay.com.tw/B2CInvoice/";
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

/// The vendor (特店後台) endpoints (download_merchant_balance). Production
/// base, verbatim from the official SDK's hardcoded URL.
pub const VENDOR_API_URL_PRODUCTION: &str = "https://vendor.ecpay.com.tw/PaymentMedia/";

/// The configured client (Go `type Ecpay struct`; the official Python SDK's
/// `ECPayPaymentSdk(MerchantID, HashKey, HashIV)` constructor). The zero
/// value is valid: empty API URLs fall back to the production endpoints.
///
/// `Debug` is hand-written and redacts the signing secrets (`hash_key`,
/// `hash_iv`, `invoice_hash_key`, `invoice_hash_iv`) so a stray
/// `{:?}` on the client never logs them.
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
    /// 特店自訂編號
    pub relate_number: String,
    pub return_url: String,
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
    /// it unique per request for their own auditing.
    pub b2b_rq_id: String,
    /// Optional injected HTTP client (your own pooling/timeout policy, or a
    /// mock in tests). `None` (the default) uses the crate's shared hardened
    /// client: no redirect following, 10s connect / 30s overall timeouts, no
    /// idle-connection pooling. An injected client is used **as-is** — the
    /// hardening is not (and cannot be) applied to it.
    pub http: Option<reqwest::Client>,
}

impl std::fmt::Debug for Ecpay {
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
    pub(crate) fn logistics_keys(&self) -> (&[u8], &[u8]) {
        let key = if self.logistics_hash_key.is_empty() {
            self.hash_key.as_bytes()
        } else {
            self.logistics_hash_key.as_bytes()
        };
        let iv = if self.logistics_hash_iv.is_empty() {
            self.hash_iv.as_bytes()
        } else {
            self.logistics_hash_iv.as_bytes()
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
    pub fn verify_check_mac_value(&self, params: &HashMap<String, String>) -> bool {
        let got = match params.get("CheckMacValue") {
            Some(v) if !v.is_empty() => v,
            _ => return false,
        };
        // SHA-256 only: EncryptType=0 is retired. A caller-supplied
        // EncryptType field is deliberately ignored here.
        crypto::verify_mac(got, params, &self.hash_key, &self.hash_iv, 1)
            .expect("SHA-256 is always supported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let sha = crypto::check_mac_value(&posted, &client.hash_key, &client.hash_iv, 1).unwrap();
        posted.insert("CheckMacValue".to_owned(), sha);
        assert!(client.verify_check_mac_value(&posted));

        // And an MD5 mac fails verification even when EncryptType=0 claims
        // MD5 — the field is never honored on inbound verification.
        let md5 = crypto::check_mac_value(&posted, &client.hash_key, &client.hash_iv, 0).unwrap();
        posted.insert("CheckMacValue".to_owned(), md5);
        assert!(!client.verify_check_mac_value(&posted));
    }
}
