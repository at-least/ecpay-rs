//! Rust port of ECPay's (綠界科技) official All-in-One payment SDK
//! ([ECPayAIO_Python]), extended with the B2C e-invoice (電子發票) AES-JSON
//! APIs from the reference Go SDK port.
//!
//! The CheckMacValue signing, AES envelope, and every wire field name are
//! pinned against ECPay's official test vectors; see the README for the two
//! documented deviations from the Python SDK's literal behavior (both are
//! cases where the Python SDK disagrees with ECPay's own server).
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
pub mod error;
pub mod invoice;
pub mod payment;

pub use client::{Request, Response, RqHeader, RqHeaderResponse};
pub use crypto::{
    check_mac_value, decrypt, decrypt_data, encrypt, encrypt_data, hash_mac, unmarshal, url_encode,
};
pub use error::{ApiError, Error, Result};
pub use invoice::{
    CheckBarcodeInput, CheckBarcodeOutput, GetCompanyNameByTaxIDInput, GetCompanyNameByTaxIDOutput,
    GetGovInvoiceWordSettingInput, GetGovInvoiceWordSettingOutput, GetInvoiceWordSettingInput,
    GetInvoiceWordSettingOutput, GetIssueInput, GetIssueOutput, GovInvoiceInfo, InvalidInput,
    InvalidOutput, InvoiceInfo, InvoiceNotifyInput, InvoiceNotifyOutput, IssueInput, IssueOutput,
    Item, VoidWithIssueInput, VoidWithIssueOutput,
};
pub use payment::{
    AioCheckOut, AioCheckOutParams, ChoosePayment, CreditCardPeriodActionParams,
    CreditDoActionParams, DownloadDisbursementBalanceParams, DownloadMerchantBalanceParams,
    OrderSearchParams, OrderSearchPeriodParams, QueryTradeInfoOutput,
    SearchSingleTransactionParams,
};

/// Go: `const DateTimeFormat = "2006/01/02 15:04:05"` (the Go reference layout
/// is kept verbatim; expand as "%Y/%m/%d %H:%M:%S" if ever formatted).
pub const DATE_TIME_FORMAT: &str = "2006/01/02 15:04:05";

pub const PAYMENT_API_URL_PRODUCTION: &str = "https://payment.ecpay.com.tw/Cashier/";
pub const PAYMENT_API_URL_STAGE: &str = "https://payment-stage.ecpay.com.tw/Cashier/";

pub const INVOICE_API_URL_PRODUCTION: &str = "https://einvoice.ecpay.com.tw/B2CInvoice/";
pub const INVOICE_API_URL_STAGE: &str = "https://einvoice-stage.ecpay.com.tw/B2CInvoice/";

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
#[derive(Debug, Clone, Default)]
pub struct Ecpay {
    pub platform_id: String,
    pub merchant_id: String,
    pub hash_key: String,
    pub hash_iv: String,
    pub payment_api_url: String,
    pub invoice_api_url: String,
    pub invoice_hash_key: Vec<u8>,
    pub invoice_hash_iv: Vec<u8>,
    /// 特店自訂編號
    pub relate_number: String,
    pub return_url: String,
    pub payment_info_url: String,
    /// Base URL for the CreditDetail endpoints; empty = production.
    pub credit_api_url: String,
    /// Base URL for the vendor (特店後台) endpoints; empty = production.
    pub vendor_api_url: String,
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
        let rest: HashMap<String, String> = params
            .iter()
            .filter(|(k, _)| *k != "CheckMacValue")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        // check_mac_value returns uppercase hex; ECPay sends uppercase too.
        // Upper-case the inbound value defensively before the constant-time
        // compare.
        let want = hash_mac(&rest, &self.hash_key, &self.hash_iv);
        crypto::constant_time_eq(got.to_uppercase().as_bytes(), want.as_bytes())
    }
}
