//! Error types. The transport/crypto variants mirror the reference Go port
//! (`api_error.go` plus the ad-hoc `fmt.Errorf` errors); the payment-SDK
//! variants cover the validations and response checks the official Python SDK
//! raises as plain `Exception`s.

use std::fmt;

/// The result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// ECPay business-level failure: the HTTP request and response decoding
/// succeeded, but the response carried a non-success RtnCode (ECPay uses
/// RtnCode == 1 for success).
///
/// Command calls — the B2C issue/void/notify/delay/allowance family
/// (`issue`, `void_with_reissue`, `invalid`, `invoice_notify`, `delay_issue`,
/// `cancel_delay_issue`, `allowance`, `allowance_invalid`,
/// `allowance_by_collegiate`, `allowance_invalid_by_collegiate`) and the B2B
/// issue — return it so callers can distinguish a genuine rejection from a
/// transport/decode error via `matches!(err, Error::Api(_))`. Query calls
/// such as GetIssue, where a non-1 RtnCode is a normal "not found" result, do
/// NOT return it — the caller inspects RtnCode directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: i64,
    pub msg: String,
}

impl fmt::Display for ApiError {
    /// Go: `fmt.Sprintf("ecpay: RtnCode=%d, RtnMsg=%q", e.Code, e.Msg)`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ecpay: RtnCode={}, RtnMsg={:?}", self.code, self.msg)
    }
}

impl std::error::Error for ApiError {}

/// The ECPay service family an [`Error::HttpStatus`] came from — the label
/// its `Display` shows. Deliberately closed and exhaustive over the
/// service families this crate talks to (a new family is a new module and
/// a new variant either way — no `Other` passthrough, matching
/// [`crate::EncryptType`]'s closedness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// AIO/Cashier 金流 APIs（`call_payment_api`、`order_search`、
    /// `credit_do_action`、餘額下載…）。
    Payment,
    /// B2C 電子發票（`call_invoice_api` 的 Go-parity 路徑）。
    Invoice,
    /// 國內 / 全方位 v2 / 跨境物流（CMV-MD5 form 與 AES-JSON 皆此標籤）。
    Logistics,
    /// 站內付 2.0（ECPG）的兩個網域。
    Ecpg,
    /// B2B 電子發票。
    B2bInvoice,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Service::Payment => "payment",
            Service::Invoice => "invoice",
            Service::Logistics => "logistics",
            Service::Ecpg => "ecpg",
            Service::B2bInvoice => "b2b invoice",
        })
    }
}

/// Everything this crate can return as `error`. `#[non_exhaustive]`: new
/// variants may be added in any minor release.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A non-success RtnCode on a command call (Go `*APIError`).
    Api(ApiError),
    /// Parameter validation failure raised before anything is sent — the
    /// AIO checkout's field checks ([`crate::payment::AioCheckOutParams`]),
    /// the per-family request guards (logistics, ECPG/B2B…), and the
    /// https-only base-URL rule (`http` is allowed only for loopback
    /// hosts). The Python SDK raises these as `Exception(message)`.
    Validation(String),
    /// A response CheckMacValue that does not match the recomputed one
    /// (`order_search` verifies it; the Python SDK raises
    /// `"CheckMacValue is error!"`).
    CheckMacValueMismatch,
    /// An HTTP-level failure (non-2xx status) of one ECPay service's
    /// endpoint. `Display` renders Go's `fmt.Errorf` shape with the service
    /// named — `ecpay {service} API error: status=%d body=%s` — printable
    /// body text verbatim up to 512 chars (control characters are escaped
    /// in the rendering, so a hostile body cannot forge log lines), then a
    /// truncation notice with the total
    /// size (the private `crate::client::truncate_for_display`); the field
    /// itself keeps the full body. A non-2xx body larger than the transport's
    /// 1 MiB cap surfaces as the body-cap [`Error::Message`] instead (the
    /// body cannot be kept).
    HttpStatus {
        service: Service,
        status: u16,
        body: String,
    },
    /// The AES-JSON envelope's TransCode gate failed: the envelope arrived
    /// but TransCode != 1, so `Data` was never sent/decrypted (renamed from
    /// `Transport` in 0.3; Go's message called this a "transport error").
    /// `msg` is the server's answer, and its content depends on the path:
    /// verbatim on the API paths (the server's own TLS response), but a
    /// bounded, Debug-escaped excerpt via the callback decoders
    /// ([`crate::Ecpay::decrypt_ecpg_callback`],
    /// [`crate::Ecpay::decrypt_logistics_callback`],
    /// [`crate::Ecpay::decrypt_temp_trade_established`]) — on a public
    /// ReturnURL the msg is attacker bytes and must never reach a log line
    /// unbounded or raw (see `crate::crypto`). Independently of the path,
    /// `Display` renders `msg` through the shared `truncate_for_display`
    /// (control characters escaped, 512-char bound) — the same
    /// defense-in-depth `HttpStatus` applies to response bodies. Note
    /// `msg.is_empty()` is
    /// never a meaningful test on the callback path (an empty TransMsg
    /// arrives as `""`, Debug-quoted).
    TransCode {
        code: i64,
        msg: String,
    },
    Http(reqwest::Error),
    Base64(base64::DecodeError),
    Json(serde_json::Error),
    /// Go: `crypto/aes: invalid key size %d` (only 16/24/32 are valid).
    AesKeySize(usize),
    /// Go: `invalid IV length: %d (must be %d)` — surfaces a misconfigured
    /// HashIV as an error instead of a panic.
    InvalidIvLength {
        got: usize,
        want: usize,
    },
    /// Go: `invalid ciphertext length: %d`.
    InvalidCiphertextLength(usize),
    /// Go: `empty ciphertext`.
    ///
    /// ⚠ **Never produced by this crate**: `decrypt` rejects an empty
    /// ciphertext as [`Error::InvalidCiphertextLength`]`(0)` — and always
    /// has (the gate runs before the old unpad path that carried this
    /// error, and that hand-rolled path is gone entirely since the cbc
    /// crate took over). Kept for source compatibility until the next
    /// breaking release; match [`Error::InvalidCiphertextLength`] instead.
    ///
    /// 這個 compile_fail 釘住 deprecation 本身：屬性若被移除而變體仍無
    /// 生產者，此測試會編譯成功 = 失敗（與 [`crate::Ecpay::return_url`]
    /// 等三個 deprecated 欄位的同一套釘法）。
    ///
    /// ```compile_fail
    /// # use ecpay::Error;
    /// #[deny(deprecated)]
    /// fn empty_ciphertext_is_never_produced() {
    ///     let _ = Error::EmptyCiphertext;
    /// }
    /// # fn main() { empty_ciphertext_is_never_produced() }
    /// ```
    #[deprecated(
        since = "0.5.0",
        note = "never produced by this crate; decrypt rejects an empty ciphertext as Error::InvalidCiphertextLength(0) — match that variant instead"
    )]
    EmptyCiphertext,
    /// Invalid PKCS7 padding. One opaque variant for every padding failure:
    /// the value and shape of the bad padding is **not** reported, because
    /// these errors surface on attacker-reachable callback endpoints and a
    /// distinguishable padding failure would give a CBC padding oracle
    /// (see `crate::crypto`).
    Padding,
    /// Go: `url.EscapeError` — `invalid URL escape "%zz"`.
    UrlEscape(String),
    /// Go: `invalid semicolon separator in query` (url.ParseQuery).
    SemicolonInQuery,
    /// Unsupported CheckMacValue EncryptType (only 0 = MD5 and 1 = SHA-256
    /// exist; anything else is a caller bug).
    UnsupportedEncryptType(i64),
    /// Ad-hoc messages: body-read failures, non-UTF-8 payloads, and a body
    /// that is not an AES-JSON envelope (no `TransCode` key, or one whose
    /// values do not fit the envelope) on every AES-JSON consumer — the B2C
    /// invoice API, the AES-JSON APIs (logistics v2 / ECPG / B2B) and the
    /// callback decoders (`"ecpay: body is not an AES-JSON envelope:
    /// <bounded, escaped excerpt>"`).
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Api(e) => write!(f, "{e}"),
            Error::Validation(m) => write!(f, "ecpay: {m}"),
            Error::CheckMacValueMismatch => write!(f, "ecpay: CheckMacValue is error!"),
            Error::HttpStatus {
                service,
                status,
                body,
            } => write!(
                f,
                "ecpay {service} API error: status={status} body={}",
                crate::client::truncate_for_display(body)
            ),
            Error::TransCode { code, msg } => {
                write!(
                    f,
                    "ecpay TransCode error: code={code} msg={}",
                    crate::client::truncate_for_display(msg)
                )
            }
            Error::Http(e) => write!(f, "{e}"),
            Error::Base64(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "{e}"),
            Error::AesKeySize(n) => write!(f, "crypto/aes: invalid key size {n}"),
            Error::InvalidIvLength { got, want } => {
                write!(f, "invalid IV length: {got} (must be {want})")
            }
            Error::InvalidCiphertextLength(n) => write!(f, "invalid ciphertext length: {n}"),
            // The variant is deprecated (never produced); the arm stays for
            // as long as the variant does.
            #[allow(deprecated)]
            Error::EmptyCiphertext => write!(f, "empty ciphertext"),
            Error::Padding => write!(f, "invalid PKCS7 padding"),
            Error::UrlEscape(esc) => write!(f, "invalid URL escape {esc:?}"),
            Error::SemicolonInQuery => write!(f, "invalid semicolon separator in query"),
            Error::UnsupportedEncryptType(n) => write!(f, "unsupported EncryptType: {n}"),
            Error::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Http(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Base64(e) => Some(e),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::Api(e)
    }
}

/// Go's `apiError` helper: the single source of truth for the command-call
/// contract — returns [`Error::Api`] for a non-success RtnCode, Ok on 1.
pub(crate) fn api_error(rtn_code: i64, rtn_msg: &str) -> Result<()> {
    if rtn_code != 1 {
        return Err(Error::Api(ApiError {
            code: rtn_code,
            msg: rtn_msg.to_owned(),
        }));
    }
    Ok(())
}
