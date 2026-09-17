//! The transport layer: the AES-JSON invoice envelope (`call_invoice_api`),
//! the form-encoded payment call with the appended CheckMacValue
//! (`call_payment_api`), and the plain form POST/parse helpers the payment-SDK
//! methods (order_search, credit_do_action, …) ride on.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::crypto::{aes_url_encode, decrypt_data, encrypt, query_unescape};
use crate::error::{Error, Result};
use crate::Ecpay;

/// Go `Request` — the outer AES-JSON envelope CallInvoiceAPI sends.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Request {
    #[serde(rename = "PlatformID", default)]
    pub platform_id: String,
    #[serde(rename = "MerchantID", default)]
    pub merchant_id: String,
    #[serde(rename = "RqHeader", default)]
    pub rq_header: RqHeader,
    #[serde(rename = "Data", default)]
    pub data: String,
}

/// Go's anonymous `Request.RqHeader` struct.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RqHeader {
    /// 傳入時間 Number 時間戳，格式為 Unix timestamp
    /// (若時間戳跟綠界接收到時間超過 10 分鐘時，交易會失敗無法進行)
    #[serde(rename = "Timestamp", default)]
    pub timestamp: i64,
    /// 串接版號 string(10)
    #[serde(rename = "Revision", default, skip_serializing_if = "String::is_empty")]
    pub revision: String,
    /// B2B invoice only: 特店請求編號 (GUID format). Omitted from the wire
    /// when empty so the B2C invoice envelope stays byte-identical to the
    /// Go reference port.
    #[serde(rename = "RqID", default, skip_serializing_if = "String::is_empty")]
    pub rq_id: String,
}

/// Go `Response` — PlatformID/MerchantID are `any` on the wire (ECPay 回傳型態
/// 不固定), so they decode into a JSON Value.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Response {
    #[serde(rename = "PlatformID", default)]
    pub platform_id: serde_json::Value,
    #[serde(rename = "MerchantID", default)]
    pub merchant_id: serde_json::Value,
    #[serde(rename = "RqHeader", default)]
    pub rq_header: RqHeaderResponse,
    /// 1 代表傳輸資料(MerchantID, RqHeader, Data)接收成功，其餘均為失敗
    #[serde(rename = "TransCode", default)]
    pub trans_code: i64,
    /// 回傳訊息
    #[serde(rename = "TransMsg", default)]
    pub trans_msg: String,
    /// 此為加密過 JSON 格式的資料
    #[serde(rename = "Data", default)]
    pub data: String,
}

/// Go's anonymous `Response.RqHeader` struct.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RqHeaderResponse {
    #[serde(rename = "Timestamp", default)]
    pub timestamp: i64,
}

impl Ecpay {
    /// Serialize `input` to its exact wire JSON, enforce the Data-level
    /// MerchantID contract, then encrypt. The single serializer behind every
    /// AES-JSON envelope.
    ///
    /// The MerchantID contract: whenever the serialized `Data` carries a
    /// top-level string `MerchantID` (B2C invoice, logistics v2/cross-border,
    /// and the ECPG/B2B Data structs all do), a SET value must equal the
    /// ENVELOPE's `envelope_merchant_id` — ECPay wants the ID in BOTH the
    /// envelope and `Data`, and rejects a mismatch server-side (ECPG names
    /// the parameter: `5000261` / `5100074`, live 2026-09). The check runs
    /// before any bytes go out. An empty value
    /// passes through unchanged here (legacy wire behavior), but the
    /// ECPG/B2B and logistics v2/CrossBorder modules additionally refuse an
    /// empty value at their field-level guards — only the B2C invoice path
    /// still lets an empty Data MerchantID through (whether ECPay accepts it
    /// is service-specific). Inputs without a Data-level MerchantID (key
    /// absent, or not a string) pass through.
    fn encrypt_checked<T: Serialize + ?Sized>(
        &self,
        envelope_merchant_id: &str,
        input: &T,
        key: &[u8],
        iv: &[u8],
    ) -> Result<String> {
        let json = serde_json::to_string(input)?;
        let value: serde_json::Value = serde_json::from_str(&json)?;
        if let Some(mid) = value.get("MerchantID").and_then(serde_json::Value::as_str) {
            if !mid.is_empty() && mid != envelope_merchant_id {
                return Err(Error::Message(format!(
                    "ecpay: Data MerchantID must equal the envelope MerchantID \
                     (got {mid:?}, envelope has {envelope_merchant_id:?}); ECPay rejects a \
                     mismatch server-side"
                )));
            }
        }
        encrypt(aes_url_encode(&json).as_bytes(), key, iv)
    }

    /// Shared by the ECPG (站內付 2.0) and B2B invoice modules: ECPay wants
    /// the MerchantID in BOTH the AES envelope and inside the encrypted
    /// `Data`, and rejects an omitted or mismatched value server-side
    /// (live-probed for ECPG in tests/stage_probes.rs; B2B applies the same
    /// guard untested) — so both modules check before any bytes go out.
    /// `tail` appends
    /// module-specific wording to the error message.
    pub(crate) fn require_data_merchant_id_with(
        &self,
        data_merchant_id: &str,
        tail: &str,
    ) -> Result<()> {
        if data_merchant_id.is_empty() || data_merchant_id != self.merchant_id {
            return Err(Error::Message(format!(
                "ecpay: Data MerchantID must be set and equal the client's MerchantID \
                 (got {data_merchant_id:?}, client has {:?}){tail}",
                self.merchant_id
            )));
        }
        Ok(())
    }
}

/// Shared HTML attribute escaper for every auto-submitting form this crate
/// builds (AIO checkout, logistics map/print/create forms). Escapes
/// `& < > " '` so a `"` in any value cannot break out of the attribute (the
/// official SDK does not escape, which breaks the form and is an injection
/// vector).
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Port of `ExtendFunction.gen_html_post_form`: an auto-submitting HTML form
/// (id `data_set`) that sends the browser to ECPay's page — shared by the AIO
/// checkout form and the logistics forms. Attribute values are HTML-escaped
/// (see [`html_escape`]).
pub(crate) fn render_auto_submit_form(action: &str, pairs: &[(String, String)]) -> String {
    let mut html = format!(
        "<form id=\"data_set\" action=\"{}\" method=\"post\">",
        html_escape(action)
    );
    for (k, v) in pairs {
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\" />",
            html_escape(k),
            html_escape(v)
        ));
    }
    html.push_str(
        "<script type=\"text/javascript\">document.getElementById(\"data_set\").submit();</script>",
    );
    html.push_str("</form>");
    html
}

/// Go `url.Values.Encode()` form body: keys sorted bytewise, each key and
/// value QueryEscape'd, pairs joined by & (Python's `requests.post(data=...)`
/// sends the same pairs in dict order; ECPay accepts either, the sort is
/// for deterministic wire bytes). The one encoder behind every form POST
/// this crate sends.
pub(crate) fn encode_query<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut pairs: Vec<(&str, &str)> = pairs.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&crate::crypto::query_escape(k));
        out.push('=');
        out.push_str(&crate::crypto::query_escape(v));
    }
    out
}

/// Go `url.ParseQuery` into first-value-wins singles: split on '&', reject
/// semicolons, QueryUnescape both halves.
pub(crate) fn parse_query(query: &str) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        if part.contains(';') {
            return Err(Error::SemicolonInQuery);
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        let k = query_unescape(k)?;
        let v = query_unescape(v)?;
        out.entry(k).or_insert(v);
    }
    Ok(out)
}

/// Python `urllib.parse.parse_qsl(text, keep_blank_values=True)` fed through
/// `dict(...)` — the response decoder the official SDK uses: blank values
/// kept (a control name without `=` yields `("k", "")`, verified against
/// CPython), `a=b=c` splits on the first `=`, malformed escapes left literal
/// (parse_qsl is lenient), and duplicate keys resolved last-value-wins
/// (dict insertion overwrites).
pub(crate) fn parse_qsl(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for part in text.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.insert(unquote_plus(k), unquote_plus(v));
    }
    out
}

/// Python `urllib.parse.unquote_plus`: `+` becomes space and %XX decodes to
/// its byte; malformed escapes stay literal (the lenient behavior parse_qsl
/// relies on).
fn unquote_plus(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi * 16 + lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Read at most 1 MiB of the body. A body that EXCEEDS the cap is an error,
/// never a silent truncation: a settlement report cut mid-row is data
/// corruption, and a truncated CheckMacValue would only fail later (or,
/// on the Big5/parse_qsl endpoints, not at all).
///
/// Two guards, because hyper delivers large chunks and the overage can sit
/// INSIDE one chunk (slicing it off would hide it): the declared
/// Content-Length is checked up front, and the bytes hyper actually
/// delivers are counted — the counter is authoritative when Content-Length
/// is absent or lying (chunked encoding).
async fn read_body_limited(resp: &mut reqwest::Response) -> Result<Vec<u8>> {
    const LIMIT: usize = 1 << 20;
    if let Some(len) = resp.content_length() {
        if len > LIMIT as u64 {
            return Err(Error::Message(format!(
                "ecpay: response body exceeds the 1 MiB safety limit ({len} bytes)"
            )));
        }
    }
    let mut delivered = 0usize;
    let mut buf = Vec::new();
    loop {
        match resp.chunk().await? {
            Some(chunk) => {
                delivered += chunk.len();
                if delivered > LIMIT {
                    return Err(Error::Message(
                        "ecpay: response body exceeds the 1 MiB safety limit".into(),
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            None => return Ok(buf),
        }
    }
}

async fn body_string(resp: &mut reqwest::Response) -> Result<String> {
    // Go never validates UTF-8: `string(body)` keeps raw bytes and
    // url.ParseQuery / json.Decoder cope (the JSON side substitutes U+FFFD).
    // A Rust String cannot hold invalid bytes, so lossy-convert to match Go's
    // never-error-on-body semantics.
    let bytes = read_body_limited(resp).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

impl Ecpay {
    /// POST the params as a urlencoded form (Python `requests.post(url,
    /// data=params)` / BasePayment.send_post): plain POST, no envelope,
    /// [`encode_query`] wire bytes. Returns the raw body bytes; the caller
    /// decodes (query string, JSON, or Big5 text).
    pub(crate) async fn post_form(
        &self,
        endpoint: &str,
        params: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let (status, body) = self.post_form_raw(endpoint, params).await?;
        if !(200..300).contains(&status) {
            return Err(Error::PaymentStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(body)
    }

    /// [`Self::post_form`] without the non-2xx gate: the HTTP status and the
    /// raw body, for a caller whose protocol carries its own error shape on
    /// any status (the logistics `0|<message>` rejections arrive on HTTP 500
    /// as well as 200).
    pub(crate) async fn post_form_raw(
        &self,
        endpoint: &str,
        params: &HashMap<String, String>,
    ) -> Result<(u16, Vec<u8>)> {
        let encoded = encode_query(crate::crypto::str_pairs(params));
        let mut resp = self
            .http()
            .post(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = read_body_limited(&mut resp).await?;
        Ok((status, body))
    }

    /// Go `CallPaymentAPI`: POST the form params plus CheckMacValue (keys
    /// sorted like url.Values.Encode) and parse the response as a query
    /// string, first value winning. The `MerchantID` entry is forced to the
    /// client's configured merchant — and the FORCED map is both what is
    /// signed and what is sent, so the signature always covers the wire
    /// bytes. The MAC is [`Self::generate_check_value`]'s (it honors the
    /// params' `EncryptType`); the response is NOT verified — callers who
    /// need a verified query should use [`crate::Ecpay::order_search`] or
    /// [`crate::Ecpay::query_trade_info`].
    pub async fn call_payment_api(
        &self,
        name: &str,
        params: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>> {
        let mut m = params.clone();
        m.insert("MerchantID".to_owned(), self.merchant_id.clone());
        let mac = self.generate_check_value(&m)?;
        m.insert("CheckMacValue".to_owned(), mac);
        let base = self.payment_base_url();
        let endpoint = format!("{base}{name}/V5");
        let encoded = encode_query(crate::crypto::str_pairs(&m));
        let mut resp = self
            .http()
            .post(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .await?;
        let body = body_string(&mut resp).await?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::PaymentStatus { status, body });
        }
        parse_query(&body)
    }

    /// Parses a body as the AES-JSON envelope. `None` unless it is a JSON
    /// object carrying a `TransCode` key: every `Response` field is
    /// serde-defaulted, so without this check any JSON object (a gateway's
    /// 502 page, an empty `{}`) would decode into a meaningless
    /// `TransCode{code:0}` and swallow the real status and body. Presence of
    /// the key is the test, not its value — a literal `"TransCode":0` is a
    /// real envelope (ECPay's 查無資料 answers look like that). A body that
    /// has the key but does not fit `Response` (`"TransCode":"1"`, a
    /// non-string `Data`) is `None` too: it is reported through the same
    /// bounded excerpt rather than serde's type error, which would echo an
    /// attacker-sized string verbatim.
    fn parse_envelope(body: &str) -> Option<Response> {
        let value: serde_json::Value = serde_json::from_str(body).ok()?;
        value.get("TransCode")?;
        crate::crypto::unmarshal_value(value).ok()
    }

    /// Gates on TransCode and decrypts `Data` into the typed output.
    fn decode_aes_response<O: DeserializeOwned>(res: Response, key: &[u8], iv: &[u8]) -> Result<O> {
        if res.trans_code != 1 {
            return Err(Error::TransCode {
                code: res.trans_code,
                msg: res.trans_msg,
            });
        }
        decrypt_data(&res.data, key, iv)
    }

    /// The decode every AES-JSON consumer shares — an API's 2xx body or an
    /// inbound callback POST: require an envelope ([`Self::parse_envelope`]),
    /// gate on TransCode, decrypt `Data`. A non-envelope body is reported
    /// with a bounded, escaped excerpt of its content ([`body_excerpt`])
    /// rather than as `TransCode{code:0}` or a bare JSON parse error that
    /// drops it.
    pub(crate) fn decode_envelope<O: DeserializeOwned>(
        body: &str,
        key: &[u8],
        iv: &[u8],
    ) -> Result<O> {
        let res = Self::parse_envelope(body).ok_or_else(|| {
            Error::Message(format!(
                "ecpay: body is not an AES-JSON envelope: {}",
                body_excerpt(body)
            ))
        })?;
        Self::decode_aes_response(res, key, iv)
    }

    /// [`Self::decode_envelope`] for the attacker-reachable callback
    /// endpoints: identical except that every payload-content-dependent
    /// failure (padding, UTF-8, JSON, URL-escape) collapses into one fixed
    /// message via `decrypt_payload_uniform`, closing the CBC padding oracle.
    /// The non-envelope body error keeps its bounded excerpt — whether the
    /// body parses as an envelope at all depends only on bytes the sender
    /// already knows.
    pub(crate) fn decode_envelope_opaque<O: DeserializeOwned>(
        body: &str,
        key: &[u8],
        iv: &[u8],
    ) -> Result<O> {
        let res = Self::parse_envelope(body).ok_or_else(|| {
            Error::Message(format!(
                "ecpay: body is not an AES-JSON envelope: {}",
                body_excerpt(body)
            ))
        })?;
        if res.trans_code != 1 {
            return Err(Error::TransCode {
                code: res.trans_code,
                msg: res.trans_msg,
            });
        }
        crate::crypto::decrypt_payload_uniform(&res.data, key, iv)
    }

    /// The two v2 browser-flow endpoints (`PrintTradeDocument`,
    /// `RedirectToLogisticsSelection`) answer with a raw **text/html**
    /// auto-submitting form instead of an AES envelope (live-captured
    /// 2026-09: the form POSTs the print record / the AES selection request
    /// to the browser page). Sends the same envelope, returns the raw HTML.
    pub(crate) async fn post_aes_json_raw<I: Serialize>(
        &self,
        endpoint: &str,
        rq_header: serde_json::Value,
        merchant_id: &str,
        input: &I,
        key: &[u8],
        iv: &[u8],
    ) -> Result<String> {
        let data = self.encrypt_checked(merchant_id, input, key, iv)?;
        let envelope = serde_json::json!({
            "MerchantID": merchant_id,
            "RqHeader": rq_header,
            "Data": data,
        });
        let mut resp = self
            .http()
            .post(endpoint)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(envelope.to_string())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = body_string(&mut resp).await?;
        if !(200..300).contains(&status) {
            return Err(Error::InvoiceStatus { status, body });
        }
        Ok(body)
    }

    /// The AES-JSON envelope core for every NON-B2C service (ECPG 站內付,
    /// logistics v2, CrossBorder, B2B invoice): builds
    /// `{MerchantID, RqHeader, Data}` — deliberately without PlatformID, the
    /// shape the official PHP examples wire for these services — encrypts
    /// `input` into `Data` (with [`Self::encrypt_checked`]'s Data-level
    /// MerchantID guard), POSTs, gates on TransCode, decrypts into `O`.
    /// The B2C invoice envelope (`call_invoice_api`) keeps its own Go-port
    /// path because it always sends PlatformID and pins `Revision: "3.0.0"`.
    pub(crate) async fn post_aes_json<I: Serialize, O: DeserializeOwned>(
        &self,
        endpoint: &str,
        rq_header: serde_json::Value,
        merchant_id: &str,
        input: &I,
        key: &[u8],
        iv: &[u8],
    ) -> Result<O> {
        let data = self.encrypt_checked(merchant_id, input, key, iv)?;
        let envelope = serde_json::json!({
            "MerchantID": merchant_id,
            "RqHeader": rq_header,
            "Data": data,
        });
        let mut resp = self
            .http()
            .post(endpoint)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(envelope.to_string())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = body_string(&mut resp).await?;
        if !(200..300).contains(&status) {
            // Server-truth (logistics v2, captured live 2026-09): some
            // business errors answer HTTP 500 with a VALID envelope whose
            // Data decrypts to the RtnCode/RtnMsg. Prefer that over a bare
            // HTTP error — but only when the body really is an envelope
            // (parse_envelope's TransCode-key gate), so a 403/502 gateway
            // body keeps its real status and content.
            match Self::parse_envelope(&body) {
                Some(res) => return Self::decode_aes_response(res, key, iv),
                None => return Err(Error::InvoiceStatus { status, body }),
            }
        }
        Self::decode_envelope(&body, key, iv)
    }

    /// Go `CallInvoiceAPI`: encrypt the input into the AES-JSON envelope
    /// (with `encrypt_checked`'s Data-level MerchantID guard), POST
    /// it, gate on TransCode, and decrypt Data into the typed output.
    pub async fn call_invoice_api<I: Serialize, O: DeserializeOwned>(
        &self,
        name: &str,
        input: &I,
    ) -> Result<O> {
        let base = self.invoice_base_url();
        let endpoint = format!("{base}{name}");
        let (key, iv) = self.invoice_keys();
        let data = self.encrypt_checked(&self.merchant_id, input, key, iv)?;
        let req = Request {
            platform_id: self.platform_id.clone(),
            merchant_id: self.merchant_id.clone(),
            data,
            rq_header: RqHeader {
                revision: "3.0.0".to_owned(),
                timestamp: crate::client::unix_now(),
                rq_id: String::new(),
            },
        };
        let j = serde_json::to_string(&req)?;
        let mut resp = self
            .http()
            .post(endpoint)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(j)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            // Go reads the body for the message; a failed read is wrapped.
            return Err(match body_string(&mut resp).await {
                Ok(body) => Error::InvoiceStatus { status, body },
                Err(source) => Error::Message(format!(
                    "ecpay invoice API error: status={status} (body read failed: {source})"
                )),
            });
        }
        let body = body_string(&mut resp).await?;
        Self::decode_envelope(&body, key, iv)
    }

    /// The HTTP client requests are sent with: an injected
    /// [`Ecpay::http`] client as-is, or the shared hardened default below.
    pub(crate) fn http(&self) -> &reqwest::Client {
        match &self.http {
            Some(client) => client,
            None => shared_http_client(),
        }
    }

    /// Recompute the CheckMacValue for the params of an outbound request with
    /// the client's payment HashKey/HashIV, honoring the params' EncryptType
    /// field (1 = SHA-256, 0 = MD5; the Python SDK's default). The
    /// MerchantID entry is forced to the client's configured merchant, exactly
    /// like the official SDK's `generate_check_value`.
    pub fn generate_check_value(&self, params: &HashMap<String, String>) -> Result<String> {
        let encrypt_type =
            crate::crypto::parse_encrypt_type(params.get("EncryptType").map(String::as_str));
        let pairs = crate::crypto::str_pairs(params)
            .filter(|(k, _)| *k != "MerchantID")
            .chain(std::iter::once(("MerchantID", self.merchant_id.as_str())));
        crate::crypto::check_mac_value_pairs(pairs, &self.hash_key, &self.hash_iv, encrypt_type)
    }
}

/// How much of a body an error message quotes.
pub(crate) const BODY_EXCERPT_CHARS: usize = 512;

/// A bounded, escaped excerpt of a body for error messages: at most
/// [`BODY_EXCERPT_CHARS`] chars, `Debug`-quoted so newlines and control
/// characters cannot reach a log line raw. The callback decoders feed
/// attacker-controlled POST bodies (a public ServerReplyURL/ReturnURL) into
/// this, so the echo must never be unbounded or verbatim. The non-envelope
/// status errors (`Error::PaymentStatus`/`InvoiceStatus`) instead render
/// their bodies through [`truncate_for_display`] — verbatim-but-bounded,
/// keeping the Go-parity `body=%s` shape for normal server responses.
pub(crate) fn body_excerpt(body: &str) -> String {
    let mut chars = body.chars();
    let head: String = chars.by_ref().take(BODY_EXCERPT_CHARS).collect();
    if chars.next().is_some() {
        format!("{head:?}… ({} bytes total)", body.len())
    } else {
        format!("{head:?}")
    }
}

/// A bounded rendering of a response body for error `Display`: verbatim up
/// to [`BODY_EXCERPT_CHARS`] chars, then a truncation notice with the total
/// size. Unlike [`body_excerpt`] it does NOT escape control characters —
/// keeping the Go-parity `body=%s` shape for normal server responses (these
/// bodies arrive over the merchant's own TLS connection, not a public
/// callback endpoint). The `PaymentStatus`/`InvoiceStatus` fields keep the
/// full body for programmatic access; only the rendered message is bounded,
/// so a hostile or misbehaving endpoint cannot flood a log line with
/// megabytes of HTML.
pub(crate) fn truncate_for_display(body: &str) -> String {
    let mut chars = body.chars();
    let head: String = chars.by_ref().take(BODY_EXCERPT_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}… (truncated; {} bytes total)", body.len())
    } else {
        head
    }
}

/// Go `int(time.Now().Unix())`.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The shared fallback HTTP client, used when [`Ecpay::http`] is not set.
/// Hardened for payment traffic: no redirect following (a 30x on a signed
/// API POST is either misconfiguration or an attempt to replay the payload
/// elsewhere — ECPay's API endpoints answer directly, never redirect), a
/// 10s connect timeout, and a 30s overall timeout (ECPay's stage endpoints
/// have been observed to hang).
///
/// `pool_max_idle_per_host(0)`: this client is a process-wide `OnceLock`,
/// but every `#[tokio::test]` spins up and tears down its own Tokio
/// runtime. A default reqwest client keeps idle keep-alive connections (and
/// the hyper task driving them) alive across calls; if that task was
/// spawned on one test's runtime and a later test — on a different runtime —
/// reuses the pooled connection, the driving task is already gone and the
/// request fails with `hyper::Error(SendRequest, ... DispatchGone,
/// "runtime dropped the dispatch task")`. Confirmed live (2026-09) once
/// `tests/sandbox.rs` grew past ~5 concurrently-running live tests, at
/// which point the race went from theoretical to reliably reproducible.
/// Disabling idle-connection reuse trades a little latency (one fresh
/// connection per call instead of reuse) for eliminating that whole class
/// of failure — an acceptable trade for a payment/invoice SDK's low-QPS,
/// call-then-wait usage pattern. Callers that need pooling inject their own
/// client via [`Ecpay::http`].
fn shared_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(0)
            .build()
            .expect("ecpay http client")
    })
}

#[cfg(test)]
mod tests {
    use super::render_auto_submit_form;

    #[test]
    fn auto_submit_form_is_byte_identical_to_the_former_inline_copies() {
        // Pins the exact shape shared by the AIO checkout and logistics
        // forms (formerly two copy-pasted html_form methods), including
        // attribute escaping and the auto-submit script tag.
        let html = render_auto_submit_form(
            "https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5",
            &[
                ("MerchantID".to_owned(), "3002607".to_owned()),
                ("TradeDesc".to_owned(), "a\"b<c>&'d".to_owned()),
            ],
        );
        assert_eq!(
            html,
            "<form id=\"data_set\" action=\"https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5\" \
method=\"post\"><input type=\"hidden\" name=\"MerchantID\" value=\"3002607\" />\
<input type=\"hidden\" name=\"TradeDesc\" value=\"a&quot;b&lt;c&gt;&amp;&#39;d\" />\
<script type=\"text/javascript\">document.getElementById(\"data_set\").submit();</script>\
</form>"
        );
    }

    /// The one form encoder: Go `url.Values.Encode` order (bytewise key
    /// sort, so uppercase before lowercase) and QueryEscape bytes (space is
    /// `+`, `~` literal, everything else uppercase %XX per UTF-8 byte) for
    /// keys and values alike.
    #[test]
    fn encode_query_sorts_bytewise_and_query_escapes_keys_and_values() {
        use super::encode_query;
        let pairs = [
            ("b", "2"),
            ("A", "1 ~"),
            ("a", "\u{4e2d}"),
            ("C", "x&y=z"),
            ("k y", "v"),
        ];
        assert_eq!(
            encode_query(pairs),
            "A=1+~&C=x%26y%3Dz&a=%E4%B8%AD&b=2&k+y=v"
        );
        assert_eq!(encode_query(std::iter::empty()), "");
    }

    #[test]
    fn body_excerpt_is_bounded_and_escaped() {
        use super::{body_excerpt, BODY_EXCERPT_CHARS};
        assert_eq!(body_excerpt("{}"), "\"{}\"");
        // Newlines and quotes are escaped, so a log line cannot be forged.
        assert_eq!(body_excerpt("a\n\"b"), "\"a\\n\\\"b\"");
        let long = "x".repeat(BODY_EXCERPT_CHARS + 1);
        let out = body_excerpt(&long);
        assert!(out.ends_with("… (513 bytes total)"), "{out}");
        assert!(out.len() < BODY_EXCERPT_CHARS + 64, "{}", out.len());
        // Exactly the bound is quoted whole.
        assert!(!body_excerpt(&"y".repeat(BODY_EXCERPT_CHARS)).contains('…'));
        // Multi-byte chars are never split.
        let cjk = "中".repeat(BODY_EXCERPT_CHARS + 5);
        assert!(body_excerpt(&cjk).contains("… (1551 bytes total)"));
    }

    #[test]
    fn truncate_for_display_is_verbatim_within_the_bound() {
        use super::{truncate_for_display, BODY_EXCERPT_CHARS};
        assert_eq!(truncate_for_display("upstream boom"), "upstream boom");
        // Exactly the bound renders whole.
        assert_eq!(
            truncate_for_display(&"z".repeat(BODY_EXCERPT_CHARS)),
            "z".repeat(BODY_EXCERPT_CHARS)
        );
        // Over it: the head plus a notice carrying the total byte count.
        let out = truncate_for_display(&"x".repeat(BODY_EXCERPT_CHARS + 1));
        assert!(
            out.starts_with(&"x".repeat(BODY_EXCERPT_CHARS))
                && out.ends_with("… (truncated; 513 bytes total)"),
            "{out}"
        );
        // Multi-byte chars are never split mid-char.
        let cjk = "中".repeat(BODY_EXCERPT_CHARS + 5);
        assert!(truncate_for_display(&cjk).ends_with("… (truncated; 1551 bytes total)"));
    }
}
