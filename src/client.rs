//! The transport layer: the AES-JSON invoice envelope (`call_invoice_api`),
//! the form-encoded payment call with the appended CheckMacValue
//! (`call_payment_api`), and the plain form POST/parse helpers the payment-SDK
//! methods (order_search, credit_do_action, …) ride on.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::crypto::{check_mac_value, decrypt_data, encrypt_data, http_client, query_unescape};
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

/// Go `url.Values.Encode()`: keys sorted alphabetically, each key and value
/// QueryEscape'd, pairs joined by &.
pub(crate) fn encode_query(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
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

/// POST the params as a urlencoded form (Python `requests.post(url,
/// data=params)`): keys sorted for deterministic wire bytes, values
/// QueryEscape'd. Returns the raw body bytes for the Big5 endpoints.
pub(crate) async fn post_form(endpoint: &str, params: &HashMap<String, String>) -> Result<Vec<u8>> {
    let mut pairs: Vec<(String, String)> =
        params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let encoded = pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                crate::crypto::query_escape(k),
                crate::crypto::query_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let resp = http_client()
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(encoded)
        .send()
        .await?;
    let status = resp.status().as_u16();
    let mut resp = resp;
    let body = read_body_limited(&mut resp).await?;
    if !(200..300).contains(&status) {
        return Err(Error::PaymentStatus {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    Ok(body)
}

impl Ecpay {
    /// Go `CallPaymentAPI`: POST the form params plus CheckMacValue (keys
    /// sorted like url.Values.Encode) and parse the response as a query
    /// string, first value winning.
    pub async fn call_payment_api(
        &self,
        name: &str,
        params: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>> {
        let base = self.payment_base_url();
        let endpoint = format!("{base}{name}/V5");
        let mac = crate::crypto::hash_mac(params, &self.hash_key, &self.hash_iv);
        let mut pairs: Vec<(String, String)> =
            params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        pairs.push(("CheckMacValue".to_owned(), mac));
        let encoded = encode_query(&pairs);
        let mut resp = http_client()
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

    /// Parses an AES-JSON response envelope. `None` when the body isn't an
    /// envelope at all (e.g. an HTML error page).
    fn parse_envelope(body: &str) -> Option<Response> {
        crate::crypto::unmarshal(body).ok()
    }

    /// Gates on TransCode and decrypts `Data` into the typed output.
    fn decode_aes_response<O: DeserializeOwned>(res: Response, key: &[u8], iv: &[u8]) -> Result<O> {
        if res.trans_code != 1 {
            return Err(Error::Transport {
                code: res.trans_code,
                msg: res.trans_msg,
            });
        }
        decrypt_data(&res.data, key, iv)
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
        let data = encrypt_data(input, key, iv)?;
        let envelope = serde_json::json!({
            "MerchantID": merchant_id,
            "RqHeader": rq_header,
            "Data": data,
        });
        let mut resp = http_client()
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
    /// `input` into `Data`, POSTs, gates on TransCode, decrypts into `O`.
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
        let data = encrypt_data(input, key, iv)?;
        let envelope = serde_json::json!({
            "MerchantID": merchant_id,
            "RqHeader": rq_header,
            "Data": data,
        });
        let mut resp = http_client()
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
            // HTTP error — but only when the body really carries a TransCode
            // gate: every Response field is serde-defaulted, so any JSON
            // object (a 403/502 gateway body, for example) would otherwise
            // decode into a meaningless Transport{code:0} and swallow the
            // real status and body.
            match Self::parse_envelope(&body).filter(|res| res.trans_code != 0) {
                Some(res) => return Self::decode_aes_response(res, key, iv),
                None => return Err(Error::InvoiceStatus { status, body }),
            }
        }
        // Same gate on the happy path: a 2xx JSON body without a TransCode
        // field is not an envelope (serde would default one into existence)
        // and deserves the explicit error, not Transport{code:0}.
        let res = Self::parse_envelope(&body)
            .filter(|res| res.trans_code != 0)
            .ok_or_else(|| {
                Error::Message(format!(
                    "ecpay: response is not an AES-JSON envelope: {body}"
                ))
            })?;
        Self::decode_aes_response(res, key, iv)
    }

    /// Go `CallInvoiceAPI`: encrypt the input into the AES-JSON envelope, POST
    /// it, gate on TransCode, and decrypt Data into the typed output.
    pub async fn call_invoice_api<I: Serialize, O: DeserializeOwned>(
        &self,
        name: &str,
        input: &I,
    ) -> Result<O> {
        let base = self.invoice_base_url();
        let endpoint = format!("{base}{name}");
        let data = encrypt_data(input, &self.invoice_hash_key, &self.invoice_hash_iv)?;
        let req = Request {
            platform_id: self.platform_id.clone(),
            merchant_id: self.merchant_id.clone(),
            data,
            rq_header: RqHeader {
                revision: "3.0.0".to_owned(),
                timestamp: crate::crypto::unix_now(),
                rq_id: String::new(),
            },
        };
        let j = serde_json::to_string(&req)?;
        let mut resp = http_client()
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
        let res: Response = crate::crypto::unmarshal(&body)?;
        if res.trans_code != 1 {
            return Err(Error::Transport {
                code: res.trans_code,
                msg: res.trans_msg,
            });
        }
        decrypt_data(&res.data, &self.invoice_hash_key, &self.invoice_hash_iv)
    }

    /// The Python-flavored payment form call (BasePayment.send_post): plain
    /// POST, no envelope, response decoded by the caller (query string, JSON,
    /// or Big5 text). `endpoint` is used verbatim.
    pub(crate) async fn send_post_form(
        &self,
        endpoint: &str,
        params: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        post_form(endpoint, params).await
    }

    /// Recompute the CheckMacValue for the params of an outbound request with
    /// the client's payment HashKey/HashIV, honoring the params' EncryptType
    /// field (1 = SHA-256, 0 = MD5; the Python SDK's default). The
    /// MerchantID entry is forced to the client's configured merchant, exactly
    /// like the official SDK's `generate_check_value`.
    pub fn generate_check_value(&self, params: &HashMap<String, String>) -> Result<String> {
        let encrypt_type = crate::crypto::parse_encrypt_type(params);
        let mut with_id = params.clone();
        with_id.insert("MerchantID".to_owned(), self.merchant_id.clone());
        check_mac_value(&with_id, &self.hash_key, &self.hash_iv, encrypt_type)
    }
}
