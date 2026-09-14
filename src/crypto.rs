//! Crypto and URL-encoding primitives: the .NET-flavored URLEncode for
//! CheckMacValue, the PHP-flavored aesURLEncode for the AES payload, the
//! CheckMacValue hash (SHA-256 per EncryptType=1, MD5 per EncryptType=0),
//! VerifyCheckMacValue, and the AES-128/192/256-CBC + PKCS7 + base64
//! encrypt/decrypt pair.
//!
//! The wire bytes match ECPay's .NET backend exactly (pinned by the official
//! test vectors in the test suite). One deliberate deviation from the official
//! Python SDK exists here: its `generate_check_value` keeps `~` literal
//! (Python's `quote` always-safe set), but ECPay's server hashes the .NET
//! encoding, which escapes `~` to `%7e`. The official `~` test vector pins the
//! `%7e` behavior; see `url_encode` and the README's compatibility notes.

use std::collections::HashMap;
use std::sync::OnceLock;

use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use base64::Engine;
use md5::Md5;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const AES_BLOCK_SIZE: usize = 16;
const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Go `url.QueryEscape`, byte-for-byte: alphanumerics and `-_.~` stay
/// literal, space becomes `+`, everything else becomes an uppercase %XX
/// escape (each UTF-8 byte escaped separately).
pub(crate) fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(UPPER_HEX[usize::from(c >> 4)] as char);
                out.push(UPPER_HEX[usize::from(c & 0x0f)] as char);
            }
        }
    }
    out
}

/// Go `url.QueryUnescape`: `+` becomes space, %XX (either case) decodes to its
/// byte, and a malformed escape is an error (`invalid URL escape "%zz"`).
pub(crate) fn query_unescape(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let bad = |i: usize| Error::UrlEscape(s[i..].chars().take(3).collect());
                if i + 2 >= b.len() {
                    return Err(bad(i));
                }
                match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                    (Some(hi), Some(lo)) => out.push(hi * 16 + lo),
                    _ => return Err(bad(i)),
                }
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::Message("invalid UTF-8 in unescaped query".into()))
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// ECPay 使用 .net 不標準的 urlencode 方式
///
/// The unreserved set is .NET's `HttpUtility.UrlEncode` IsUrlSafeChar set —
/// alphanumerics plus `- _ . ! * ( )` — with space becoming `+` and every
/// other byte (including `~` and each UTF-8 byte) a lowercase %XX escape.
/// This is the exact transform ECPay applies before hashing CheckMacValue.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'*'
            | b'('
            | b')' => out.push(c as char),
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(LOWER_HEX[usize::from(c >> 4)] as char);
                out.push(LOWER_HEX[usize::from(c & 0x0f)] as char);
            }
        }
    }
    out
}

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// aesURLEncode is the URL-encode flavor ECPay uses for the AES payload (the
/// invoice Data field). It is deliberately NOT the same as URLEncode above:
/// CheckMacValue is hashed, so it lowercases the hex and restores .NET's
/// unescaped set; the AES payload is encrypted and then url-DECODED by ECPay,
/// so it must mirror PHP urlencode instead — uppercase hex, space -> +, no
/// lowercase and no .NET restoration. Go's url.QueryEscape already matches
/// that except it leaves ~ literal, so only ~ -> %7E is added. Mixing the two
/// encoders is what ECPay warns yields TransCode != 1. (Verified against
/// ECPay's official AES test vectors.)
pub(crate) fn aes_url_encode(s: &str) -> String {
    query_escape(s).replace('~', "%7E")
}

/// Sort the "k=v" pairs the way the official SDKs order the CheckMacValue
/// preimage: by lowercased key (the Python SDK sorts `key=lambda k:
/// k[0].lower()`), with the original key as a deterministic tie-breaker (the
/// Python sort is stable over dict insertion order, which a hash map does not
/// reproduce).
fn sorted_pairs(params: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> =
        params.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    pairs.sort_by(|a, b| {
        a.0.to_lowercase()
            .cmp(&b.0.to_lowercase())
            .then_with(|| a.0.cmp(&b.0))
    });
    pairs
}

/// Go `HashMac`: the "k=v" pairs (joined by &, wrapped in HashKey/HashIV)
/// URL-encoded with the .NET-flavored encoder, lowercased, SHA-256-hashed,
/// UPPERCASE hex. Equivalent to [`check_mac_value`] with EncryptType = 1.
pub fn hash_mac(params: &HashMap<String, String>, hash_key: &str, hash_iv: &str) -> String {
    check_mac_value(params, hash_key, hash_iv, 1).expect("EncryptType=1 cannot fail")
}

/// Shared verification half of [`check_mac_value`]: recompute the mac over
/// `params` (a leftover `CheckMacValue` key in the map is scrubbed) and
/// constant-time compare against `got`, upper-casing the inbound value
/// defensively (ECPay sends uppercase, but a received value's case isn't a
/// signal worth failing on). Empty `got` verifies as `false`;
/// `encrypt_type` is chosen by the caller (payment responses derive it from
/// the response's `EncryptType`, logistics hardcodes MD5 = 0, the AIO
/// callback verifies SHA-256 only).
pub(crate) fn verify_mac(
    got: &str,
    params: &HashMap<String, String>,
    hash_key: &str,
    hash_iv: &str,
    encrypt_type: i64,
) -> Result<bool> {
    if got.is_empty() {
        return Ok(false);
    }
    let want = check_mac_value(params, hash_key, hash_iv, encrypt_type)?;
    Ok(constant_time_eq(
        got.to_uppercase().as_bytes(),
        want.as_bytes(),
    ))
}

/// Reads the `EncryptType` field out of a params map, defaulting to 1
/// (SHA-256) like the official SDK when it's missing or unparsable. Shared
/// by [`crate::Ecpay::generate_check_value`] (signing an outbound request)
/// and the payment-response verification path (checking an inbound one).
pub(crate) fn parse_encrypt_type(params: &HashMap<String, String>) -> i64 {
    params
        .get("EncryptType")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1)
}

/// The Python SDK's `generate_check_value`: drop any existing CheckMacValue,
/// force MerchantID to the client's, sort by lowercased key, wrap in
/// HashKey/HashIV, .NET-URLEncode, lowercase, then SHA-256 (EncryptType 1) or
/// MD5 (EncryptType 0) — uppercase hex. `encrypt_type` comes from the
/// request's own `EncryptType` field, defaulting to 1.
pub fn check_mac_value(
    params: &HashMap<String, String>,
    hash_key: &str,
    hash_iv: &str,
    encrypt_type: i64,
) -> Result<String> {
    let mut scrubbed = params.clone();
    scrubbed.remove("CheckMacValue");
    let pairs = sorted_pairs(&scrubbed);
    let mut s = format!("HashKey={hash_key}&");
    for (k, v) in &pairs {
        s.push_str(&format!("{k}={v}&"));
    }
    s.push_str(&format!("HashIV={hash_iv}"));
    let s = url_encode(&s).to_lowercase();
    let digest: Vec<u8> = match encrypt_type {
        1 => Sha256::digest(s.as_bytes()).to_vec(),
        0 => <Md5 as Digest>::digest(s.as_bytes()).to_vec(),
        n => return Err(Error::UnsupportedEncryptType(n)),
    };
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(UPPER_HEX[usize::from(b >> 4)] as char);
        out.push(UPPER_HEX[usize::from(b & 0x0f)] as char);
    }
    Ok(out)
}

/// Constant-time byte comparison (Go `crypto/subtle.ConstantTimeCompare`; like
/// Go, a length difference short-circuits — lengths are not secret).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Go `Encrypt`: validate the key size and IV length (Go aes.NewCipher +
/// the explicit check that keeps a misconfigured HashIV an error instead of a
/// panic), PKCS7-pad, AES-CBC encrypt, base64.
pub fn encrypt(text: &[u8], hash_key: &[u8], hash_iv: &[u8]) -> Result<String> {
    if hash_iv.len() != AES_BLOCK_SIZE {
        return Err(Error::InvalidIvLength {
            got: hash_iv.len(),
            want: AES_BLOCK_SIZE,
        });
    }
    let padded = pad_pkcs7(text, AES_BLOCK_SIZE);
    let crypted = match hash_key.len() {
        16 => cbc_encrypt::<aes::Aes128>(hash_key, hash_iv, padded)?,
        24 => cbc_encrypt::<aes::Aes192>(hash_key, hash_iv, padded)?,
        32 => cbc_encrypt::<aes::Aes256>(hash_key, hash_iv, padded)?,
        n => return Err(Error::AesKeySize(n)),
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(crypted))
}

/// Go `Decrypt`: base64-decode, AES-CBC decrypt, PKCS7-unpad. Errors (never
/// panics) on bad padding, a wrong IV length, or a non-block-multiple
/// ciphertext. Check order matches Go: base64, key size, ciphertext length,
/// IV length, padding.
pub fn decrypt(text: &str, hash_key: &[u8], hash_iv: &[u8]) -> Result<String> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(text)?;
    if hash_key.len() != 16 && hash_key.len() != 24 && hash_key.len() != 32 {
        return Err(Error::AesKeySize(hash_key.len()));
    }
    if decoded.is_empty() || decoded.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidCiphertextLength(decoded.len()));
    }
    if hash_iv.len() != AES_BLOCK_SIZE {
        return Err(Error::InvalidIvLength {
            got: hash_iv.len(),
            want: AES_BLOCK_SIZE,
        });
    }
    let plain = match hash_key.len() {
        16 => cbc_decrypt::<aes::Aes128>(hash_key, hash_iv, decoded)?,
        24 => cbc_decrypt::<aes::Aes192>(hash_key, hash_iv, decoded)?,
        _ => cbc_decrypt::<aes::Aes256>(hash_key, hash_iv, decoded)?,
    };
    let unpadded = unpad_pkcs7(&plain)?;
    String::from_utf8(unpadded.to_vec())
        .map_err(|_| Error::Message("decrypted payload is not UTF-8".into()))
}

fn cbc_encrypt<C>(hash_key: &[u8], hash_iv: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>>
where
    C: KeyInit + BlockCipherEncrypt + BlockSizeUser,
{
    let cipher = C::new_from_slice(hash_key).map_err(|_| Error::AesKeySize(hash_key.len()))?;
    // Textbook CBC chaining over the raw AES block cipher, so PKCS7 padding
    // and its error branches stay exactly Go's. Byte-exactness is pinned by
    // the official ECPay AES test vectors (tests/aes_vectors.rs).
    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(hash_iv);
    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let block: &mut Block<C> = chunk
            .try_into()
            .expect("chunk length equals the AES block size");
        cipher.encrypt_block(block);
        prev.copy_from_slice(chunk);
    }
    Ok(data)
}

fn cbc_decrypt<C>(hash_key: &[u8], hash_iv: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>>
where
    C: KeyInit + BlockCipherDecrypt + BlockSizeUser,
{
    let cipher = C::new_from_slice(hash_key).map_err(|_| Error::AesKeySize(hash_key.len()))?;
    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(hash_iv);
    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        let mut saved = [0u8; AES_BLOCK_SIZE];
        saved.copy_from_slice(chunk);
        let block: &mut Block<C> = chunk
            .try_into()
            .expect("chunk length equals the AES block size");
        cipher.decrypt_block(block);
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev.copy_from_slice(&saved);
    }
    Ok(data)
}

/// Go `EncryptData`: compact JSON with HTML escaping OFF (<, >, & literal —
/// serde_json never HTML-escapes, matching Go's SetEscapeHTML(false)), then
/// aesURLEncode, then Encrypt.
pub fn encrypt_data<T: Serialize + ?Sized>(
    input: &T,
    hash_key: &[u8],
    hash_iv: &[u8],
) -> Result<String> {
    let data = serde_json::to_string(input)?;
    let encoded = aes_url_encode(&data);
    encrypt(encoded.as_bytes(), hash_key, hash_iv)
}

/// Go `DecryptData`: Decrypt, url-unescape (Go QueryUnescape semantics),
/// then JSON-parse into the typed output.
pub fn decrypt_data<T: DeserializeOwned>(data: &str, hash_key: &[u8], hash_iv: &[u8]) -> Result<T> {
    let decrypted = decrypt(data, hash_key, hash_iv)?;
    let j = query_unescape(&decrypted)?;
    unmarshal(&j)
}

/// Go `json.Unmarshal` into a struct: JSON null decodes to the zero value for
/// every field type, same as an absent field. serde errors on an explicit
/// null for String/i64/Vec fields instead, so drop null-valued properties
/// before the typed pass and let `#[serde(default)]` supply the zero value
/// (Value fields keep null either way — their default IS null). Null ELEMENTS
/// inside arrays are left as-is; no ecpay wire struct has a Vec whose ECPay
/// ever sends null elements in.
pub fn unmarshal<T: DeserializeOwned>(s: &str) -> Result<T> {
    let v: serde_json::Value = serde_json::from_str(s)?;
    Ok(serde_json::from_value(strip_null_properties(v))?)
}

fn strip_null_properties(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_null_properties(v)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(strip_null_properties).collect())
        }
        other => other,
    }
}

/// Go `padPKCS7`: always appends 1..=blockSize pad bytes (empty input gets a
/// full block).
fn pad_pkcs7(ciphertext: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - ciphertext.len() % block_size;
    let mut out = Vec::with_capacity(ciphertext.len() + padding);
    out.extend_from_slice(ciphertext);
    out.extend(std::iter::repeat_n(padding as u8, padding));
    out
}

/// Go `unpadPKCS7`, with the same error branches.
fn unpad_pkcs7(ciphertext: &[u8]) -> Result<&[u8]> {
    let length = ciphertext.len();
    if length == 0 {
        return Err(Error::EmptyCiphertext);
    }
    let unpadding = ciphertext[length - 1];
    if unpadding == 0 || unpadding as usize > AES_BLOCK_SIZE || unpadding as usize > length {
        return Err(Error::PaddingValue(unpadding));
    }
    for &b in &ciphertext[length - unpadding as usize..] {
        if b != unpadding {
            return Err(Error::PaddingBytes);
        }
    }
    Ok(&ciphertext[..length - unpadding as usize])
}

/// Go `int(time.Now().Unix())`.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The package-level HTTP client. Hardened for payment traffic: no redirect
/// following (a 30x on a signed API POST is either misconfiguration or an
/// attempt to replay the payload elsewhere — ECPay's API endpoints answer
/// directly, never redirect), a 10s connect timeout, and a 30s overall
/// timeout (ECPay's stage endpoints have been observed to hang).
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
/// call-then-wait usage pattern.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
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

/// serde helper for the AES-JSON money fields (ItemCount/ItemPrice/
/// ItemAmount, GoodsWeight): JSON has no NaN/Infinity, and serde_json
/// silently serializes a non-finite f64 as `null` — a payment field must
/// never do that, so reject it loudly. Finite values use serde_json's
/// default (shortest round-trip digits; integral values keep a trailing
/// `.0`). `1.0` and `1` are the same JSON number to ECPay's parser — the
/// B2B module has sent serde_json-formatted floats to the stage server and
/// been accepted (2026-09) — which is why the former Go-`encoding/json`
/// byte emulation was dropped.
pub mod finite_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        if v.is_finite() {
            s.serialize_f64(*v)
        } else {
            Err(serde::ser::Error::custom(format_args!(
                "non-finite float {v} cannot be serialized to JSON"
            )))
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        f64::deserialize(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_is_the_dot_net_contract() {
        assert_eq!(url_encode("a~b !(*)"), "a%7eb+!(*)");
        assert_eq!(url_encode("測"), "%e6%b8%ac");
        assert_eq!(url_encode("k=v"), "k%3dv");
        assert_eq!(url_encode(" "), "+");
    }

    #[test]
    fn check_mac_value_supports_md5_and_rejects_others() {
        let mut params = HashMap::new();
        params.insert("MerchantID".to_owned(), "2000132".to_owned());
        params.insert("EncryptType".to_owned(), "0".to_owned());
        // EncryptType is chosen by the argument, not by reading the map.
        let md5 = check_mac_value(&params, "k", "i", 0).unwrap();
        assert_eq!(md5.len(), 32, "MD5 digest is 32 hex chars");
        assert!(md5
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert!(matches!(
            check_mac_value(&params, "k", "i", 2),
            Err(Error::UnsupportedEncryptType(2))
        ));
    }

    #[test]
    fn verify_mac_matches_both_digests_and_is_case_defensive() {
        let mut params = HashMap::new();
        params.insert("MerchantID".to_owned(), "2000132".to_owned());
        params.insert("EncryptType".to_owned(), "1".to_owned());

        let sha = check_mac_value(&params, "k", "i", 1).unwrap();
        assert!(verify_mac(&sha, &params, "k", "i", 1).unwrap());
        // Lowercase inbound verifies too (upper-cased before compare).
        assert!(verify_mac(&sha.to_lowercase(), &params, "k", "i", 1).unwrap());
        // Wrong key / wrong digest type / empty got all verify as false.
        assert!(!verify_mac(&sha, &params, "other", "i", 1).unwrap());
        assert!(!verify_mac(&sha, &params, "k", "i", 0).unwrap());
        assert!(!verify_mac("", &params, "k", "i", 1).unwrap());

        // A leftover CheckMacValue in the map is scrubbed before hashing.
        params.insert("CheckMacValue".to_owned(), "stale".to_owned());
        assert!(verify_mac(&sha, &params, "k", "i", 1).unwrap());

        // MD5 (EncryptType 0) verifies against its own digest.
        let md5 = check_mac_value(&params, "k", "i", 0).unwrap();
        assert!(verify_mac(&md5, &params, "k", "i", 0).unwrap());
        assert!(matches!(
            verify_mac(&md5, &params, "k", "i", 7),
            Err(Error::UnsupportedEncryptType(7))
        ));
    }

    #[test]
    fn sorted_pairs_orders_by_lowercased_key_with_tiebreak() {
        let mut params = HashMap::new();
        params.insert("b".to_owned(), "2".to_owned());
        params.insert("A".to_owned(), "1".to_owned());
        params.insert("a".to_owned(), "3".to_owned());
        let got: Vec<(String, String)> = sorted_pairs(&params);
        assert_eq!(
            got,
            vec![
                ("A".to_owned(), "1".to_owned()),
                ("a".to_owned(), "3".to_owned()),
                ("b".to_owned(), "2".to_owned()),
            ]
        );
    }

    #[test]
    fn unpad_rejects_bad_padding() {
        assert!(unpad_pkcs7(b"").is_err());
        let mut b = [0u8; 16];
        assert!(unpad_pkcs7(&b).is_err()); // pad value 0
        b[15] = 0x20; // 32 > block size
        assert!(unpad_pkcs7(&b).is_err());
        b[15] = 3;
        b[14] = 3;
        b[13] = 1; // claims 3 but not all 3s
        assert!(unpad_pkcs7(&b).is_err());
        assert_eq!(unpad_pkcs7(b"abc\x02\x02").unwrap(), b"abc");
    }
}
