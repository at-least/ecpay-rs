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

use base64::Engine;
use cbc::cipher::{
    block_padding::Pkcs7, Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt,
    BlockModeEncrypt, Key, KeyInit, KeyIvInit,
};
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

/// Hex nibble decoder shared with [`crate::client`]'s lenient
/// `unquote_plus` (single source for both `%XX` readers).
pub(crate) fn hex_val(c: u8) -> Option<u8> {
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

/// The digest a CheckMacValue selects, typed: SHA-256 (`EncryptType=1`,
/// AIO 金流) or MD5 (`EncryptType=0`, 國內物流 — the only family still on
/// it). Deliberately closed and exhaustive: 0 and 1 are all the protocol
/// has; a third digest would be a new ECPay protocol and a breaking
/// release either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptType {
    /// SHA-256 (wire `EncryptType=1`).
    Sha256,
    /// MD5 (wire `EncryptType=0`; retired on AIO, still how 國內物流 signs).
    Md5,
}

impl EncryptType {
    /// The wire integer.
    pub fn as_i64(self) -> i64 {
        match self {
            Self::Sha256 => 1,
            Self::Md5 => 0,
        }
    }
}

impl From<EncryptType> for i64 {
    fn from(t: EncryptType) -> i64 {
        t.as_i64()
    }
}

impl std::convert::TryFrom<i64> for EncryptType {
    type Error = Error;

    /// Only 0 and 1 exist; anything else is the caller bug the old i64
    /// parameter surfaced at hashing time — same error, moved to the
    /// conversion where it belongs.
    fn try_from(n: i64) -> Result<Self> {
        match n {
            1 => Ok(Self::Sha256),
            0 => Ok(Self::Md5),
            n => Err(Error::UnsupportedEncryptType(n)),
        }
    }
}

/// Borrowed `(key, value)` view of a `HashMap`/`BTreeMap<String, String>`
/// for the pair-iterator entry points below — a response map is hashed as
/// received, without cloning it first.
pub(crate) fn str_pairs<'a>(
    map: impl IntoIterator<Item = (&'a String, &'a String)>,
) -> impl Iterator<Item = (&'a str, &'a str)> {
    map.into_iter().map(|(k, v)| (k.as_str(), v.as_str()))
}

/// Sort the "k=v" pairs the way the official SDKs order the CheckMacValue
/// preimage: by lowercased key (the Python SDK sorts `key=lambda k:
/// k[0].lower()`), with the original key as a deterministic tie-breaker (the
/// Python sort is stable over dict insertion order, which a hash map does not
/// reproduce).
fn sorted_pairs<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<(&'a str, &'a str)> {
    // Decorate-sort-undecorate: lowercase each key once (O(n) allocations)
    // instead of on every comparison.
    let mut decorated: Vec<(String, &str, &str)> = pairs
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), k, v))
        .collect();
    decorated.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    decorated.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// Go `HashMac`: the "k=v" pairs (joined by &, wrapped in HashKey/HashIV)
/// URL-encoded with the .NET-flavored encoder, lowercased, SHA-256-hashed,
/// UPPERCASE hex. Equivalent to [`check_mac_value`] with EncryptType = 1 —
/// and, like that arm, computed over the shared preimage path
/// (`cmv_preimage`), so there is no error branch to swallow (SHA-256
/// cannot fail).
pub fn hash_mac(params: &HashMap<String, String>, hash_key: &str, hash_iv: &str) -> String {
    to_upper_hex(&Sha256::digest(
        cmv_preimage(str_pairs(params), hash_key, hash_iv).as_bytes(),
    ))
}

/// Shared verification half of [`check_mac_value`]: recompute the mac over
/// the `params` pairs (a leftover `CheckMacValue` pair is scrubbed) and
/// constant-time compare against `got`, upper-casing the inbound value
/// defensively (ECPay sends uppercase, but a received value's case isn't a
/// signal worth failing on). Empty `got` verifies as `false`;
/// `encrypt_type` is chosen by the caller — **never** by the verified
/// message itself (a verifier must not take its algorithm selector from
/// the very message it is verifying): payment query responses verify with
/// the digest the REQUEST was signed under (`post_cmv_verified` reads the
/// request's `EncryptType`, defaulting to SHA-256), logistics hardcodes
/// MD5, the AIO callback verifies SHA-256 only.
pub(crate) fn verify_mac<'a>(
    got: &str,
    params: impl IntoIterator<Item = (&'a str, &'a str)>,
    hash_key: &str,
    hash_iv: &str,
    encrypt_type: EncryptType,
) -> bool {
    if got.is_empty() {
        return false;
    }
    let want = check_mac_value_pairs(params, hash_key, hash_iv, encrypt_type);
    constant_time_eq(got.to_uppercase().as_bytes(), want.as_bytes())
}

/// Parses a params map's `EncryptType` value the way the official SDK does:
/// missing or unparsable defaults to SHA-256; a parsable but nonexistent
/// code is the caller bug `TryFrom<i64>` reports. Shared by
/// [`crate::Ecpay::generate_check_value`] (signing an outbound request) and
/// the payment-response verification path (checking an inbound one).
pub(crate) fn parse_encrypt_type(value: Option<&str>) -> Result<EncryptType> {
    let n = value.and_then(|v| v.parse::<i64>().ok()).unwrap_or(1);
    EncryptType::try_from(n)
}

/// The hashing half of the Python SDK's `generate_check_value`: drop any
/// existing CheckMacValue, sort by lowercased key, wrap in HashKey/HashIV,
/// .NET-URLEncode, lowercase, then SHA-256 ([`EncryptType::Sha256`]) or
/// MD5 ([`EncryptType::Md5`]) — uppercase hex. Forcing MerchantID to the
/// client's is [`crate::Ecpay::generate_check_value`]'s job, not this
/// function's.
///
/// Infallible by construction: the enum makes an unsupported digest
/// unrepresentable (the rejection lives in `TryFrom<i64>` /
/// `parse_encrypt_type`).
pub fn check_mac_value(
    params: &HashMap<String, String>,
    hash_key: &str,
    hash_iv: &str,
    encrypt_type: EncryptType,
) -> String {
    check_mac_value_pairs(str_pairs(params), hash_key, hash_iv, encrypt_type)
}

/// [`check_mac_value`] over borrowed pairs — the crate-internal form every
/// signing and verifying path shares, so a response map is hashed as
/// received without a clone. Any `CheckMacValue` pair is scrubbed.
pub(crate) fn check_mac_value_pairs<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    hash_key: &str,
    hash_iv: &str,
    encrypt_type: EncryptType,
) -> String {
    let preimage = cmv_preimage(pairs, hash_key, hash_iv);
    match encrypt_type {
        EncryptType::Sha256 => to_upper_hex(&Sha256::digest(preimage.as_bytes())),
        EncryptType::Md5 => to_upper_hex(&<Md5 as Digest>::digest(preimage.as_bytes())),
    }
}

/// The digest preimage both EncryptType arms (and [`hash_mac`], which is
/// SHA-256 by definition) share: drop any existing CheckMacValue, sort by
/// lowercased key, join "k=v" pairs with &, wrap in HashKey/HashIV, .NET-
/// URLEncode, lowercase.
fn cmv_preimage<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    hash_key: &str,
    hash_iv: &str,
) -> String {
    let pairs = sorted_pairs(pairs.into_iter().filter(|(k, _)| *k != "CheckMacValue"));
    use std::fmt::Write as _;
    let mut s = format!("HashKey={hash_key}&");
    for (k, v) in &pairs {
        // write! into a String cannot fail; avoids a per-pair allocation.
        let _ = write!(s, "{k}={v}&");
    }
    let _ = write!(s, "HashIV={hash_iv}");
    url_encode(&s).to_lowercase()
}

fn to_upper_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(UPPER_HEX[usize::from(b >> 4)] as char);
        out.push(UPPER_HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Constant-time byte comparison, on the audited `subtle` primitive (Go
/// `crypto/subtle.ConstantTimeCompare` semantics). The explicit length
/// guard documents that lengths are not secret (subtle's slice `ct_eq`
/// also short-circuits to not-equal on unequal lengths).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq as _;
    a.ct_eq(b).into()
}

/// Go `Encrypt`: key size first (`aes.NewCipher`'s order), then the IV
/// length (kept an explicit error instead of a panic for a misconfigured
/// HashIV), PKCS7-pad, AES-CBC encrypt, base64.
pub fn encrypt(text: &[u8], hash_key: &[u8], hash_iv: &[u8]) -> Result<String> {
    let crypted = match hash_key.len() {
        16 => cbc_encrypt::<aes::Aes128>(hash_key, hash_iv, text)?,
        24 => cbc_encrypt::<aes::Aes192>(hash_key, hash_iv, text)?,
        32 => cbc_encrypt::<aes::Aes256>(hash_key, hash_iv, text)?,
        n => return Err(Error::AesKeySize(n)),
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(crypted))
}

/// Go `Decrypt`: base64-decode, AES-CBC decrypt, PKCS7-unpad. Errors (never
/// panics) on bad padding, a wrong IV length, or a non-block-multiple
/// ciphertext. Check order matches Go: base64, key size, ciphertext length,
/// IV length, padding.
///
/// ⚠ The returned errors are **detailed** (which stage failed, and `Error::
/// Padding` is distinct from the UTF-8/JSON errors). That is right for
/// decrypting ECPay's *responses* over your own TLS connection, but never
/// use this directly on attacker-reachable callback bodies — a distinguishable
/// padding failure there is a CBC padding oracle. Use the callback decoders
/// ([`crate::Ecpay::decrypt_ecpg_callback`],
/// [`crate::Ecpay::decrypt_logistics_callback`],
/// [`crate::Ecpay::decrypt_temp_trade_established`]), which collapse every
/// payload-content-dependent failure into one fixed message.
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
        16 => cbc_decrypt::<aes::Aes128>(hash_key, hash_iv, &decoded)?,
        24 => cbc_decrypt::<aes::Aes192>(hash_key, hash_iv, &decoded)?,
        _ => cbc_decrypt::<aes::Aes256>(hash_key, hash_iv, &decoded)?,
    };
    String::from_utf8(plain).map_err(|_| Error::Message("decrypted payload is not UTF-8".into()))
}

/// CBC + PKCS7 via the audited RustCrypto [`cbc`] mode crate — padding
/// (always 1..=block bytes, empty input gets a full block) and the CBC
/// chaining are the crate's, not hand-rolled. The official ECPay AES test
/// vectors (tests/aes_vectors.rs) pin the exact wire bytes this must keep
/// producing.
fn cbc_encrypt<C>(hash_key: &[u8], hash_iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: BlockCipherEncrypt + KeyInit,
{
    let key = Key::<C>::try_from(hash_key).map_err(|_| Error::AesKeySize(hash_key.len()))?;
    let iv = Array::<u8, C::BlockSize>::try_from(hash_iv).map_err(|_| Error::InvalidIvLength {
        got: hash_iv.len(),
        want: AES_BLOCK_SIZE,
    })?;
    Ok(cbc::Encryptor::<C>::new(&key, &iv).encrypt_padded_vec::<Pkcs7>(data))
}

/// [`cbc_encrypt`]'s inverse. The `block_padding::Error` the crate returns
/// is opaque (a unit struct — the bad padding's value and shape are not
/// reported), so mapping it to [`Error::Padding`] keeps the padding-oracle
/// collapse: no content-dependent detail escapes (see [`decrypt`]). Runs
/// only on ciphertext our length gate already validated as a non-empty
/// block multiple.
fn cbc_decrypt<C>(hash_key: &[u8], hash_iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: BlockCipherDecrypt + KeyInit,
{
    let key = Key::<C>::try_from(hash_key).map_err(|_| Error::AesKeySize(hash_key.len()))?;
    let iv = Array::<u8, C::BlockSize>::try_from(hash_iv).map_err(|_| Error::InvalidIvLength {
        got: hash_iv.len(),
        want: AES_BLOCK_SIZE,
    })?;
    cbc::Decryptor::<C>::new(&key, &iv)
        .decrypt_padded_vec::<Pkcs7>(data)
        .map_err(|_| Error::Padding)
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
///
/// ⚠ Like [`decrypt`], the errors here are detailed per stage — for
/// attacker-reachable callback bodies use the callback decoders instead
/// (see [`decrypt`]).
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
    unmarshal_value(serde_json::from_str(s)?)
}

/// [`unmarshal`] for an already-parsed JSON value (same null stripping).
pub(crate) fn unmarshal_value<T: DeserializeOwned>(v: serde_json::Value) -> Result<T> {
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

/// [`decrypt_data`] for attacker-reachable callback bodies
/// (`decrypt_ecpg_callback` / `decrypt_logistics_callback` /
/// `decrypt_temp_trade_established`). The AES envelope authenticates no
/// `Data`, so a distinguishable failure between "bad padding" and a later
/// stage (UTF-8, JSON, URL-escape) would let a caller on a public endpoint
/// forge payload encryption without the key (CBC padding oracle / CBC-R).
/// ALLOWLIST the errors that depend only on inputs the attacker already
/// knows — their own ciphertext's base64 shape and the configured key/IV
/// sizes — and collapse EVERYTHING else into one fixed message, so a future
/// variant fails closed instead of silently reopening the oracle. The
/// accepted residual is timing (padding fails before parsing); handlers must
/// additionally answer every callback error uniformly (see README).
pub(crate) fn decrypt_payload_uniform<T: DeserializeOwned>(
    data: &str,
    hash_key: &[u8],
    hash_iv: &[u8],
) -> Result<T> {
    decrypt_data(data, hash_key, hash_iv).map_err(|e| match e {
        Error::Base64(_)
        | Error::AesKeySize(_)
        | Error::InvalidIvLength { .. }
        | Error::InvalidCiphertextLength(_) => e,
        _ => Error::Message("ecpay: callback payload failed to decrypt or parse".into()),
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
///
/// ⚠ Float-money hygiene for callers: shortest-round-trip means an f64
/// arithmetic artifact goes on the wire verbatim — `3 * 19.99` serializes
/// as `59.970000000000006`. Construct these fields by parsing the decimal
/// literal your pricing produced (`"59.97".parse::<f64>()`) or compute in
/// integer minor units and convert once at the end; TWD totals
/// (`TotalAmount`, `SalesAmount`, …) are `i64` and never touch this path.
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
    fn check_mac_value_supports_md5() {
        let mut params = HashMap::new();
        params.insert("MerchantID".to_owned(), "2000132".to_owned());
        params.insert("EncryptType".to_owned(), "0".to_owned());
        // EncryptType is chosen by the argument, not by reading the map.
        let md5 = check_mac_value(&params, "k", "i", EncryptType::Md5);
        assert_eq!(md5.len(), 32, "MD5 digest is 32 hex chars");
        assert!(md5
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn verify_mac_matches_both_digests_and_is_case_defensive() {
        let mut params = HashMap::new();
        params.insert("MerchantID".to_owned(), "2000132".to_owned());
        params.insert("EncryptType".to_owned(), "1".to_owned());

        let sha = check_mac_value(&params, "k", "i", EncryptType::Sha256);
        assert!(verify_mac(
            &sha,
            str_pairs(&params),
            "k",
            "i",
            EncryptType::Sha256
        ));
        // Lowercase inbound verifies too (upper-cased before compare).
        assert!(verify_mac(
            &sha.to_lowercase(),
            str_pairs(&params),
            "k",
            "i",
            EncryptType::Sha256
        ));
        // Wrong key / wrong digest type / empty got all verify as false.
        assert!(!verify_mac(
            &sha,
            str_pairs(&params),
            "other",
            "i",
            EncryptType::Sha256
        ));
        assert!(!verify_mac(
            &sha,
            str_pairs(&params),
            "k",
            "i",
            EncryptType::Md5
        ));
        assert!(!verify_mac(
            "",
            str_pairs(&params),
            "k",
            "i",
            EncryptType::Sha256
        ));

        // A leftover CheckMacValue in the map is scrubbed before hashing —
        // by the public map form and the borrowed-pairs form alike.
        params.insert("CheckMacValue".to_owned(), "stale".to_owned());
        assert_eq!(check_mac_value(&params, "k", "i", EncryptType::Sha256), sha);
        assert!(verify_mac(
            &sha,
            str_pairs(&params),
            "k",
            "i",
            EncryptType::Sha256
        ));

        // MD5 (EncryptType 0) verifies against its own digest.
        let md5 = check_mac_value(&params, "k", "i", EncryptType::Md5);
        assert!(verify_mac(
            &md5,
            str_pairs(&params),
            "k",
            "i",
            EncryptType::Md5
        ));
    }

    #[test]
    fn sorted_pairs_orders_by_lowercased_key_with_tiebreak() {
        let mut params = HashMap::new();
        params.insert("b".to_owned(), "2".to_owned());
        params.insert("A".to_owned(), "1".to_owned());
        params.insert("a".to_owned(), "3".to_owned());
        let got = sorted_pairs(str_pairs(&params));
        assert_eq!(got, vec![("A", "1"), ("a", "3"), ("b", "2")]);
    }

    // PKCS7 pad/unpad correctness is pinned through the PUBLIC decrypt API
    // (tests/crypto.rs crafts raw-CBC ciphertexts with malformed padding and
    // asserts the opaque Error::Padding), so the cbc crate's unpad path is
    // covered end-to-end without exposing internals.

    // Characterization (pinning): the contract verify_mac depends on —
    // equal inputs true, any one-bit difference false, unequal lengths
    // false without panicking. Written before swapping the body onto the
    // `subtle` crate; must stay green across that refactor.
    #[test]
    fn constant_time_eq_equal_differs_on_one_bit_and_on_length() {
        assert!(constant_time_eq(b"MACVALUE", b"MACVALUE"));
        assert!(!constant_time_eq(b"MACVALUE", b"MACVALUF")); // last bit flipped
        assert!(!constant_time_eq(b"MACVALUE", b"MACVALU")); // shorter
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    // EncryptType's whole contract in one place: the two wire values
    // round-trip, anything else is Error::UnsupportedEncryptType, and the
    // wire-string parse keeps the Python-SDK default (missing/garbage → 1)
    // while rejecting parsable-but-nonexistent codes.
    #[test]
    fn encrypt_type_conversions_and_parse_defaults() {
        assert_eq!(EncryptType::Sha256.as_i64(), 1);
        assert_eq!(EncryptType::Md5.as_i64(), 0);
        assert_eq!(i64::from(EncryptType::Sha256), 1);
        assert_eq!(i64::from(EncryptType::Md5), 0);
        assert_eq!(EncryptType::try_from(1).unwrap(), EncryptType::Sha256);
        assert_eq!(EncryptType::try_from(0).unwrap(), EncryptType::Md5);
        assert!(matches!(
            EncryptType::try_from(2),
            Err(Error::UnsupportedEncryptType(2))
        ));
        assert!(matches!(
            EncryptType::try_from(-1),
            Err(Error::UnsupportedEncryptType(-1))
        ));
        // parse: missing/blank/garbage defaults to SHA-256 (SDK parity).
        assert_eq!(parse_encrypt_type(None).unwrap(), EncryptType::Sha256);
        assert_eq!(parse_encrypt_type(Some("")).unwrap(), EncryptType::Sha256);
        assert_eq!(
            parse_encrypt_type(Some("abc")).unwrap(),
            EncryptType::Sha256
        );
        assert_eq!(parse_encrypt_type(Some("1")).unwrap(), EncryptType::Sha256);
        assert_eq!(parse_encrypt_type(Some("0")).unwrap(), EncryptType::Md5);
        // Parsable but nonexistent: the same error TryFrom gives.
        assert!(matches!(
            parse_encrypt_type(Some("2")),
            Err(Error::UnsupportedEncryptType(2))
        ));
    }
}
