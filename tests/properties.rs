//! Property-based tests for the money-path primitives. A payment library's
//! crypto must hold for EVERY input, not just curated vectors: sign→verify
//! round-trips, tamper detection, codec conformance, and AES inversion are
//! asserted over randomized inputs (proptest shrinks on failure).

use std::collections::HashMap;

use proptest::collection::{hash_map, vec};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use sha2::{Digest, Sha256};

use ecpay::{decrypt, encrypt, hash_mac, url_encode};

/// Field names ECPay actually exchanges, plus hostile punctuation.
fn key_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // real wire keys
        prop::sample::select(vec![
            "MerchantID",
            "MerchantTradeNo",
            "RtnCode",
            "RtnMsg",
            "TradeAmt",
            "ItemName",
            "CheckMacValue",
            "EncryptType",
            "TradeNo",
            "CustomField1",
            "PaymentType",
        ])
        .prop_map(String::from),
        // hostile names
        "[a-zA-Z0-9_]{0,12}[&= ~%!#*()']{0,4}[a-zA-Z]{0,8}",
    ]
}

/// Values: ASCII, CJK, emoji, control-ish punctuation, and the exact bytes
/// that break naive encoders (`&`, `=`, `+`, `%`, `~`, space, quote).
fn value_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[ -~]{0,40}",                                      // printable ASCII
        "[\\u{4e00}-\\u{9fff}a-zA-Z0-9#~+ %&='!*()]{0,40}", // CJK + metachars
        "[\\u{1F600}-\\u{1F64F}\\u{2600}-\\u{26FF}]{0,8}",  // emoji / symbols
        prop::option::of("[\\u{0001}-\\u{001f}]{0,4}") // control chars (valid in Rust strings)
            .prop_map(|o| o.unwrap_or_default()),
    ]
}

fn stage_client() -> ecpay::Ecpay {
    ecpay::Ecpay {
        merchant_id: "3002607".into(),
        hash_key: KEY.into(),
        hash_iv: IV.into(),
        ..Default::default()
    }
}

fn params_strategy() -> impl Strategy<Value = HashMap<String, String>> {
    hash_map(key_strategy(), value_strategy(), 0..12).prop_map(|m| {
        let mut m = m;
        // MerchantID is always present in real traffic; guarantee it.
        m.entry("MerchantID".to_owned())
            .or_insert_with(|| "3002607".to_owned());
        m
    })
}

/// Turn a crate error into a shrinking proptest failure.
fn or_fail<T>(r: ecpay::Result<T>) -> Result<T, TestCaseError> {
    r.map_err(|e| TestCaseError::fail(e.to_string()))
}

const KEY: &str = "pwFHCqoQZGmho4w6";
const IV: &str = "EkRm7iFT261dpevs";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Sign→verify round-trip: anything this crate signs verifies, for ANY
    /// parameter map — the invariant the ReturnURL callback check relies on.
    #[test]
    fn sign_then_verify_round_trips(params in params_strategy()) {
        let client = stage_client();
        let mac = hash_mac(&params, KEY, IV);
        let mut with_mac = params.clone();
        with_mac.insert("CheckMacValue".to_owned(), mac);
        prop_assert!(client.verify_check_mac_value(&with_mac));
    }

    /// Tamper detection: flipping ANY byte of the digest must fail
    /// verification, and so must dropping or blanking the MAC.
    #[test]
    fn any_single_byte_mac_flip_fails_verification(
        params in params_strategy(),
        byte_index in 0usize..64,
        replacement in "[0-9A-F]",
    ) {
        let mac = hash_mac(&params, KEY, IV);
        let mut flipped = mac.clone();
        let idx = byte_index % mac.len();
        let original = flipped.as_bytes()[idx];
        let candidate = replacement.as_bytes()[0];
        if candidate.eq_ignore_ascii_case(&original) {
            // Chose the same digit: flip deterministically to the other nibble.
            let other = if original == b'0' { b'1' } else { b'0' };
            flipped.replace_range(idx..idx + 1, &(other as char).to_string());
        } else {
            flipped.replace_range(idx..idx + 1, &(candidate as char).to_string());
        }
        let client = stage_client();
        let mut with_mac = params.clone();
        with_mac.insert("CheckMacValue".to_owned(), flipped);
        prop_assert!(!client.verify_check_mac_value(&with_mac), "flipped MAC accepted");

        // Absent / blank / lowercase-copied-but-equal cases.
        prop_assert!(!client.verify_check_mac_value(&params), "missing MAC accepted");
        let mut blank = params.clone();
        blank.insert("CheckMacValue".to_owned(), String::new());
        prop_assert!(!client.verify_check_mac_value(&blank), "blank MAC accepted");
        // Case-insensitive acceptance of the SAME digest is intentional (ECPay
        // sends uppercase; the compare upper-cases both sides).
        let mut lower = params.clone();
        lower.insert("CheckMacValue".to_owned(), mac.to_lowercase());
        prop_assert!(client.verify_check_mac_value(&lower));
    }

    /// CMV determinism + independence from the map's insertion order, and
    /// agreement with an independent SHA-256 reference over the documented
    /// preimage.
    #[test]
    fn cmv_is_deterministic_and_matches_the_documented_preimage(params in params_strategy()) {
        let a = hash_mac(&params, KEY, IV);
        let b = hash_mac(&params, KEY, IV);
        prop_assert_eq!(a.len(), 64);
        prop_assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        prop_assert_eq!(a.clone(), b);

        // Independent reference: scrub CheckMacValue (as the library does),
        // sort by lowercased key, wrap, .NET-encode, lowercase, SHA-256,
        // uppercase hex (sha2 is already a dependency).
        let mut sorted: Vec<(String, String)> = params
            .iter()
            .filter(|(k, _)| *k != "CheckMacValue")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        sorted.sort_by(|x, y| {
            x.0.to_lowercase()
                .cmp(&y.0.to_lowercase())
                .then_with(|| x.0.cmp(&y.0))
        });
        let mut preimage = format!("HashKey={KEY}&");
        for (k, v) in &sorted {
            preimage.push_str(&format!("{k}={v}&"));
        }
        preimage.push_str(&format!("HashIV={IV}"));
        let mut netted = String::with_capacity(preimage.len());
        for &c in preimage.as_bytes() {
            match c {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'*'
                | b'(' | b')' => netted.push(c as char),
                b' ' => netted.push('+'),
                _ => netted.push_str(&format!("%{:02x}", c)),
            }
        }
        let digest = Sha256::digest(netted.to_lowercase().as_bytes());
        let reference: String = digest.iter().map(|b| format!("{b:02X}")).collect();
        prop_assert_eq!(a, reference);
    }

    /// url_encode conformance for arbitrary Unicode input: alnum +
    /// `-_.!*()` literal, space→+, every other byte (of the UTF-8 encoding)
    /// lowercase %xx — the official URLEncode table (2904) pins ~→%7e and
    /// the .NET restorations.
    #[test]
    fn url_encode_matches_the_dot_net_contract_for_arbitrary_text(
        chars in proptest::collection::vec(proptest::char::any(), 0..48),
    ) {
        let input: String = chars.into_iter().collect();
        let mut expected = String::with_capacity(input.len());
        for &b in input.as_bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'*'
                | b'(' | b')' => expected.push(b as char),
                b' ' => expected.push('+'),
                _ => expected.push_str(&format!("%{:02x}", b)),
            }
        }
        prop_assert_eq!(url_encode(&input), expected);
    }


    /// AES-128/192/256 round-trip: decrypt(encrypt(m)) == m for arbitrary
    /// Latin-1-mapped payloads (every byte becomes one Unicode codepoint, so
    /// the plaintext is always valid UTF-8 — the crate's String-typed API
    /// cannot carry non-UTF-8 bytes through `decrypt`) and all three key
    /// sizes.
    #[test]
    fn aes_round_trips_for_all_key_sizes(
        payload in vec(proptest::num::u8::ANY, 0..96),
        key_choice in 0usize..3,
    ) {
        let keys: [&[u8]; 3] = [
            b"ejCk326UnaZWKisg",
            b"ejCk326UnaZWKisg23456789",            // 24
            b"ejCk326UnaZWKisg2345678901234567",    // 32
        ];
        let iv = b"q9jcZX8Ib9LM8wYk";
        let key = keys[key_choice % 3];
        let plaintext: String = payload.iter().map(|&b| b as char).collect();
        let ciphertext = or_fail(encrypt(plaintext.as_bytes(), key, iv))?;
        let recovered = or_fail(decrypt(&ciphertext, key, iv))?;
        prop_assert_eq!(recovered, plaintext);
    }

    /// AES tamper detection: flipping a byte in the FIRST ciphertext block
    /// must change the recovered plaintext (or error) — never silently
    /// return the original.
    #[test]
    fn aes_ciphertext_tampering_changes_the_plaintext(
        payload in vec(proptest::num::u8::ANY, 32..96),
        flip_index in 0usize..16,
    ) {
        let key = b"ejCk326UnaZWKisg";
        let iv = b"q9jcZX8Ib9LM8wYk";
        let plaintext: String = payload.iter().map(|&b| b as char).collect();
        let mut ciphertext = or_fail(encrypt(plaintext.as_bytes(), key, iv))?;
        // The base64 body, not the block layout, is what an attacker edits:
        // flip one base64 char within the first block's span.
        let idx = flip_index % 16.min(ciphertext.len());
        let original = ciphertext.as_bytes()[idx];
        let replacement = if original == b'A' { 'B' } else { 'A' };
        ciphertext.replace_range(idx..idx + 1, &replacement.to_string());
        if let Ok(recovered) = decrypt(&ciphertext, key, iv) {
            prop_assert_ne!(recovered, plaintext);
        } // else: rejected as bad padding/base64 — also acceptable
    }

    /// TryFrom<i64> (and with it the wire-field parse behind
    /// generate_check_value) rejects unknown EncryptTypes instead of
    /// signing with the wrong algorithm (the Python SDK silently emits an
    /// empty MAC). The enum makes an unsupported type unrepresentable at
    /// the hashing call itself, so the rejection lives at the conversion
    /// boundary — and generate_check_value still surfaces it end to end.
    #[test]
    fn unsupported_encrypt_types_are_rejected(
        params in params_strategy(),
        t in -100i64..100
    ) {
        prop_assume!(t != 0 && t != 1);
        let got = ecpay::EncryptType::try_from(t);
        prop_assert!(matches!(got, Err(ecpay::Error::UnsupportedEncryptType(_))));
        let mut params = params;
        params.insert("EncryptType".to_owned(), t.to_string());
        let client = ecpay::Ecpay {
            merchant_id: "3002607".into(),
            hash_key: KEY.to_owned(),
            hash_iv: IV.to_owned(),
            ..Default::default()
        };
        let got = client.generate_check_value(&params);
        prop_assert!(matches!(got, Err(ecpay::Error::UnsupportedEncryptType(_))));
    }
}

/// The exhaustive single-byte table: every ASCII byte 0x00–0x7F one at a
/// time (multi-byte UTF-8 is covered by the arbitrary-text property).
#[test]
fn url_encode_exhaustive_ascii_byte_table() {
    for b in 0u8..=0x7f {
        let input = (b as char).to_string();
        let expected = match b {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'*'
            | b'('
            | b')' => input.clone(),
            b' ' => "+".to_owned(),
            _ => format!("%{b:02x}"),
        };
        assert_eq!(url_encode(&input), expected, "byte 0x{b:02x}");
    }
}
