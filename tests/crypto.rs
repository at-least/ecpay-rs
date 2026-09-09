//! Port of Go `crypto_test.go`: the AES-CBC/PKCS7 encrypt/decrypt primitive,
//! its error branches, and the EncryptData/DecryptData pipeline round-trips.

use std::collections::HashMap;

use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use base64::Engine;
use serde::{Deserialize, Serialize};

use ecpay::{decrypt, decrypt_data, encrypt, encrypt_data};

const CRYPTO_KEY: &[u8] = b"A123456789012345";
const CRYPTO_IV: &[u8] = b"B123456789012345";

#[test]
fn test_encrypt_decrypt_round_trip() {
    let long = "x".repeat(100);
    let cases = vec![
        "",                  // empty -> a full block of padding (padding == blockSize)
        "a",                 // 1 byte
        "012345678901234",   // 15 bytes -> 1 pad byte
        "0123456789012345",  // exactly one block -> a second full pad block
        "01234567890123456", // 17 bytes
        "中文與符號 %&=+/",  // multibyte
        long.as_str(),       // long
    ];
    for input in cases {
        let enc = encrypt(input.as_bytes(), CRYPTO_KEY, CRYPTO_IV)
            .unwrap_or_else(|e| panic!("Encrypt({input:?}): {e}"));
        let got = decrypt(&enc, CRYPTO_KEY, CRYPTO_IV)
            .unwrap_or_else(|e| panic!("Decrypt({input:?}): {e}"));
        assert_eq!(got, input, "round trip of {input:?} changed the value");
    }
}

#[test]
fn test_encrypt_bad_key_length() {
    assert!(
        encrypt(b"data", b"too-short", CRYPTO_IV).is_err(),
        "Encrypt with a non-16/24/32-byte key should error"
    );
}

#[test]
fn test_encrypt_bad_iv_length() {
    // A wrong-length IV must surface as an error, never a panic.
    assert!(
        encrypt(b"data", CRYPTO_KEY, b"short").is_err(),
        "Encrypt with a non-block-size IV should error"
    );
}

#[test]
fn test_decrypt_bad_iv_length() {
    // Build a valid one-block ciphertext, then decrypt it with a wrong-length IV.
    let ct = encrypt(b"data", CRYPTO_KEY, CRYPTO_IV).unwrap();
    assert!(
        decrypt(&ct, CRYPTO_KEY, b"short").is_err(),
        "Decrypt with a non-block-size IV should error"
    );
}

#[test]
fn test_decrypt_invalid_base64() {
    assert!(
        decrypt("not!base64!!", CRYPTO_KEY, CRYPTO_IV).is_err(),
        "Decrypt of non-base64 input should error"
    );
}

#[test]
fn test_decrypt_bad_key_length() {
    // Valid base64 of a 16-byte block, but the key length is invalid.
    let ct = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    assert!(
        decrypt(&ct, b"short", CRYPTO_IV).is_err(),
        "Decrypt with a non-16/24/32-byte key should error"
    );
}

#[test]
fn test_decrypt_non_block_multiple_length() {
    // 7 bytes is not a multiple of the AES block size (16).
    let ct = base64::engine::general_purpose::STANDARD.encode([0u8; 7]);
    assert!(
        decrypt(&ct, CRYPTO_KEY, CRYPTO_IV).is_err(),
        "Decrypt of a ciphertext whose length is not a block multiple should error"
    );
}

#[test]
fn test_decrypt_empty_ciphertext() {
    // Empty base64 decodes to zero bytes -> rejected as an invalid length.
    assert!(
        decrypt("", CRYPTO_KEY, CRYPTO_IV).is_err(),
        "Decrypt of empty ciphertext should error"
    );
}

/// rawCBCEncrypt encrypts exactly one block of plaintext with no PKCS7
/// padding, so a test can craft a ciphertext that decrypts to deliberately
/// malformed padding and drive the unpad rejection branches through Decrypt.
fn raw_cbc_encrypt(plain: &[u8; 16]) -> String {
    type Aes128 = aes::Aes128;
    let cipher = Aes128::new_from_slice(CRYPTO_KEY).unwrap();
    let mut plain = *plain;
    let block: &mut Block<Aes128> = plain.as_mut_slice().try_into().unwrap();
    cipher.encrypt_block(block);
    base64::engine::general_purpose::STANDARD.encode(block)
}

#[test]
fn test_decrypt_invalid_padding_value() {
    // Last byte 0x00 is an invalid PKCS7 pad count.
    let block = [0u8; 16]; // all zero -> trailing byte 0
    assert!(
        decrypt(&raw_cbc_encrypt(&block), CRYPTO_KEY, CRYPTO_IV).is_err(),
        "Decrypt should reject a zero padding value"
    );

    // Last byte 0x20 (32) exceeds the AES block size -> invalid.
    let mut block2 = [0u8; 16];
    block2[15] = 0x20;
    assert!(
        decrypt(&raw_cbc_encrypt(&block2), CRYPTO_KEY, CRYPTO_IV).is_err(),
        "Decrypt should reject a padding value larger than the block size"
    );
}

#[test]
fn test_decrypt_invalid_padding_bytes() {
    // Claims 3 padding bytes but the preceding bytes are not all 0x03.
    let mut block = [0u8; 16];
    block[15] = 0x03;
    block[14] = 0x03;
    block[13] = 0x01; // wrong
    assert!(
        decrypt(&raw_cbc_encrypt(&block), CRYPTO_KEY, CRYPTO_IV).is_err(),
        "Decrypt should reject inconsistent PKCS7 padding bytes"
    );
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
struct Payload {
    merchant_id: String,
    amount: i64,
    note: String,
}

#[test]
fn test_encrypt_data_decrypt_data_round_trip() {
    let input = Payload {
        merchant_id: "2000132".to_owned(),
        amount: 100,
        note: "中文 %&=+".to_owned(),
    };
    let enc = encrypt_data(&input, CRYPTO_KEY, CRYPTO_IV).expect("EncryptData");
    let out: Payload = decrypt_data(&enc, CRYPTO_KEY, CRYPTO_IV).expect("DecryptData");
    assert_eq!(out, input, "round trip changed the payload");
}

#[test]
fn test_encrypt_data_unserializable_value() {
    // A tuple cannot be a JSON map key, so EncryptData must surface the
    // serialization error (Go: a channel cannot be marshaled).
    let mut m = HashMap::new();
    m.insert((1, 2), 3);
    assert!(
        encrypt_data(&m, CRYPTO_KEY, CRYPTO_IV).is_err(),
        "EncryptData of an unserializable value should error"
    );
}

#[test]
fn test_decrypt_data_decrypt_error() {
    let result: Result<HashMap<String, serde_json::Value>, _> =
        decrypt_data("not!base64!!", CRYPTO_KEY, CRYPTO_IV);
    assert!(
        result.is_err(),
        "DecryptData should propagate a Decrypt error"
    );
}

#[test]
fn test_decrypt_data_invalid_url_escaping() {
    // The decrypted payload is URL-unescaped before JSON parsing; a bad percent
    // escape must surface as an error rather than a panic.
    let enc = encrypt(b"%zz", CRYPTO_KEY, CRYPTO_IV).unwrap();
    let result: Result<HashMap<String, serde_json::Value>, _> =
        decrypt_data(&enc, CRYPTO_KEY, CRYPTO_IV);
    assert!(
        result.is_err(),
        "DecryptData should error when the decrypted payload has invalid URL escaping"
    );
}

#[test]
fn test_decrypt_data_invalid_json() {
    // Encrypt a payload that is valid (URL-escaped) text but not valid JSON, so
    // the final JSON parse inside DecryptData fails.
    let enc = encrypt(b"not-json", CRYPTO_KEY, CRYPTO_IV).unwrap();
    let result: Result<HashMap<String, serde_json::Value>, _> =
        decrypt_data(&enc, CRYPTO_KEY, CRYPTO_IV);
    assert!(
        result.is_err(),
        "DecryptData should error when the decrypted payload is not JSON"
    );
}
