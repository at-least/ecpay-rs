//! Port of Go `aes_vectors_test.go`: the official ECPay AES test vectors
//! (AES-128-CBC), pinned byte-exact. Flow: JSON -> URL encode (PHP urlencode:
//! uppercase hex, space->+, ~->%7E) -> AES-128-CBC/PKCS7 -> base64. The
//! e-invoice account (ejCk326UnaZWKisg / q9jcZX8Ib9LM8wYk) and the ECPG
//! payment account (pwFHCqoQZGmho4w6 / EkRm7iFT261dpevs) share the same AES
//! flow, so both are pinned here.

use serde::Serialize;

use ecpay::{decrypt, decrypt_data, encrypt, encrypt_data};

const INV_KEY: &[u8] = b"ejCk326UnaZWKisg";
const INV_IV: &[u8] = b"q9jcZX8Ib9LM8wYk";
const ECG_KEY: &[u8] = b"pwFHCqoQZGmho4w6";
const ECG_IV: &[u8] = b"EkRm7iFT261dpevs";

struct PrimitiveVector {
    name: &'static str,
    key: &'static [u8],
    iv: &'static [u8],
    url_encoded: &'static str,
    want: &'static str,
}

/// TestEncryptOfficialVectors pins the AES-128-CBC/PKCS7/base64 primitive: the
/// already-url-encoded plaintext must encrypt to ECPay's published ciphertext.
#[test]
fn test_encrypt_official_vectors() {
    let tests = vec![
        PrimitiveVector {
            name: "insertion-order",
            key: INV_KEY,
            iv: INV_IV,
            url_encoded: "%7B%22MerchantID%22%3A%222000132%22%2C%22BarCode%22%3A%22%2F1234567%22%7D",
            want: "XeEOdHpTRvxKEqs/JD9RSd16s7VtpyWVCN6AV44pKTW3DVa6yI7vKmjBRp2eulDhXoru/qBqFDBH3fEqlkMn3bbJfJBfGAq+v+SvttutYnc=",
        },
        PrimitiveVector {
            // alphabetical-order JSON keys (Go map / Java HashMap form);
            // vector from ECPay's own AI-skill test-vectors/aes-encryption.json
            name: "alphabetical-order",
            key: INV_KEY,
            iv: INV_IV,
            url_encoded: "%7B%22BarCode%22%3A%22%2F1234567%22%2C%22MerchantID%22%3A%222000132%22%7D",
            want: "r0JSyF9wVmywUav725b3rdJs3xp/ekrC/7PGb18zhKyXkPsamV9l4rPnBkaaraPcHtMSwrmSPP3wuS7b8g/aAKGs0iGiknpgpbdXKXvFrYM=",
        },
        PrimitiveVector {
            // special chars: ! * ' ( ) ~
            name: "special-chars",
            key: INV_KEY,
            iv: INV_IV,
            url_encoded: "%7B%22Name%22%3A%22test%21%2A%27%28%29%7Evalue%22%7D",
            want: "uvI4yrErM37XNQkXGAgRgBuDOiJoVs72Xn/rum9Ejl1DSna4HyLSoY7764PmhTR7JXb9jJWLSjCGcZEDeFiABg==",
        },
        PrimitiveVector {
            // urlencoded len == 32 (2 blocks) -> full pad block
            name: "pkcs7-32-byte-boundary",
            key: INV_KEY,
            iv: INV_IV,
            url_encoded: "%7B%22N%22%3A%221234567890%22%7D",
            want: "gVwWJnIpl1m3ZDypcRAjiCctilYnQhHn4h8OzJP5IxQPov7HuysXX+jPONvrHS7Z",
        },
        PrimitiveVector {
            name: "ecpg-payment-account",
            key: ECG_KEY,
            iv: ECG_IV,
            url_encoded: "%7B%22MerchantID%22%3A%223002607%22%2C%22RespondType%22%3A%22JSON%22%7D",
            want: "udqjXgM+7Q6lCrrculcvzUFnN5zv0ibax1glKFxrORoO0sl6pcoib/QDYPKCAP57ME4+3Yo84XmyabVFnxriMTuy9JK/RXS7DtEOvF+PUoU=",
        },
    ];
    for tt in tests {
        let PrimitiveVector {
            name,
            key,
            iv,
            url_encoded,
            want,
        } = tt;
        let got =
            encrypt(url_encoded.as_bytes(), key, iv).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(got, want, "official vector {name}");
    }
}

/// TestDecryptOfficialVector is the reverse: ECPay's ciphertext decrypts back
/// to the url-encoded plaintext (the callback-decryption path).
#[test]
fn test_decrypt_official_vector() {
    const CIPHERTEXT: &str =
        "XeEOdHpTRvxKEqs/JD9RSd16s7VtpyWVCN6AV44pKTW3DVa6yI7vKmjBRp2eulDhXoru/qBqFDBH3fEqlkMn3bbJfJBfGAq+v+SvttutYnc=";
    const WANT: &str = "%7B%22MerchantID%22%3A%222000132%22%2C%22BarCode%22%3A%22%2F1234567%22%7D";
    let got = decrypt(CIPHERTEXT, INV_KEY, INV_IV).unwrap();
    assert_eq!(got, WANT);
}

// --- TestEncryptDataOfficialVectors: struct field order fixes JSON key order
// (serde, like Go's encoder, emits fields in declaration order). ---

#[derive(Serialize)]
struct BarcodeReq {
    #[serde(rename = "MerchantID")]
    merchant_id: String,
    #[serde(rename = "BarCode")]
    bar_code: String,
}

#[derive(Serialize)]
struct NameReq {
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Serialize)]
struct EcpgReq {
    #[serde(rename = "MerchantID")]
    merchant_id: String,
    #[serde(rename = "RespondType")]
    respond_type: String,
}

// alphaReq reproduces the alphabetic-key vector (BarCode first).
#[derive(Serialize)]
struct AlphaReq {
    #[serde(rename = "BarCode")]
    bar_code: String,
    #[serde(rename = "MerchantID")]
    merchant_id: String,
}

#[derive(Serialize)]
struct Utf8Req {
    #[serde(rename = "MerchantID")]
    merchant_id: String,
    #[serde(rename = "ItemName")]
    item_name: String,
}

/// TestEncryptDataOfficialVectors pins the full pipeline (JSON serialize ->
/// AES url-encode -> encrypt) to ECPay's published ciphertext, proving
/// EncryptData produces the canonical wire bytes — uppercase hex,
/// ! * ' ( ) ~ escaped, no HTML escaping.
#[test]
fn test_encrypt_data_official_vectors() {
    // insertion-order
    let got = encrypt_data(
        &BarcodeReq {
            merchant_id: "2000132".to_owned(),
            bar_code: "/1234567".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    assert_eq!(
        got,
        "XeEOdHpTRvxKEqs/JD9RSd16s7VtpyWVCN6AV44pKTW3DVa6yI7vKmjBRp2eulDhXoru/qBqFDBH3fEqlkMn3bbJfJBfGAq+v+SvttutYnc="
    );

    // special-chars
    let got = encrypt_data(
        &NameReq {
            name: "test!*'()~value".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    assert_eq!(
        got,
        "uvI4yrErM37XNQkXGAgRgBuDOiJoVs72Xn/rum9Ejl1DSna4HyLSoY7764PmhTR7JXb9jJWLSjCGcZEDeFiABg=="
    );

    // ecpg-account
    let got = encrypt_data(
        &EcpgReq {
            merchant_id: "3002607".to_owned(),
            respond_type: "JSON".to_owned(),
        },
        ECG_KEY,
        ECG_IV,
    )
    .unwrap();
    assert_eq!(
        got,
        "udqjXgM+7Q6lCrrculcvzUFnN5zv0ibax1glKFxrORoO0sl6pcoib/QDYPKCAP57ME4+3Yo84XmyabVFnxriMTuy9JK/RXS7DtEOvF+PUoU="
    );

    // alphabetic-key-order: different key order than insertion-order ->
    // different ciphertext.
    let got = encrypt_data(
        &AlphaReq {
            bar_code: "/1234567".to_owned(),
            merchant_id: "2000132".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    assert_eq!(
        got,
        "r0JSyF9wVmywUav725b3rdJs3xp/ekrC/7PGb18zhKyXkPsamV9l4rPnBkaaraPcHtMSwrmSPP3wuS7b8g/aAKGs0iGiknpgpbdXKXvFrYM="
    );

    // utf-8
    let got = encrypt_data(
        &Utf8Req {
            merchant_id: "2000132".to_owned(),
            item_name: "綠界科技測試商品".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    assert_eq!(
        got,
        "XeEOdHpTRvxKEqs/JD9RSd16s7VtpyWVCN6AV44pKTVKsXddZRgV+Cle9oeB2PqsEC2O0oDi4kObiCtdGznG9aAX69Kj0//VjGXhieBYZ3RuGW9v20xQyBevaBwtOvg1lYjlDw6jsgfToGMUvlGsIJ2DO6/tbXjNZumnRgj2GCSj7LLDRBU3KlkUWji16nO1"
    );
}

/// TestEncryptDataDecryptDataRealTypes round-trips the actual ECPay request
/// types the codebase sends (IssueInput, InvalidInput, GetIssueInput,
/// GetInvoiceWordSettingInput), including fields carrying special and
/// multibyte characters.
#[test]
fn test_encrypt_data_decrypt_data_real_types() {
    // IssueInput with special + UTF-8 fields
    let input = ecpay::IssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "ord_~!*()'".to_owned(),
        customer_name: "全部生命 A&B <Co> 測試".to_owned(),
        customer_email: "user+tag@example.com".to_owned(),
        sales_amount: 100,
        inv_type: "07".to_owned(),
        vat: "1".to_owned(),
        items: Some(vec![ecpay::Item {
            item_seq: 1,
            item_name: "唯識的每日靜心 ~v2".to_owned(),
            item_count: 1.0,
            item_word: "項".to_owned(),
            item_price: 100.0,
            item_tax_type: "1".to_owned(),
            item_amount: 100.0,
            ..Default::default()
        }]),
        ..Default::default()
    };
    let enc = encrypt_data(&input, INV_KEY, INV_IV).unwrap();
    let out: ecpay::IssueInput = decrypt_data(&enc, INV_KEY, INV_IV).unwrap();
    assert_eq!(out.relate_number, input.relate_number);
    assert_eq!(out.customer_name, input.customer_name);
    assert_eq!(out.customer_email, input.customer_email);
    assert_eq!(out.sales_amount, input.sales_amount);
    assert_eq!(out.items.as_ref().map(Vec::len), Some(1));
    assert_eq!(
        out.items.as_ref().unwrap()[0].item_name,
        "唯識的每日靜心 ~v2"
    );
    assert_eq!(out.items.as_ref().unwrap()[0].item_amount, 100.0);

    // InvalidInput
    let input = ecpay::InvalidInput {
        merchant_id: "2000132".to_owned(),
        invoice_no: "AB12345678".to_owned(),
        invoice_date: "2024-01-02".to_owned(),
        reason: "註銷訂單 ~ 測試".to_owned(),
    };
    let enc = encrypt_data(&input, INV_KEY, INV_IV).unwrap();
    let out: ecpay::InvalidInput = decrypt_data(&enc, INV_KEY, INV_IV).unwrap();
    assert_eq!(out.merchant_id, input.merchant_id);
    assert_eq!(out.invoice_no, input.invoice_no);
    assert_eq!(out.invoice_date, input.invoice_date);
    assert_eq!(out.reason, input.reason);

    // GetIssueInput
    let input = ecpay::GetIssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "order_001".to_owned(),
        ..Default::default()
    };
    let enc = encrypt_data(&input, INV_KEY, INV_IV).unwrap();
    let out: ecpay::GetIssueInput = decrypt_data(&enc, INV_KEY, INV_IV).unwrap();
    assert_eq!(out.merchant_id, input.merchant_id);
    assert_eq!(out.relate_number, input.relate_number);

    // GetInvoiceWordSettingInput
    let input = ecpay::GetInvoiceWordSettingInput {
        merchant_id: "2000132".to_owned(),
        invoice_year: "113".to_owned(),
        invoice_term: 0,
        invoice_category: 1,
        inv_type: "07".to_owned(),
        ..Default::default()
    };
    let enc = encrypt_data(&input, INV_KEY, INV_IV).unwrap();
    let out: ecpay::GetInvoiceWordSettingInput = decrypt_data(&enc, INV_KEY, INV_IV).unwrap();
    assert_eq!(out.merchant_id, input.merchant_id);
    assert_eq!(out.invoice_year, input.invoice_year);
    assert_eq!(out.invoice_term, input.invoice_term);
    assert_eq!(out.invoice_category, input.invoice_category);
    assert_eq!(out.inv_type, input.inv_type);
}

/// TestEncryptDataURLEncodingForm checks the intermediate url-encoding (via a
/// decrypt round-trip) against ECPay's expected_url_encoded — the
/// uppercase-hex, %21%2A%27%28%29%7E, literal-UTF-8 form. This is what
/// distinguishes the AES encoder from the CheckMacValue one.
#[test]
fn test_encrypt_data_url_encoding_form() {
    // special-chars uppercase + escaped
    let ct = encrypt_data(
        &NameReq {
            name: "test!*'()~value".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    let got = decrypt(&ct, INV_KEY, INV_IV).unwrap();
    assert_eq!(got, "%7B%22Name%22%3A%22test%21%2A%27%28%29%7Evalue%22%7D");

    // utf-8 literal bytes
    let ct = encrypt_data(
        &Utf8Req {
            merchant_id: "2000132".to_owned(),
            item_name: "綠界科技測試商品".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    let got = decrypt(&ct, INV_KEY, INV_IV).unwrap();
    assert_eq!(
        got,
        "%7B%22MerchantID%22%3A%222000132%22%2C%22ItemName%22%3A%22%E7%B6%A0%E7%95%8C%E7%A7%91%E6%8A%80%E6%B8%AC%E8%A9%A6%E5%95%86%E5%93%81%22%7D"
    );
}

/// TestEncryptDataNoHTMLEscape guards the SetEscapeHTML(false) requirement:
/// angle brackets and ampersand must survive as literal characters in the AES
/// payload (serialized by serde as literal bytes, then %-escaped by
/// aesURLEncode), not Go's default backslash-u escapes.
#[test]
fn test_encrypt_data_no_html_escape() {
    #[derive(Serialize)]
    struct Req {
        #[serde(rename = "Company")]
        company: String,
    }
    let ct = encrypt_data(
        &Req {
            company: "A&B <Co>".to_owned(),
        },
        INV_KEY,
        INV_IV,
    )
    .unwrap();
    let decoded = decrypt(&ct, INV_KEY, INV_IV).unwrap();
    // %26 = &, %3C = <, %3E = > ; the \u escapes must NOT appear.
    assert!(
        decoded.contains("%26") && decoded.contains("%3C") && decoded.contains("%3E"),
        "expected literal &<> (%26 %3C %3E) in payload, got {decoded:?}"
    );
    assert!(
        !decoded.to_lowercase().contains("u0026") && !decoded.to_lowercase().contains("u003c"),
        "HTML escaping leaked into the AES payload: {decoded:?}"
    );
}
