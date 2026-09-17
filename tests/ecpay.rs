//! Port of Go `ecpay_test.go`: HashMac/URLEncode oracle vectors (including the
//! exhaustive .NET contract sweep), Response envelope decoding with both
//! number- and string-typed PlatformID, the Encrypt/Decrypt vectors, and the
//! GetIssue typed decode tests.

use std::collections::HashMap;

use serde::Deserialize;

use ecpay::client::Response;
use ecpay::{
    decrypt, decrypt_data, encrypt, encrypt_data, hash_mac, url_encode, GetIssueInput,
    GetIssueOutput, IssueOutput, INVOICE_API_URL_PRODUCTION, INVOICE_API_URL_STAGE,
};

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn test_invoice_api_url() {
    assert_eq!(
        INVOICE_API_URL_PRODUCTION,
        "https://einvoice.ecpay.com.tw/B2CInvoice/"
    );
    assert_eq!(
        INVOICE_API_URL_STAGE,
        "https://einvoice-stage.ecpay.com.tw/B2CInvoice/"
    );
}

#[test]
fn test_hash_mac_sample() {
    let params = map(&[
        ("TradeDesc", "促銷方案"),
        ("PaymentType", "aio"),
        ("MerchantTradeDate", "2013/03/12 15:30:23"),
        ("MerchantTradeNo", "ecpay20130312153023"),
        ("MerchantID", "2000132"),
        ("ReturnURL", "https://www.ecpay.com.tw/receive.php"),
        ("ItemName", "Apple iphone 7 手機殼"),
        ("TotalAmount", "1000"),
        ("ChoosePayment", "ALL"),
        ("EncryptType", "1"),
    ]);
    let mac = hash_mac(&params, "5294y06JbISpM5x9", "v77hoKGq4kWxNNIS");
    assert_eq!(
        mac,
        "CFA9BDE377361FBDD8F160274930E815D1A8A2E3E80CE7D404C45FC9A0A1E407"
    );
}

/// dotNetURLEncode mirrors .NET HttpUtility.UrlEncode — the exact contract
/// ECPay computes CheckMacValue against. The only unescaped characters are
/// alphanumerics and - _ . ! * ( ) (.NET's IsUrlSafeChar set); space becomes
/// +; every other byte (including ~ and each UTF-8 byte) becomes a lowercase
/// %xx escape. It is the reference URLEncode must match.
fn dot_net_url_encode(s: &str) -> String {
    const SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!*()";
    let mut b = String::new();
    for c in s.bytes() {
        match c {
            _ if SAFE.contains(&c) => b.push(c as char),
            b' ' => b.push('+'),
            _ => b.push_str(&format!("%{:02x}", c)),
        }
    }
    b
}

#[test]
fn test_url_encode() {
    let tests: Vec<(&str, &str)> = vec![
        // unescaped (.NET IsUrlSafeChar)
        ("a", "a"),
        ("z", "z"),
        ("A", "A"),
        ("Z", "Z"),
        ("0", "0"),
        ("9", "9"),
        ("-", "-"),
        ("_", "_"),
        (".", "."),
        ("!", "!"),
        ("*", "*"),
        ("(", "("),
        (")", ")"),
        // space is special
        (" ", "+"),
        // the fix: Go leaves ~ literal, .NET escapes it
        ("~", "%7e"),
        ("a~b", "a%7eb"),
        // everything else -> lowercase %xx
        ("\"", "%22"),
        ("#", "%23"),
        ("$", "%24"),
        ("%", "%25"),
        ("&", "%26"),
        ("'", "%27"),
        ("+", "%2b"),
        (",", "%2c"),
        ("/", "%2f"),
        (":", "%3a"),
        (";", "%3b"),
        ("<", "%3c"),
        ("=", "%3d"),
        (">", "%3e"),
        ("?", "%3f"),
        ("@", "%40"),
        ("[", "%5b"),
        ("\\", "%5c"),
        ("]", "%5d"),
        ("^", "%5e"),
        ("`", "%60"),
        ("{", "%7b"),
        ("|", "%7c"),
        ("}", "%7d"),
        // UTF-8 is escaped byte-by-byte in lowercase hex
        ("測", "%e6%b8%ac"),
        ("k=v", "k%3dv"),
    ];
    for (input, want) in tests {
        assert_eq!(url_encode(input), want, "URLEncode({input:?}) mismatch");
    }
}

/// TestURLEncodeMatchesDotNetContract is the exhaustive check: URLEncode must
/// equal the .NET reference for EVERY printable-ASCII byte and for
/// representative UTF-8 / real-world strings.
#[test]
fn test_url_encode_matches_dot_net_contract() {
    let mut samples: Vec<String> = Vec::new();
    for c in 0x20u8..=0x7e {
        samples.push((c as char).to_string()); // every printable ASCII byte, one at a time
    }
    samples.extend([
        " !\"#$%&'()*+,-./0123456789:;<=>?@ABCXYZ[\\]^_`abcxyz{|}~".to_owned(), // all classes mixed
        "測試商品".to_owned(),
        "新春~好禮".to_owned(),
        "Tom's Shop".to_owned(),
        "Test~Product".to_owned(),
        "a b+c=d".to_owned(),
        "https://store.totality-of-life.com/ecpay/return".to_owned(),
        "全部生命APP系統 $500".to_owned(),
    ]);
    for s in &samples {
        assert_eq!(
            url_encode(s),
            dot_net_url_encode(s),
            "URLEncode({s:?}) != the .NET contract"
        );
    }
}

/// TestHashMacOfficialVectors checks HashMac against ECPay's published
/// CheckMacValue test vectors (SHA256 / AIO payment account 3002607).
#[test]
fn test_hash_mac_official_vectors() {
    const KEY: &str = "pwFHCqoQZGmho4w6";
    const IV: &str = "EkRm7iFT261dpevs";
    let tests: Vec<(&str, HashMap<String, String>, &str)> = vec![
        (
            "basic AIO",
            map(&[
                ("MerchantID", "3002607"),
                ("MerchantTradeNo", "Test1234567890"),
                ("MerchantTradeDate", "2025/01/01 12:00:00"),
                ("PaymentType", "aio"),
                ("TotalAmount", "100"),
                ("TradeDesc", "測試"),
                ("ItemName", "測試商品"),
                ("ReturnURL", "https://example.com/notify"),
                ("ChoosePayment", "ALL"),
                ("EncryptType", "1"),
            ]),
            "291CBA324D31FB5A4BBBFDF2CFE5D32598524753AFD4959C3BF590C5B2F57FB2",
        ),
        (
            "apostrophe",
            map(&[
                ("MerchantID", "3002607"),
                ("ItemName", "Tom's Shop"),
                ("TotalAmount", "100"),
            ]),
            "CF0A3D4901D99459D8641516EC57210700E8A5C9AB26B1D021301E9CB93EF78D",
        ),
        (
            "tilde",
            map(&[
                ("MerchantID", "3002607"),
                ("ItemName", "Test~Product"),
                ("TotalAmount", "200"),
            ]),
            "CEEAE01D2F9A8E74D4AC0DCE7735B046D73F35A5EC99558A31A2EE03159DA1C9",
        ),
        (
            "space becomes plus",
            map(&[
                ("MerchantID", "3002607"),
                ("ItemName", "My Test Product"),
                ("TotalAmount", "300"),
            ]),
            "7712A5E6EDC3B57086063C88568084C66CE882A21D40E74DE5ACA3B478C6F316",
        ),
        (
            // Verifying a payment-completion callback: recompute the MAC over
            // every returned field except CheckMacValue and compare.
            "callback verification",
            map(&[
                ("MerchantID", "3002607"),
                ("MerchantTradeNo", "Test1234567890"),
                ("RtnCode", "1"),
                ("RtnMsg", "Succeeded"),
                ("TradeNo", "2301011234567890"),
                ("TradeAmt", "100"),
                ("PaymentDate", "2025/01/01 12:05:00"),
                ("PaymentType", "Credit_CreditCard"),
                ("TradeDate", "2025/01/01 12:00:00"),
                ("SimulatePaid", "0"),
            ]),
            "2AB536D86AFF8E1086744D59175040A32538C96B1C28C4135B551BD728E913B8",
        ),
    ];
    for (name, params, want) in tests {
        assert_eq!(
            hash_mac(&params, KEY, IV),
            want,
            "official HashMac vector {name}"
        );
    }
}

#[test]
fn test_response_decode_number_platform_id() {
    // ECPay 回傳 PlatformID/MerchantID 為數字
    let raw = r#"{"PlatformID":0,"MerchantID":2000132,"RqHeader":{"Timestamp":1},"TransCode":1,"TransMsg":"OK","Data":"abc"}"#;
    let res: Response = serde_json::from_str(raw).expect("unmarshal number PlatformID");
    assert_eq!(res.trans_code, 1);
}

#[test]
fn test_response_decode_string_platform_id() {
    // PlatformID/MerchantID 為字串的情境
    let raw = r#"{"PlatformID":"3002607","MerchantID":"2000132","RqHeader":{"Timestamp":1},"TransCode":1,"TransMsg":"OK","Data":"abc"}"#;
    let res: Response = serde_json::from_str(raw).expect("unmarshal string PlatformID");
    assert_eq!(res.trans_code, 1);
}

#[test]
fn test_response_decode_null_fields_are_zero_values() {
    // Envelope level: Go json.NewDecoder maps null to the zero value
    // (TransMsg "", Data "" → a clean decrypt error downstream, not a parse
    // error); serde would fail the whole decode on the first null.
    let raw = r#"{"PlatformID":null,"MerchantID":null,"RqHeader":null,"TransCode":1,"TransMsg":null,"Data":null}"#;
    let res: Response = ecpay::unmarshal(raw).expect("unmarshal null fields");
    assert_eq!(res.trans_code, 1);
    assert_eq!(res.trans_msg, "");
    assert_eq!(res.data, "");
    assert!(res.platform_id.is_null());
    assert_eq!(res.rq_header.timestamp, 0);
}

#[test]
fn test_decrypt_data_null_fields_are_zero_values() {
    // Go's json.Unmarshal decodes JSON null into the zero value for every
    // field type; serde errors on an explicit null for String/i64 fields.
    // This is the decrypted Data payload of a TransCode=1 envelope.
    let payload =
        r#"{"RtnCode":1,"RtnMsg":null,"InvoiceNo":null,"InvoiceDate":null,"RandomNumber":null}"#;
    let encrypted = encrypt(payload.as_bytes(), b"A123456789012345", b"B123456789012345").unwrap();
    let out: IssueOutput =
        decrypt_data(&encrypted, b"A123456789012345", b"B123456789012345").unwrap();
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.rtn_msg, "");
    assert_eq!(out.invoice_no, "");
    assert_eq!(out.invoice_date, "");
    assert_eq!(out.random_number, "");
}

#[test]
fn test_encrypt() {
    let raw = b"%7B%22Name%22%3A%22Test%22%2C%22ID%22%3A%22A123456789%22%7D";
    let want =
        "7woM9RorZKAtXJRVccAb0qhHYm+5lnlhBzyfh5EZdNck7PacNsRHgv/Jvp//ajJidqcQcs0UmAgPQVjXQHeziw==";
    let got = encrypt(raw, b"A123456789012345", b"B123456789012345").unwrap();
    assert_eq!(got, want);
}

#[test]
fn test_decrypt() {
    let encrypted =
        "7woM9RorZKAtXJRVccAb0qhHYm+5lnlhBzyfh5EZdNck7PacNsRHgv/Jvp//ajJidqcQcs0UmAgPQVjXQHeziw==";
    let want = "%7B%22Name%22%3A%22Test%22%2C%22ID%22%3A%22A123456789%22%7D";
    let got = decrypt(encrypted, b"A123456789012345", b"B123456789012345").unwrap();
    assert_eq!(got, want);
}

#[test]
fn test_unmarshal_strips_nulls_inside_array_elements() {
    // ECPay's GetIssue reply carries Items whose optional members can be
    // null; Go zero-values them and so must the recursive strip.
    let raw = r#"{"RtnCode":1,"Items":[{"ItemSeq":1,"ItemName":"x","ItemRemark":null,"ItemWord":null}],"IIS_Number":null}"#;
    let out: GetIssueOutput = ecpay::unmarshal(raw).expect("unmarshal nested nulls");
    let items = out.items.expect("Items present");
    assert_eq!(items[0].item_name, "x");
    assert_eq!(items[0].item_remark, "");
    assert_eq!(items[0].item_word, "");
    assert_eq!(out.iis_number, "");

    // A null Items array itself is None (Go nil slice), and serde's strict
    // path would have rejected the nested nulls outright.
    let out: GetIssueOutput = ecpay::unmarshal(r#"{"RtnCode":1,"Items":null}"#).unwrap();
    assert!(out.items.is_none());
    assert!(
        serde_json::from_str::<GetIssueOutput>(raw).is_err(),
        "sanity: without the strip, a null String member fails to decode"
    );
}

#[test]
fn test_get_issue_output_unmarshal() {
    // 模擬 ECPay GetIssue 回傳的 JSON（解密後）
    let raw = r#"{
        "RtnCode": 1,
        "RtnMsg": "查詢發票成功",
        "IIS_Mer_ID": "2000132",
        "IIS_Number": "AA12345678",
        "IIS_Relate_Number": "order_001",
        "IIS_Create_Date": "2025-01-15 10:30:00",
        "IIS_Award_Flag": "",
        "IIS_Invalid_Status": "0",
        "IIS_Upload_Status": "1",
        "IIS_Sales_Amount": 500,
        "IIS_Issue_Status": "1",
        "IIS_Category": "B2C"
    }"#;
    let out: GetIssueOutput = serde_json::from_str(raw).expect("unmarshal");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.rtn_msg, "查詢發票成功");
    assert_eq!(out.iis_number, "AA12345678");
    assert_eq!(out.iis_relate_number, "order_001");
    assert_eq!(out.iis_create_date, "2025-01-15 10:30:00");
}

#[test]
fn test_get_issue_output_unmarshal_inconsistent_types() {
    // ECPay 有時回傳數字有時回傳字串，確認 any 欄位能接住兩種
    let raw = r#"{
        "RtnCode": 1,
        "RtnMsg": "查詢發票成功",
        "IIS_Mer_ID": 2000132,
        "IIS_Number": "AA12345678",
        "IIS_Relate_Number": "order_002",
        "IIS_Create_Date": "2025-01-15 10:30:00",
        "IIS_Award_Flag": 0,
        "IIS_Invalid_Status": 0,
        "IIS_Upload_Status": 1,
        "IIS_Sales_Amount": "500",
        "IIS_Issue_Status": 1,
        "IIS_Category": "B2C"
    }"#;
    let out: GetIssueOutput = serde_json::from_str(raw).expect("unmarshal inconsistent types");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.iis_number, "AA12345678");
    assert_eq!(out.iis_create_date, "2025-01-15 10:30:00");
}

#[derive(Debug, Deserialize, PartialEq)]
struct GetIssueInputDecoded {
    #[serde(rename = "MerchantID")]
    merchant_id: String,
    #[serde(rename = "RelateNumber")]
    relate_number: String,
}

#[test]
fn test_get_issue_input_encrypt_decrypt_round_trip() {
    let hash_key = b"ejCk326UnaZWKisg";
    let hash_iv = b"q9jcZX8Ib9LM8wYk";

    let input = GetIssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "order_001".to_owned(),
        ..Default::default()
    };
    let encrypted = encrypt_data(&input, hash_key, hash_iv).expect("encrypt");

    let decoded: GetIssueInputDecoded =
        decrypt_data(&encrypted, hash_key, hash_iv).expect("decrypt");
    assert_eq!(
        decoded,
        GetIssueInputDecoded {
            merchant_id: input.merchant_id.clone(),
            relate_number: input.relate_number.clone(),
        }
    );
}

/// `Ecpay::stage` must set EVERY service base URL to its stage endpoint in
/// one call: a partially-configured stage client silently falls back to the
/// PRODUCTION endpoints field by field, which is how signed production
/// traffic gets sent by mistake. All eight URL fields (plus the credentials)
/// are asserted here; the constructor itself builds the struct field-by-field
/// without `..Default::default()`, so a future URL field added to `Ecpay`
/// breaks its compilation until it gains a stage entry — this test pins the
/// eight that exist today.
#[test]
fn stage_constructor_sets_every_base_url_to_its_stage_endpoint() {
    use ecpay::Ecpay;
    use ecpay::{
        B2B_INVOICE_API_URL_STAGE, CREDIT_API_URL_STAGE, ECPAYMENT_API_URL_STAGE,
        ECPG_API_URL_STAGE, LOGISTICS_API_URL_STAGE, PAYMENT_API_URL_STAGE, VENDOR_API_URL_STAGE,
    };
    let client = Ecpay::stage("3002607", "pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs");
    assert_eq!(client.merchant_id, "3002607");
    assert_eq!(client.hash_key, "pwFHCqoQZGmho4w6");
    assert_eq!(client.hash_iv, "EkRm7iFT261dpevs");
    assert_eq!(client.payment_api_url, PAYMENT_API_URL_STAGE);
    assert_eq!(client.invoice_api_url, INVOICE_API_URL_STAGE);
    assert_eq!(client.b2b_invoice_api_url, B2B_INVOICE_API_URL_STAGE);
    assert_eq!(client.logistics_api_url, LOGISTICS_API_URL_STAGE);
    assert_eq!(client.ecpg_api_url, ECPG_API_URL_STAGE);
    assert_eq!(client.ecpayment_api_url, ECPAYMENT_API_URL_STAGE);
    assert_eq!(client.credit_api_url, CREDIT_API_URL_STAGE);
    assert_eq!(client.vendor_api_url, VENDOR_API_URL_STAGE);
    assert_eq!(
        client.credit_api_url, "https://payment-stage.ecpay.com.tw/CreditDetail/",
        "the CreditDetail stage base shares the payment stage host"
    );
    assert_eq!(
        client.vendor_api_url, "https://vendor-stage.ecpay.com.tw/PaymentMedia/",
        "the vendor stage base is the stage 特店後台 host"
    );
}
