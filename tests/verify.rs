//! Port of Go `verify_test.go`: VerifyCheckMacValue, including ECPay's own
//! published payment-callback signature.

use std::collections::HashMap;

use ecpay::{check_mac_value, hash_mac, Ecpay};

fn test_payment_ecpay(base_url: &str) -> Ecpay {
    Ecpay {
        merchant_id: "2000132".to_owned(),
        hash_key: "5294y06JbISpM5x9".to_owned(),
        hash_iv: "v77hoKGq4kWxNNIS".to_owned(),
        payment_api_url: base_url.to_owned(),
        ..Default::default()
    }
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn test_verify_check_mac_value() {
    let ec = test_payment_ecpay("");
    let base = map(&[
        ("MerchantID", "3002607"),
        ("MerchantTradeNo", "Test1234567890"),
        ("RtnCode", "1"),
        ("TradeAmt", "100"),
        ("PaymentDate", "2025/01/01 12:05:00"),
    ]);
    let mac = hash_mac(&base, &ec.hash_key, &ec.hash_iv);

    let with_mac = |extra: &[(&str, &str)]| {
        let mut m = base.clone();
        m.insert("CheckMacValue".to_owned(), mac.clone());
        for (k, v) in extra {
            m.insert(k.to_string(), v.to_string());
        }
        m
    };

    assert!(
        ec.verify_check_mac_value(&with_mac(&[])),
        "a correctly-signed callback must verify"
    );

    // Tampered amount -> recomputed MAC differs -> reject.
    assert!(
        !ec.verify_check_mac_value(&with_mac(&[("TradeAmt", "999")])),
        "a tampered TradeAmt must fail verification"
    );

    // Missing CheckMacValue -> reject.
    assert!(
        !ec.verify_check_mac_value(&base),
        "a callback with no CheckMacValue must fail verification"
    );

    // Empty CheckMacValue -> reject.
    assert!(
        !ec.verify_check_mac_value(&with_mac(&[("CheckMacValue", "")])),
        "an empty CheckMacValue must fail verification"
    );

    // A lowercase CheckMacValue still verifies (defensive upper-casing).
    let lower = with_mac(&[("CheckMacValue", &mac.to_lowercase())]);
    assert!(
        ec.verify_check_mac_value(&lower),
        "a lowercase-hex CheckMacValue should still verify"
    );

    // An extra field ECPay added (e.g. SimulatePaid) is part of the MAC, so a
    // value computed without it must NOT validate against the fuller set.
    assert!(
        !ec.verify_check_mac_value(&with_mac(&[("SimulatePaid", "0")])),
        "an unsigned extra field must change the recomputed MAC and fail"
    );
}

/// TestVerifyCheckMacValueOfficialCallback feeds ECPay's OWN published
/// callback signature through VerifyCheckMacValue. Passing proves the inbound
/// CheckMacValue check accepts a genuine ECPay-computed callback MAC.
#[test]
fn test_verify_check_mac_value_official_callback() {
    let ec = Ecpay {
        hash_key: "pwFHCqoQZGmho4w6".to_owned(),
        hash_iv: "EkRm7iFT261dpevs".to_owned(),
        ..Default::default()
    };
    let mut params = map(&[
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
        (
            "CheckMacValue",
            "2AB536D86AFF8E1086744D59175040A32538C96B1C28C4135B551BD728E913B8",
        ),
    ]);
    assert!(
        ec.verify_check_mac_value(&params),
        "VerifyCheckMacValue must accept ECPay's official payment-callback signature"
    );
    // Flip one signed field: the official MAC must no longer validate.
    params.insert("TradeAmt".to_owned(), "1".to_owned());
    assert!(
        !ec.verify_check_mac_value(&params),
        "tampering a signed field must invalidate the official MAC"
    );
}

/// A client whose HashKey/HashIV were never configured must not "verify" a
/// MAC computed over the empty-key preimage: whoever knows the param set can
/// produce that exact MAC, so accepting it turns an unconfigured client into
/// a forged-callback oracle (a real ECPay callback would fail either way —
/// this guards the attacker-crafted direction).
#[test]
fn empty_key_client_rejects_empty_key_forged_mac() {
    let ec = Ecpay {
        merchant_id: "2000132".to_owned(),
        ..Default::default()
    };
    assert!(ec.hash_key.is_empty() && ec.hash_iv.is_empty());
    let mut params = map(&[
        ("MerchantID", "2000132"),
        ("MerchantTradeNo", "Test1234567890"),
        ("RtnCode", "1"),
        ("TradeAmt", "100"),
    ]);
    let forged = check_mac_value(&params, "", "", ecpay::EncryptType::Sha256);
    params.insert("CheckMacValue".to_owned(), forged);
    assert!(
        !ec.verify_check_mac_value(&params),
        "an empty-key client must reject a MAC computed with the same empty keys"
    );
}
