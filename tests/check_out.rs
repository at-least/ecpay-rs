//! `aio_check_out` builder behavior the Python-SDK fixtures do not reach:
//! HTML escaping in the auto-submit form, the InvoiceMark rules, the
//! group-membership rejections, the remaining `validate_invoice` branches,
//! the filter-stage rules for optional ints, and the endpoint default.

use std::collections::BTreeMap;

use ecpay::payment::{
    reply_payment_type, union_pay, AioCheckOutParams, CarruerType, ChoosePayment, Donation,
    InvType, InvoiceExtend, PrintMark, TaxType,
};
use ecpay::{Ecpay, Error, PAYMENT_API_URL_PRODUCTION, PAYMENT_API_URL_STAGE};

fn sdk() -> Ecpay {
    Ecpay {
        merchant_id: "3002607".into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        ..Default::default()
    }
}

fn base(choose_payment: ChoosePayment) -> AioCheckOutParams {
    AioCheckOutParams {
        merchant_trade_no: "NO20240101120000".into(),
        merchant_trade_date: "2024/01/01 12:00:00".into(),
        total_amount: 100,
        trade_desc: "desc".into(),
        item_name: "item".into(),
        return_url: "https://example.com/return".into(),
        choose_payment,
        ..Default::default()
    }
}

/// A valid invoice block (Print=0, no donation, phone given).
fn invoice() -> InvoiceExtend {
    InvoiceExtend {
        relate_number: "R1".into(),
        customer_phone: Some("0912345678".into()),
        tax_type: TaxType::Dutiable,
        donation: Donation::No,
        print: PrintMark::No,
        invoice_item_name: "商品".into(),
        invoice_item_count: "1".into(),
        invoice_item_word: "個".into(),
        invoice_item_price: "100".into(),
        delay_day: 0,
        inv_type: InvType::General,
        ..Default::default()
    }
}

fn param<'a>(out: &'a ecpay::AioCheckOut, key: &str) -> Option<&'a str> {
    out.params()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn validation(err: Error) -> String {
    match err {
        Error::Validation(m) => m,
        other => panic!("expected Error::Validation, got {other:?}"),
    }
}

// --- html_form ---

/// The official SDK interpolates values raw into the form, which breaks on
/// `"` and is an injection vector; ours escapes every attribute value.
#[test]
fn html_form_escapes_attribute_values() {
    let out = sdk()
        .aio_check_out(&AioCheckOutParams {
            trade_desc: r#"a"b&c<d>e'f"#.into(),
            item_name: "x\" onmouseover=\"alert(1)".into(),
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    let html = out.html_form();
    assert!(
        html.contains(r#"name="TradeDesc" value="a&quot;b&amp;c&lt;d&gt;e&#39;f""#),
        "{html}"
    );
    assert!(
        html.contains(r#"name="ItemName" value="x&quot; onmouseover=&quot;alert(1)""#),
        "{html}"
    );
    assert!(!html.contains("onmouseover=\"alert"), "{html}");
    // The action URL is escaped the same way.
    let out = Ecpay {
        payment_api_url: "https://x.example/?a=1&b=2\"".into(),
        ..sdk()
    }
    .aio_check_out(&base(ChoosePayment::Credit))
    .unwrap();
    assert!(
        out.html_form()
            .starts_with(r#"<form id="data_set" action="https://x.example/?a=1&amp;b=2&quot;AioCheckOut/V5" method="post">"#),
        "{}",
        out.html_form()
    );
}

/// Every signed parameter, including CheckMacValue, is a hidden input, in
/// key order, and the form auto-submits.
#[test]
fn html_form_carries_every_signed_param() {
    let out = sdk().aio_check_out(&base(ChoosePayment::Atm)).unwrap();
    let html = out.html_form();
    let mut last = 0;
    for (k, v) in out.params() {
        let input = format!(r#"<input type="hidden" name="{k}" value="{v}" />"#);
        let pos = html
            .find(&input)
            .unwrap_or_else(|| panic!("missing {input} in {html}"));
        assert!(pos >= last, "params must render in sorted order: {k}");
        last = pos;
    }
    assert!(html.contains(&format!(
        r#"name="CheckMacValue" value="{}""#,
        out.check_mac_value()
    )));
    assert!(html.ends_with(r#"<script type="text/javascript">document.getElementById("data_set").submit();</script></form>"#));
    assert_eq!(out.clone().into_pairs(), out.params().to_vec());
}

// --- endpoint ---

#[test]
fn action_follows_the_payment_api_url_and_defaults_to_production() {
    let out = sdk().aio_check_out(&base(ChoosePayment::Credit)).unwrap();
    assert_eq!(
        out.action(),
        format!("{PAYMENT_API_URL_PRODUCTION}AioCheckOut/V5")
    );
    assert_eq!(
        out.action(),
        "https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5"
    );
    let out = Ecpay {
        payment_api_url: PAYMENT_API_URL_STAGE.into(),
        ..sdk()
    }
    .aio_check_out(&base(ChoosePayment::Credit))
    .unwrap();
    assert_eq!(
        out.action(),
        "https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5"
    );
}

// --- required fields and the filter stage ---

#[test]
fn required_fields_and_lengths_are_enforced_with_the_sdk_messages() {
    let client = sdk();
    let cases: Vec<(AioCheckOutParams, &str)> = vec![
        (
            AioCheckOutParams {
                merchant_trade_date: String::new(),
                ..base(ChoosePayment::Credit)
            },
            "MerchantTradeDate content is required.",
        ),
        (
            AioCheckOutParams {
                trade_desc: String::new(),
                ..base(ChoosePayment::Credit)
            },
            "TradeDesc content is required.",
        ),
        (
            AioCheckOutParams {
                return_url: String::new(),
                ..base(ChoosePayment::Credit)
            },
            "ReturnURL content is required.",
        ),
        (
            AioCheckOutParams {
                trade_desc: "x".repeat(201),
                ..base(ChoosePayment::Credit)
            },
            "TradeDesc max langth is 200.",
        ),
        (
            AioCheckOutParams {
                store_id: Some("x".repeat(11)),
                ..base(ChoosePayment::Credit)
            },
            "StoreID max langth is 10.",
        ),
        (
            AioCheckOutParams {
                need_extra_paid_info: Some("YY".into()),
                ..base(ChoosePayment::Credit)
            },
            "NeedExtraPaidInfo max langth is 1.",
        ),
        (
            AioCheckOutParams {
                custom_field4: Some("x".repeat(51)),
                ..base(ChoosePayment::Credit)
            },
            "CustomField4 max langth is 50.",
        ),
        (
            AioCheckOutParams {
                invoice_mark: Some("YY".into()),
                ..base(ChoosePayment::Credit)
            },
            "InvoiceMark max langth is 1.",
        ),
    ];
    for (params, want) in cases {
        let got = validation(client.aio_check_out(&params).expect_err(want));
        assert_eq!(got, want);
    }
}

/// Python `len()` counts code points, not bytes: 20 CJK characters (60
/// bytes) fit a 20-char field, 21 do not.
#[test]
fn lengths_count_characters_not_bytes() {
    let client = sdk();
    client
        .aio_check_out(&AioCheckOutParams {
            merchant_trade_no: "單".repeat(20),
            ..base(ChoosePayment::Credit)
        })
        .expect("20 code points fit");
    let got = validation(
        client
            .aio_check_out(&AioCheckOutParams {
                merchant_trade_no: "單".repeat(21),
                ..base(ChoosePayment::Credit)
            })
            .expect_err("21 code points do not"),
    );
    assert_eq!(got, "MerchantTradeNo max langth is 20.");
}

/// filter_parameter: optional strings are dropped when empty, optional ints
/// when negative — `0` stays.
#[test]
fn optional_fields_follow_the_filter_stage() {
    let out = sdk()
        .aio_check_out(&AioCheckOutParams {
            store_id: Some(String::new()),
            remark: Some("note".into()),
            expire_date: Some(-1),
            ..base(ChoosePayment::Atm)
        })
        .unwrap();
    assert_eq!(
        param(&out, "StoreID"),
        None,
        "empty optional string dropped"
    );
    assert_eq!(param(&out, "Remark"), Some("note"));
    assert_eq!(param(&out, "ExpireDate"), None, "negative int dropped");

    let out = sdk()
        .aio_check_out(&AioCheckOutParams {
            expire_date: Some(0),
            ..base(ChoosePayment::Atm)
        })
        .unwrap();
    assert_eq!(param(&out, "ExpireDate"), Some("0"), "zero is kept");

    let out = sdk()
        .aio_check_out(&AioCheckOutParams {
            binding_card: Some(-1),
            union_pay: Some(-5),
            period_amount: None,
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    assert_eq!(param(&out, "BindingCard"), None);
    assert_eq!(param(&out, "UnionPay"), None);
}

#[test]
fn defaults_are_always_sent() {
    let out = sdk().aio_check_out(&base(ChoosePayment::Credit)).unwrap();
    assert_eq!(param(&out, "MerchantID"), Some("3002607"));
    assert_eq!(param(&out, "PaymentType"), Some("aio"));
    assert_eq!(param(&out, "EncryptType"), Some("1"));
    assert_eq!(param(&out, "ChoosePayment"), Some("Credit"));
    assert_eq!(param(&out, "TotalAmount"), Some("100"));
    assert_eq!(param(&out, "InvoiceMark"), None, "no invoice, no mark");
    assert_eq!(
        out.check_mac_value().len(),
        64,
        "SHA-256 (EncryptType=1) digest"
    );
    let md5 = sdk()
        .aio_check_out(&AioCheckOutParams {
            encrypt_type: 0,
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    assert_eq!(param(&md5, "EncryptType"), Some("0"));
    assert_eq!(
        md5.check_mac_value().len(),
        32,
        "MD5 (EncryptType=0) digest"
    );
}

// --- ChoosePayment groups ---

/// `ALL` activates every group at once: the ATM, CVS/BARCODE and Credit
/// extend fields all pass validation and all reach the wire.
#[test]
fn choose_payment_all_accepts_every_group() {
    let out = sdk()
        .aio_check_out(&AioCheckOutParams {
            expire_date: Some(3),
            payment_info_url: Some("https://x.example/info".into()),
            client_redirect_url: Some("https://x.example/back".into()),
            store_expire_date: Some(1440),
            desc_1: Some("d1".into()),
            desc_4: Some("d4".into()),
            binding_card: Some(1),
            merchant_member_id: Some("m1".into()),
            redeem: Some("Y".into()),
            union_pay: Some(union_pay::HIDDEN),
            language: Some("ENG".into()),
            ..base(ChoosePayment::All)
        })
        .expect("ALL accepts every group");
    for (k, v) in [
        ("ExpireDate", "3"),
        ("PaymentInfoURL", "https://x.example/info"),
        ("ClientRedirectURL", "https://x.example/back"),
        ("StoreExpireDate", "1440"),
        ("Desc_1", "d1"),
        ("Desc_4", "d4"),
        ("BindingCard", "1"),
        ("MerchantMemberID", "m1"),
        ("Redeem", "Y"),
        ("UnionPay", "2"),
        ("Language", "ENG"),
    ] {
        assert_eq!(param(&out, k), Some(v), "{k}");
    }
}

#[test]
fn fields_outside_their_group_are_rejected() {
    let client = sdk();
    let cases: Vec<(AioCheckOutParams, &str)> = vec![
        (
            AioCheckOutParams {
                desc_2: Some("x".into()),
                ..base(ChoosePayment::Atm)
            },
            "a CVS/BARCODE extend field (StoreExpireDate/Desc_1..4)",
        ),
        (
            AioCheckOutParams {
                store_expire_date: Some(1),
                ..base(ChoosePayment::Credit)
            },
            "a CVS/BARCODE extend field (StoreExpireDate/Desc_1..4)",
        ),
        (
            AioCheckOutParams {
                payment_info_url: Some("https://x.example/i".into()),
                ..base(ChoosePayment::Credit)
            },
            "PaymentInfoURL/ClientRedirectURL (ATM/CVS/BARCODE groups)",
        ),
        (
            AioCheckOutParams {
                client_redirect_url: Some("https://x.example/b".into()),
                ..base(ChoosePayment::WebATM)
            },
            "PaymentInfoURL/ClientRedirectURL (ATM/CVS/BARCODE groups)",
        ),
        (
            AioCheckOutParams {
                binding_card: Some(1),
                ..base(ChoosePayment::Atm)
            },
            "a Credit bind-card field (BindingCard/MerchantMemberID)",
        ),
        (
            AioCheckOutParams {
                merchant_member_id: Some("m".into()),
                ..base(ChoosePayment::Cvs)
            },
            "a Credit bind-card field (BindingCard/MerchantMemberID)",
        ),
        (
            AioCheckOutParams {
                redeem: Some("Y".into()),
                ..base(ChoosePayment::Atm)
            },
            "a Credit payment-plan field (Redeem/UnionPay/CreditInstallment/Period*)",
        ),
        (
            AioCheckOutParams {
                period_amount: Some(100),
                ..base(ChoosePayment::Barcode)
            },
            "a Credit payment-plan field (Redeem/UnionPay/CreditInstallment/Period*)",
        ),
        (
            AioCheckOutParams {
                expire_date: Some(1),
                ..base(ChoosePayment::Cvs)
            },
            "ExpireDate",
        ),
    ];
    for (params, name) in cases {
        let got = validation(client.aio_check_out(&params).expect_err(name));
        assert_eq!(
            got,
            format!(
                "{name} is only valid with its ChoosePayment group (the official SDK would not send it)."
            )
        );
    }

    // The same fields with their own group pass, and CVS/BARCODE share.
    client
        .aio_check_out(&AioCheckOutParams {
            desc_2: Some("x".into()),
            store_expire_date: Some(1),
            client_redirect_url: Some("https://x.example/b".into()),
            ..base(ChoosePayment::Barcode)
        })
        .expect("CVS/BARCODE fields with BARCODE");
    let out = client
        .aio_check_out(&AioCheckOutParams {
            period_amount: Some(100),
            period_type: Some("M".into()),
            frequency: Some(1),
            exec_times: Some(12),
            period_return_url: Some("https://x.example/p".into()),
            ..base(ChoosePayment::Credit)
        })
        .expect("the Period* group with Credit");
    for (k, v) in [
        ("PeriodAmount", "100"),
        ("PeriodType", "M"),
        ("Frequency", "1"),
        ("ExecTimes", "12"),
        ("PeriodReturnURL", "https://x.example/p"),
    ] {
        assert_eq!(param(&out, k), Some(v), "{k}");
    }
    let out = client
        .aio_check_out(&AioCheckOutParams {
            credit_installment: Some("3,6".into()),
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    assert_eq!(param(&out, "CreditInstallment"), Some("3,6"));
}

// --- InvoiceMark and the invoice block ---

#[test]
fn invoice_mark_rules() {
    let client = sdk();

    // Y without the invoice fields is a validation error.
    let got = validation(
        client
            .aio_check_out(&AioCheckOutParams {
                invoice_mark: Some("Y".into()),
                ..base(ChoosePayment::Credit)
            })
            .expect_err("InvoiceMark=Y needs the invoice block"),
    );
    assert_eq!(
        got,
        "InvoiceMark=Y requires the invoice fields (InvoiceExtend)."
    );

    // N without an invoice is sent verbatim (the official samples do this).
    let out = client
        .aio_check_out(&AioCheckOutParams {
            invoice_mark: Some("N".into()),
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    assert_eq!(param(&out, "InvoiceMark"), Some("N"));

    // An invoice with no explicit mark auto-fills Y, once.
    let out = client
        .aio_check_out(&AioCheckOutParams {
            invoice: Some(invoice()),
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    assert_eq!(param(&out, "InvoiceMark"), Some("Y"));
    assert_eq!(
        out.params()
            .iter()
            .filter(|(k, _)| k == "InvoiceMark")
            .count(),
        1
    );
    for (k, v) in [
        ("RelateNumber", "R1"),
        ("CustomerPhone", "0912345678"),
        ("TaxType", "1"),
        ("Donation", "2"),
        ("Print", "0"),
        ("InvoiceItemName", "%E5%95%86%E5%93%81"),
        ("InvoiceItemCount", "1"),
        ("InvoiceItemWord", "%E5%80%8B"),
        ("InvoiceItemPrice", "100"),
        ("DelayDay", "0"),
        ("InvType", "07"),
    ] {
        assert_eq!(param(&out, k), Some(v), "{k}");
    }
    assert_eq!(param(&out, "CustomerName"), None);
    assert_eq!(param(&out, "LoveCode"), None);

    // An explicit Y with the invoice is the same payload.
    let explicit = client
        .aio_check_out(&AioCheckOutParams {
            invoice_mark: Some("Y".into()),
            invoice: Some(invoice()),
            ..base(ChoosePayment::Credit)
        })
        .unwrap();
    assert_eq!(explicit.params(), out.params());
}

#[test]
fn invoice_validation_branches_not_covered_by_the_sdk_fixture() {
    let client = sdk();
    let with = |inv: InvoiceExtend| AioCheckOutParams {
        invoice: Some(inv),
        ..base(ChoosePayment::Credit)
    };
    let printable = || InvoiceExtend {
        customer_name: Some("客戶".into()),
        customer_addr: Some("地址".into()),
        print: PrintMark::Yes,
        ..invoice()
    };
    let cases: Vec<(InvoiceExtend, &str)> = vec![
        (
            InvoiceExtend {
                customer_identifier: Some("53348111".into()),
                ..invoice()
            },
            r#"Print have to fill "1", when CustomerIdentifier have value."#,
        ),
        (
            InvoiceExtend {
                customer_identifier: Some("53348111".into()),
                donation: Donation::Yes,
                love_code: Some("168001".into()),
                ..printable()
            },
            r#"Donation have to fill "0", when CustomerIdentifier have value."#,
        ),
        (
            InvoiceExtend {
                customer_addr: None,
                ..printable()
            },
            "CustomerAddr have to fill value.",
        ),
        (
            InvoiceExtend {
                carruer_type: Some(CarruerType::Member),
                ..printable()
            },
            r#"CarruerType do not fill any value, when Print is "1"."#,
        ),
        (
            InvoiceExtend {
                love_code: Some("12345678".into()),
                ..invoice()
            },
            "LoveCode max langth is 7.",
        ),
        (
            InvoiceExtend {
                love_code: Some("12".into()),
                ..invoice()
            },
            "LoveCode have to fill fixed length of 3~7 digits.",
        ),
        (
            InvoiceExtend {
                relate_number: String::new(),
                ..invoice()
            },
            "RelateNumber content is required.",
        ),
        (
            InvoiceExtend {
                invoice_item_count: String::new(),
                ..invoice()
            },
            "InvoiceItemCount content is required.",
        ),
    ];
    for (inv, want) in cases {
        let got = validation(client.aio_check_out(&with(inv)).expect_err(want));
        assert_eq!(got, want);
    }

    // An unmodeled code passes through verbatim — the value is ECPay's to
    // adjudicate, exactly like the official SDK (the pre-enum local length
    // check "InvType max langth is 2." is gone with the String field).
    let out = client
        .aio_check_out(&with(InvoiceExtend {
            inv_type: "007".into(),
            ..invoice()
        }))
        .expect("unknown codes pass through to the server");
    assert_eq!(param(&out, "InvType"), Some("007"));

    // The positive counterparts: a printed B2B invoice and a donation.
    let out = client
        .aio_check_out(&with(InvoiceExtend {
            customer_identifier: Some("53348111".into()),
            ..printable()
        }))
        .expect("identifier + Print=1 + no carrier is valid");
    assert_eq!(param(&out, "CustomerIdentifier"), Some("53348111"));
    assert_eq!(param(&out, "Print"), Some("1"));
    assert_eq!(param(&out, "CustomerAddr"), Some("%E5%9C%B0%E5%9D%80"));
    let out = client
        .aio_check_out(&with(InvoiceExtend {
            donation: Donation::Yes,
            love_code: Some("168001".into()),
            customer_email: Some("A@Example.com".into()),
            customer_phone: None,
            ..invoice()
        }))
        .expect("donation with a love code and an email only");
    assert_eq!(param(&out, "LoveCode"), Some("168001"));
    assert_eq!(
        param(&out, "CustomerEmail"),
        Some("A%40Example.com"),
        "escaped, case preserved"
    );
    assert_eq!(param(&out, "CustomerPhone"), None);
}

// --- extra ---

#[test]
fn extra_cannot_smuggle_a_check_mac_value() {
    let got = validation(
        sdk()
            .aio_check_out(&AioCheckOutParams {
                extra: BTreeMap::from([("CheckMacValue".to_owned(), "DEADBEEF".to_owned())]),
                ..base(ChoosePayment::Credit)
            })
            .expect_err("a caller-supplied CheckMacValue must be rejected"),
    );
    assert_eq!(
        got,
        r#"extra parameter "CheckMacValue" collides with a modeled field"#
    );
    // Invoice keys are modeled too, even though they only appear with an
    // invoice block.
    let got = validation(
        sdk()
            .aio_check_out(&AioCheckOutParams {
                invoice: Some(invoice()),
                extra: BTreeMap::from([("RelateNumber".to_owned(), "R9".to_owned())]),
                ..base(ChoosePayment::Credit)
            })
            .expect_err("RelateNumber is modeled once an invoice is present"),
    );
    assert!(got.contains("RelateNumber"), "{got}");
}

// --- reply_payment_type ---

#[test]
fn reply_payment_type_maps_known_codes_only() {
    assert_eq!(reply_payment_type("Credit_CreditCard"), Some("信用卡"));
    assert_eq!(reply_payment_type("ATM_TAISHIN"), Some("台新銀行 ATM"));
    assert_eq!(reply_payment_type("BARCODE_BARCODE"), Some("超商條碼繳款"));
    assert_eq!(reply_payment_type("TWQR"), Some("歐付寶TWQR行動支付"));
    assert_eq!(
        reply_payment_type("credit_creditcard"),
        None,
        "case-sensitive"
    );
    assert_eq!(reply_payment_type(""), None);
}
