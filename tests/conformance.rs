//! Port of Go `conformance_test.go` (field-name conformance) plus the minimal
//! hermetic ECPay mock servers it needs (the harness parts of Go's
//! mock_test.go: a mock B2CInvoice endpoint and a mock Cashier endpoint that
//! verify the inbound CheckMacValue).
//!
//! These tests pin each request/response to the exact field names, casing, and
//! envelope ECPay's official specs require, so a future rename that silently
//! breaks the wire contract fails a test instead of production.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ecpay::{
    encrypt_data, hash_mac, AllowanceByCollegiateInput, AllowanceInput, AllowanceInvalidInput,
    AllowanceItem, CancelDelayIssueInput, CheckBarcodeInput, CheckLoveCodeInput, DelayIssueInput,
    Ecpay, GetAllowanceInput, GetAllowanceInvalidInput, GetCompanyNameByTaxIDInput,
    GetGovInvoiceWordSettingInput, GetInvalidInput, GetInvoiceWordSettingInput, GetIssueInput,
    GetIssueOutput, InvalidInput, InvoiceNotifyInput, IssueInput, IssueModel, Item,
    TriggerIssueInput, VoidModel, VoidWithReIssueInput,
};

mod common;
use common::spawn_http_server;

// --- Go mock_test.go constants and helpers ---

const TEST_INVOICE_HASH_KEY: &str = "ejCk326UnaZWKisg";
const TEST_INVOICE_HASH_IV: &str = "q9jcZX8Ib9LM8wYk";
const TEST_PAYMENT_HASH_KEY: &str = "5294y06JbISpM5x9";
const TEST_PAYMENT_HASH_IV: &str = "v77hoKGq4kWxNNIS";
const TEST_MERCHANT_ID: &str = "2000132";

fn test_invoice_ecpay(base_url: &str) -> Ecpay {
    Ecpay {
        merchant_id: TEST_MERCHANT_ID.to_owned(),
        invoice_hash_key: TEST_INVOICE_HASH_KEY.to_owned(),
        invoice_hash_iv: TEST_INVOICE_HASH_IV.to_owned(),
        invoice_api_url: base_url.to_owned(),
        ..Default::default()
    }
}

fn test_payment_ecpay(base_url: &str) -> Ecpay {
    Ecpay {
        merchant_id: TEST_MERCHANT_ID.to_owned(),
        hash_key: TEST_PAYMENT_HASH_KEY.to_owned(),
        hash_iv: TEST_PAYMENT_HASH_IV.to_owned(),
        payment_api_url: base_url.to_owned(),
        ..Default::default()
    }
}

fn form_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16).unwrap_or(u32::MAX);
                let lo = (b[i + 2] as char).to_digit(16).unwrap_or(u32::MAX);
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in body.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.insert(form_unescape(k), form_unescape(v));
    }
    out
}

fn form_escape(s: &str) -> String {
    // Go url.QueryEscape: unreserved A-Za-z0-9-_.~ literal, space -> '+',
    // everything else uppercase %XX.
    let mut out = String::new();
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

fn encode_form(params: &HashMap<String, String>) -> Vec<u8> {
    let mut pairs: Vec<(&String, &String)> = params.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_escape(k), form_escape(v)))
        .collect();
    encoded.join("&").into_bytes()
}

/// Mock Cashier endpoint (Go newPaymentMock): verifies the inbound
/// CheckMacValue (so a signing regression fails the test) and answers with the
/// given params form-encoded. The inbound params are stored in `captured`.
fn new_payment_mock(
    respond: HashMap<String, String>,
    captured: Arc<Mutex<Option<HashMap<String, String>>>>,
) -> String {
    spawn_http_server(move |_path, body| {
        let body = String::from_utf8_lossy(body);
        let mut params = parse_form(&body);
        let got_mac = params.remove("CheckMacValue").unwrap_or_default();
        let want_mac = hash_mac(&params, TEST_PAYMENT_HASH_KEY, TEST_PAYMENT_HASH_IV);
        assert_eq!(got_mac, want_mac, "mock: CheckMacValue signing mismatch");
        *captured.lock().unwrap() = Some(params);
        (
            200,
            "application/x-www-form-urlencoded".to_owned(),
            encode_form(&respond),
        )
    })
}

// --- Field-name conformance (Go conformance_test.go) ---

fn assert_keys(obj: &serde_json::Map<String, serde_json::Value>, want: &[&str]) {
    for k in want {
        assert!(
            obj.contains_key(*k),
            "missing required field {k:?}; got keys {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }
}

/// TestIssueInputFieldNames locks the Issue (開立發票) request contract,
/// including the ECPay quirk that the tax-inclusive flag is lowercase "vat"
/// (every other field is PascalCase).
#[test]
fn test_issue_input_field_names() {
    let input = IssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "o1".to_owned(),
        print: "0".into(),
        donation: "0".into(),
        tax_type: "1".into(),
        sales_amount: 100,
        inv_type: "07".into(),
        vat: "1".to_owned(),
        items: Some(vec![Item {
            item_seq: 1,
            item_name: "x".to_owned(),
            item_count: 1.0,
            item_word: "項".to_owned(),
            item_price: 100.0,
            item_tax_type: "1".to_owned(),
            item_amount: 100.0,
            ..Default::default()
        }]),
        ..Default::default()
    };
    let m = serde_json::to_value(&input).unwrap();
    let obj = m.as_object().unwrap();
    assert_keys(
        obj,
        &[
            "MerchantID",
            "RelateNumber",
            "Print",
            "Donation",
            "TaxType",
            "SalesAmount",
            "InvType",
            "Items",
        ],
    );

    assert!(
        obj.contains_key("vat"),
        r#"Issue tax-inclusive flag must marshal as lowercase "vat" per ECPay spec"#
    );
    assert!(
        !obj.contains_key("Vat"),
        r#"found PascalCase "Vat"; ECPay's spec field is lowercase "vat""#
    );

    let item = serde_json::to_value(&input.items.unwrap()[0]).unwrap();
    assert_keys(
        item.as_object().unwrap(),
        &[
            "ItemSeq",
            "ItemName",
            "ItemCount",
            "ItemWord",
            "ItemPrice",
            "ItemTaxType",
            "ItemAmount",
        ],
    );
}

/// TestInvalidInputFieldNames locks the Invalid (作廢發票) request contract.
#[test]
fn test_invalid_input_field_names() {
    let input = InvalidInput {
        merchant_id: "2000132".to_owned(),
        invoice_no: "AB12345678".to_owned(),
        invoice_date: "2024-01-02".to_owned(),
        reason: "x".to_owned(),
    };
    let m = serde_json::to_value(&input).unwrap();
    assert_keys(
        m.as_object().unwrap(),
        &["MerchantID", "InvoiceNo", "InvoiceDate", "Reason"],
    );
}

/// TestGetIssueInputFieldNames locks the GetIssue (查詢發票) request contract.
#[test]
fn test_get_issue_input_field_names() {
    let input = GetIssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "o1".to_owned(),
        ..Default::default()
    };
    let m = serde_json::to_value(&input).unwrap();
    assert_keys(m.as_object().unwrap(), &["MerchantID", "RelateNumber"]);
}

/// GetIssue supports two mutually exclusive query modes (RelateNumber alone,
/// or InvoiceNo+InvoiceDate). ECPay's server picks the mode by which keys are
/// *present* in the JSON, not by whether their values are empty — sending an
/// empty RelateNumber alongside InvoiceNo/InvoiceDate (or vice versa) makes
/// the server pick the wrong mode and answer "not found" even for a real
/// invoice (confirmed live against stage, 2026-09). This pins that the unused
/// side is omitted entirely, not sent as `""`.
#[test]
fn test_get_issue_input_omits_the_unused_query_mode() {
    let by_relate = GetIssueInput {
        merchant_id: "2000132".to_owned(),
        relate_number: "o1".to_owned(),
        ..Default::default()
    };
    let m = serde_json::to_value(&by_relate).unwrap();
    let obj = m.as_object().unwrap();
    assert_keys(obj, &["MerchantID", "RelateNumber"]);
    assert!(!obj.contains_key("InvoiceNo"));
    assert!(!obj.contains_key("InvoiceDate"));

    let by_invoice_no = GetIssueInput {
        merchant_id: "2000132".to_owned(),
        invoice_no: "AB12345678".to_owned(),
        invoice_date: "2024-01-02".to_owned(),
        ..Default::default()
    };
    let m = serde_json::to_value(&by_invoice_no).unwrap();
    let obj = m.as_object().unwrap();
    assert_keys(obj, &["MerchantID", "InvoiceNo", "InvoiceDate"]);
    assert!(!obj.contains_key("RelateNumber"));
}

/// TestGetIssueOutputFieldNames confirms the response fields the codebase
/// reads (RtnCode, IIS_Number, IIS_Create_Date, IIS_Relate_Number) decode from
/// ECPay's verbatim spec names — through the crate's own `GetIssueOutput` and
/// the `unmarshal` path `call_invoice_api` uses (an earlier version decoded
/// into a local struct and never touched the crate's type).
#[test]
fn test_get_issue_output_field_names() {
    let raw = r#"{"RtnCode":1,"RtnMsg":"ok","IIS_Number":"AB12345678","IIS_Create_Date":"2024-01-02 15:04:05","IIS_Relate_Number":"o1","IIS_Mer_ID":"2000132","IIS_Remain_Allowance_Amt":100,"Items":[{"ItemSeq":1,"ItemName":"x","ItemCount":2,"ItemPrice":50,"ItemAmount":100,"ItemRemark":null}],"QRCode_Left":"L","QRCode_Right":"R","PosBarCode":"P"}"#;
    let out: GetIssueOutput = ecpay::unmarshal(raw).expect("decode GetIssueOutput");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.rtn_msg, "ok");
    assert_eq!(out.iis_number, "AB12345678");
    assert_eq!(out.iis_create_date, "2024-01-02 15:04:05");
    assert_eq!(out.iis_relate_number, "o1");
    assert_eq!(out.iis_mer_id, serde_json::json!("2000132"));
    assert_eq!(out.iis_remain_allowance_amt, serde_json::json!(100));
    assert_eq!(out.qr_code_left, "L");
    assert_eq!(out.qr_code_right, "R");
    assert_eq!(out.pos_bar_code, "P");
    let items = out.items.expect("Items decodes");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].item_count, 2.0);
    assert_eq!(items[0].item_price, 50.0);
    assert_eq!(items[0].item_amount, 100.0);
    assert_eq!(
        items[0].item_remark, "",
        "a null inside an array element decodes to the zero value too"
    );
}

/// Serialize an input and return its JSON object (every invoice input is a
/// flat object except VoidWithReIssue).
fn json_object<T: serde::Serialize>(input: &T) -> serde_json::Map<String, serde_json::Value> {
    serde_json::to_value(input)
        .expect("serialize")
        .as_object()
        .expect("a JSON object")
        .clone()
}

/// The remaining request contracts that only the sandbox tests pinned so
/// far, plus the spec quirks the doc comments call out: CheckBarcode's field
/// is "Barcode" (not the Go field name BarCode), VoidWithReIssue nests two
/// models, GetAllowance queries by SearchType/Date.
#[test]
fn test_remaining_invoice_input_field_names() {
    let obj = json_object(&CheckBarcodeInput {
        merchant_id: "2000132".into(),
        barcode: "/1234567".into(),
    });
    assert_keys(&obj, &["MerchantID", "Barcode"]);
    assert!(
        !obj.contains_key("BarCode"),
        r#"ECPay's spec field is "Barcode", not the Go field name "BarCode""#
    );

    let obj = json_object(&VoidWithReIssueInput {
        void_model: VoidModel {
            merchant_id: "2000132".into(),
            invoice_no: "AB12345678".into(),
            void_reason: "x".into(),
        },
        issue_model: IssueModel {
            merchant_id: "2000132".into(),
            relate_number: "o2".into(),
            invoice_date: "2024-01-02 15:04:05".into(),
            ..Default::default()
        },
    });
    assert_keys(&obj, &["VoidModel", "IssueModel"]);
    assert_eq!(obj.len(), 2, "nothing is flattened next to the two models");
    let void_model = obj["VoidModel"].as_object().unwrap();
    assert_keys(void_model, &["MerchantID", "InvoiceNo", "VoidReason"]);
    let issue_model = obj["IssueModel"].as_object().unwrap();
    assert_keys(
        issue_model,
        &["MerchantID", "RelateNumber", "InvoiceDate", "vat", "Items"],
    );
    assert!(
        !issue_model.contains_key("TaxAmount"),
        "TaxAmount=None is omitted so ECPay computes it"
    );

    let obj = json_object(&InvoiceNotifyInput {
        merchant_id: "2000132".into(),
        invoice_no: "AB12345678".into(),
        notify: "E".into(),
        notify_mail: "a@b.c".into(),
        invoice_tag: "I".into(),
        notified: "C".into(),
        ..Default::default()
    });
    assert_keys(
        &obj,
        &[
            "MerchantID",
            "InvoiceNo",
            "AllowanceNo",
            "Phone",
            "NotifyMail",
            "Notify",
            "InvoiceTag",
            "Notified",
        ],
    );

    let obj = json_object(&GetCompanyNameByTaxIDInput {
        merchant_id: "2000132".into(),
        unified_business_no: "53348111".into(),
    });
    assert_keys(&obj, &["MerchantID", "UnifiedBusinessNo"]);

    let obj = json_object(&GetGovInvoiceWordSettingInput {
        merchant_id: "2000132".into(),
        invoice_year: "113".into(),
    });
    assert_keys(&obj, &["MerchantID", "InvoiceYear"]);

    let obj = json_object(&GetInvoiceWordSettingInput {
        merchant_id: "2000132".into(),
        invoice_year: "113".into(),
        invoice_term: 0,
        use_status: 0,
        invoice_category: 1,
        inv_type: "07".into(),
        invoice_header: String::new(),
    });
    assert_keys(
        &obj,
        &[
            "MerchantID",
            "InvoiceYear",
            "InvoiceTerm",
            "UseStatus",
            "InvoiceCategory",
            "InvType",
            "InvoiceHeader",
        ],
    );

    let obj = json_object(&DelayIssueInput {
        merchant_id: "2000132".into(),
        relate_number: "o1".into(),
        delay_flag: "1".into(),
        delay_day: 1,
        tsr: "T1".into(),
        pay_type: "2".into(),
        pay_act: "ECPAY".into(),
        notify_url: "https://example.com/n".into(),
        ..Default::default()
    });
    assert_keys(
        &obj,
        &[
            "MerchantID",
            "RelateNumber",
            "vat",
            "DelayFlag",
            "DelayDay",
            "Tsr",
            "PayType",
            "PayAct",
            "NotifyURL",
        ],
    );

    let obj = json_object(&TriggerIssueInput {
        merchant_id: "2000132".into(),
        tsr: "T1".into(),
        pay_type: "2".into(),
    });
    assert_keys(&obj, &["MerchantID", "Tsr", "PayType"]);

    let obj = json_object(&CancelDelayIssueInput {
        merchant_id: "2000132".into(),
        tsr: "T1".into(),
    });
    assert_keys(&obj, &["MerchantID", "Tsr"]);

    // GetInvalid sends all three keys together (no GetIssue-style omission).
    let obj = json_object(&GetInvalidInput {
        merchant_id: "2000132".into(),
        ..Default::default()
    });
    assert_keys(
        &obj,
        &["MerchantID", "RelateNumber", "InvoiceNo", "InvoiceDate"],
    );

    let obj = json_object(&CheckLoveCodeInput {
        merchant_id: "2000132".into(),
        love_code: "168001".into(),
    });
    assert_keys(&obj, &["MerchantID", "LoveCode"]);

    let obj = json_object(&AllowanceInput {
        merchant_id: "2000132".into(),
        invoice_no: "AB12345678".into(),
        invoice_date: "2024-01-02".into(),
        allowance_notify: "E".into(),
        customer_name: "c".into(),
        notify_mail: "a@b.c".into(),
        allowance_amount: 10,
        reason: "r".into(),
        items: Some(vec![AllowanceItem {
            item_seq: 1,
            item_name: "x".into(),
            item_count: 1.0,
            item_word: "個".into(),
            item_price: 10.0,
            item_tax_type: "1".into(),
            item_amount: 10.0,
        }]),
        ..Default::default()
    });
    assert_keys(
        &obj,
        &[
            "MerchantID",
            "InvoiceNo",
            "InvoiceDate",
            "AllowanceNotify",
            "CustomerName",
            "NotifyMail",
            "NotifyPhone",
            "AllowanceAmount",
            "Reason",
            "Items",
        ],
    );
    let item = obj["Items"][0].as_object().unwrap();
    assert_keys(
        item,
        &[
            "ItemSeq",
            "ItemName",
            "ItemCount",
            "ItemWord",
            "ItemPrice",
            "ItemTaxType",
            "ItemAmount",
        ],
    );
    assert!(
        !item.contains_key("ItemRemark"),
        "AllowanceItem has no ItemRemark (spec 7901.md)"
    );

    let obj = json_object(&AllowanceInvalidInput {
        merchant_id: "2000132".into(),
        invoice_no: "AB12345678".into(),
        allowance_no: "A1".into(),
        reason: "r".into(),
    });
    assert_keys(&obj, &["MerchantID", "InvoiceNo", "AllowanceNo", "Reason"]);

    let obj = json_object(&AllowanceByCollegiateInput {
        merchant_id: "2000132".into(),
        return_url: "https://example.com/r".into(),
        ..Default::default()
    });
    assert_keys(
        &obj,
        &[
            "MerchantID",
            "InvoiceNo",
            "InvoiceDate",
            "AllowanceNotify",
            "CustomerName",
            "NotifyMail",
            "AllowanceAmount",
            "Reason",
            "ReturnURL",
            "Items",
        ],
    );

    let obj = json_object(&GetAllowanceInput {
        merchant_id: "2000132".into(),
        search_type: "0".into(),
        allowance_no: "A1".into(),
        invoice_no: "AB12345678".into(),
        date: "2024-01-02".into(),
    });
    assert_keys(
        &obj,
        &[
            "MerchantID",
            "SearchType",
            "AllowanceNo",
            "InvoiceNo",
            "Date",
        ],
    );

    let obj = json_object(&GetAllowanceInvalidInput {
        merchant_id: "2000132".into(),
        invoice_no: "AB12345678".into(),
        allowance_no: "A1".into(),
    });
    assert_keys(&obj, &["MerchantID", "InvoiceNo", "AllowanceNo"]);
}

/// The two `Option` conventions on the Issue-family inputs: `TaxAmount: None`
/// is OMITTED (ECPay computes the tax; sending 0 would be a special-tax
/// declaration) while `Items: None` is sent as `null` (the Go nil slice).
#[test]
fn test_issue_input_option_fields() {
    let obj = json_object(&IssueInput::default());
    assert!(!obj.contains_key("TaxAmount"), "keys: {:?}", obj.keys());
    assert_eq!(obj["Items"], serde_json::Value::Null);

    let obj = json_object(&IssueInput {
        tax_amount: Some(0),
        items: Some(Vec::new()),
        ..Default::default()
    });
    assert_eq!(obj["TaxAmount"], serde_json::json!(0));
    assert_eq!(obj["Items"], serde_json::json!([]));

    for (name, obj) in [
        ("IssueModel", json_object(&IssueModel::default())),
        ("DelayIssueInput", json_object(&DelayIssueInput::default())),
    ] {
        assert!(!obj.contains_key("TaxAmount"), "{name}");
        assert_eq!(obj["Items"], serde_json::Value::Null, "{name}");
    }
}

/// TestInvoiceRequestEnvelope checks the outer AES-JSON envelope
/// call_invoice_api sends: RqHeader.Revision must be "3.0.0", MerchantID must
/// be set, and the Timestamp must be a fresh Unix epoch (ECPay rejects
/// requests >10 min skewed).
#[tokio::test]
async fn test_invoice_request_envelope() {
    let got: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let srv = {
        let got = got.clone();
        spawn_http_server(move |path, body| {
            let _ = path; // /GetIssue
            let req: ecpay::client::Request =
                serde_json::from_slice(body).expect("decode envelope");
            *got.lock().unwrap() =
                Some(serde_json::to_value(&req).expect("encode captured envelope"));
            let data = encrypt_data(
                &GetIssueOutput {
                    rtn_code: 0,
                    ..Default::default()
                },
                TEST_INVOICE_HASH_KEY.as_bytes(),
                TEST_INVOICE_HASH_IV.as_bytes(),
            )
            .expect("encrypt reply");
            let res = ecpay::client::Response {
                trans_code: 1,
                data,
                ..Default::default()
            };
            (
                200,
                "application/json".to_owned(),
                serde_json::to_vec(&res).unwrap(),
            )
        })
    };

    let ec = test_invoice_ecpay(&srv);
    let input = GetIssueInput {
        merchant_id: ec.merchant_id.clone(),
        relate_number: "o1".to_owned(),
        ..Default::default()
    };
    let out = ec
        .get_issue(&input)
        .await
        .expect("GetIssue through the mock");
    assert_eq!(
        out.rtn_code, 0,
        "the mock's RtnCode=0 reply must round-trip"
    );

    let got = got
        .lock()
        .unwrap()
        .clone()
        .expect("the envelope was captured");
    assert_eq!(
        got["RqHeader"]["Revision"], "3.0.0",
        "RqHeader.Revision must be 3.0.0"
    );
    assert_eq!(
        got["MerchantID"], TEST_MERCHANT_ID,
        "envelope MerchantID mismatch"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ts = got["RqHeader"]["Timestamp"]
        .as_i64()
        .expect("Timestamp is a number");
    assert!(
        (now - 120..=now + 5).contains(&ts),
        "RqHeader.Timestamp = {ts}, want within ~now ({now})"
    );
}

/// TestQueryTradeInfoRequestParams confirms the payment query sends exactly
/// the spec's request params (MerchantID, MerchantTradeNo, TimeStamp) — note
/// ECPay's payment API spells it "TimeStamp" — plus a CheckMacValue the mock
/// verifies.
#[tokio::test]
async fn test_query_trade_info_request_params() {
    let captured: Arc<Mutex<Option<HashMap<String, String>>>> = Arc::new(Mutex::new(None));
    let respond: HashMap<String, String> = [
        ("MerchantID", "3002607"),
        ("MerchantTradeNo", "order_abc"),
        ("TradeStatus", "1"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let srv = new_payment_mock(respond, captured.clone());

    let ec = test_payment_ecpay(&srv);
    let out = ec
        .query_trade_info("order_abc")
        .await
        .expect("QueryTradeInfo");
    assert_eq!(out.trade_status, "1");
    assert_eq!(out.merchant_trade_no, "order_abc");

    let got = captured.lock().unwrap().clone().expect("params captured");
    for k in ["MerchantID", "MerchantTradeNo", "TimeStamp"] {
        assert!(
            got.contains_key(k),
            "QueryTradeInfo request missing param {k:?}; got {:?}",
            got.keys().collect::<Vec<_>>()
        );
    }
    assert_eq!(
        got.get("MerchantTradeNo").map(String::as_str),
        Some("order_abc")
    );
}

// --- Transport contract errors (from Go transport_test.go's core cases) ---

/// TestCallInvoiceAPITransCodeGate: TransCode != 1 is a transport-level
/// failure — the client must error before attempting to decrypt Data.
#[tokio::test]
async fn test_call_invoice_api_trans_code_gate() {
    let srv = spawn_http_server(move |_path, _body| {
        let res = ecpay::client::Response {
            merchant_id: serde_json::json!(TEST_MERCHANT_ID),
            trans_code: 0, // TransCode 0
            trans_msg: "查無資料".to_owned(),
            ..Default::default()
        };
        (
            200,
            "application/json".to_owned(),
            serde_json::to_vec(&res).unwrap(),
        )
    });
    let ec = test_invoice_ecpay(&srv);
    let input = GetIssueInput {
        merchant_id: ec.merchant_id.clone(),
        relate_number: "o1".to_owned(),
        ..Default::default()
    };
    let err = ec
        .get_issue(&input)
        .await
        .expect_err("expected a transport error when TransCode != 1");
    match &err {
        ecpay::Error::TransCode { code, msg } => {
            assert_eq!(*code, 0);
            assert_eq!(msg, "查無資料");
        }
        other => panic!("expected Error::TransCode, got {other:?}"),
    }
    assert!(
        err.to_string().contains("ecpay TransCode error: code=0"),
        "TransCode error message mismatch: {err}"
    );
}

/// TestCallInvoiceAPINon2xx + TestCallPaymentAPINon2xx: a non-2xx status
/// surfaces as an error on both transports.
#[tokio::test]
async fn test_api_non_2xx_errors() {
    // Invoice transport.
    let srv = spawn_http_server(move |_path, _body| {
        (502, "text/plain".to_owned(), b"upstream boom".to_vec())
    });
    let ec = test_invoice_ecpay(&srv);
    let input = GetIssueInput {
        merchant_id: ec.merchant_id.clone(),
        relate_number: "o1".to_owned(),
        ..Default::default()
    };
    let err = ec
        .get_issue(&input)
        .await
        .expect_err("expected an error on a non-2xx invoice API response");
    assert!(
        err.to_string()
            .contains("ecpay invoice API error: status=502 body=upstream boom"),
        "invoice non-2xx message mismatch: {err}"
    );

    // Payment transport.
    let srv =
        spawn_http_server(move |_path, _body| (500, "text/plain".to_owned(), b"boom".to_vec()));
    let ec = test_payment_ecpay(&srv);
    let err = ec
        .query_trade_info("order_x")
        .await
        .expect_err("expected an error on a non-2xx payment API response");
    match &err {
        ecpay::Error::PaymentStatus { status, body } => {
            assert_eq!(*status, 500);
            assert_eq!(body, "boom");
        }
        other => panic!("expected Error::PaymentStatus, got {other:?}"),
    }
    assert!(
        err.to_string() == "ecpay payment API error: status=500 body=boom",
        "payment non-2xx message mismatch: {err}"
    );
}
