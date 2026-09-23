//! Hermetic wire-conformance tests for ALL 23 B2B e-invoice endpoints
//! (`src/invoice_b2b.rs`). Every call must produce ECPay's verbatim
//! `{MerchantID, RqHeader, Data}` envelope — the B2B `RqHeader` with exactly
//! `Timestamp` + `RqID` + `Revision: "1.0.0"` — and a `Data` payload whose
//! decrypted field names and values match the official PHP SDK examples
//! (`example/Invoice/B2B/`). No network: the "server" is a local thread from
//! `tests/common/mod.rs` that decrypts the request with the same invoice
//! keys and replies with an encrypted, stage-shaped response.

use ecpay::invoice_b2b::{
    AllowanceInput, B2bAllowanceDetail, B2bItem, GetInvoiceWordSettingInput, InvalidInput,
    IssueB2bInput, MaintainMerchantCustomerDataInput,
};
use ecpay::Ecpay;

mod common;
use common::spawn_http_server;

const MERCHANT_ID: &str = "2000132";
// B2B uses the SAME keys as the B2C invoice API (official PHP B2B examples).
const B2B_KEY: &str = "ejCk326UnaZWKisg";
const B2B_IV: &str = "q9jcZX8Ib9LM8wYk";
// The fixed GUID from the official PHP examples / stage probe.
const B2B_RQ_ID: &str = "701b3264-a538-437e-ad45-2505eb7dde39";

fn b2b_client(b2b_invoice_api_url: String) -> Ecpay {
    Ecpay {
        merchant_id: MERCHANT_ID.into(),
        invoice_hash_key: B2B_KEY.to_owned(),
        invoice_hash_iv: B2B_IV.to_owned(),
        b2b_invoice_api_url,
        b2b_rq_id: B2B_RQ_ID.into(),
        ..Default::default()
    }
}

/// The stage-proven Issue success payload (2026-09 live probe, commit
/// ed87553): RtnCode is an INTEGER and the invoice field is `InvoiceNumber`
/// (B2C uses `InvoiceNo`).
fn issue_success_data() -> serde_json::Value {
    serde_json::json!({
        "RtnCode": 1,
        "RtnMsg": "發票開立成功",
        "InvoiceNumber": "LP30000931",
        "RandomNumber": "3990",
    })
}

/// The response envelope the real server sends: `{TransCode, TransMsg,
/// Data}` — plus ECPay's own typo'd header spellings `RpHeader`/`Reversion`
/// (captured live on stage, 2026-09), reproduced here verbatim to prove our
/// decode is indifferent to them. `Data` = AES-encrypted url-encoded JSON,
/// as a raw body.
fn aes_reply(data: &serde_json::Value) -> (u16, String, Vec<u8>) {
    let encrypted = ecpay::crypto::encrypt_data(data, B2B_KEY.as_bytes(), B2B_IV.as_bytes())
        .expect("encrypt reply Data");
    let body = format!(
        r#"{{"MerchantID":2000132,"RpHeader":{{"Timestamp":1789079520,"RqID":"701b3264-a538-437e-ad45-2505eb7dde39","Reversion":"1.0.0"}},"TransCode":1,"TransMsg":"Success","Data":"{encrypted}"}}"#
    );
    (
        200,
        "application/json; charset=utf-8".to_owned(),
        body.into_bytes(),
    )
}

/// Asserts everything every B2B call has in common — the request path ends
/// with the action, the envelope carries EXACTLY `{MerchantID, RqHeader,
/// Data}`, the RqHeader carries EXACTLY `{Timestamp, RqID, Revision}` with
/// `Revision == "1.0.0"` and the configured GUID — then returns the
/// DECRYPTED `Data` payload for per-endpoint field assertions.
fn assert_envelope_and_decrypt(path: &str, body: &[u8], action: &str) -> serde_json::Value {
    assert_eq!(
        path,
        &format!("/{action}"),
        "request path must end with the action"
    );

    let envelope: serde_json::Value = serde_json::from_slice(body).expect("envelope is JSON");
    let obj = envelope.as_object().expect("envelope is a JSON object");
    let mut keys: Vec<_> = obj.keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["Data", "MerchantID", "RqHeader"], "envelope keys");
    assert_eq!(envelope["MerchantID"], MERCHANT_ID, "envelope MerchantID");

    let rq = envelope["RqHeader"]
        .as_object()
        .expect("RqHeader is a JSON object");
    let mut rq_keys: Vec<_> = rq.keys().cloned().collect();
    rq_keys.sort();
    assert_eq!(rq_keys, ["Revision", "RqID", "Timestamp"], "RqHeader keys");
    assert_eq!(envelope["RqHeader"]["Revision"], "1.0.0", "B2B Revision");
    assert_eq!(envelope["RqHeader"]["RqID"], B2B_RQ_ID, "B2B RqID");
    let ts = envelope["RqHeader"]["Timestamp"]
        .as_i64()
        .expect("Timestamp is an integer");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        (ts - now).abs() < 600,
        "Timestamp {ts} must be fresh (ECPay allows a 10-minute window; now={now})"
    );

    ecpay::crypto::decrypt_data::<serde_json::Value>(
        envelope["Data"].as_str().expect("Data is a string"),
        B2B_KEY.as_bytes(),
        B2B_IV.as_bytes(),
    )
    .expect("Data decrypts with the B2C invoice keys")
}

/// Asserts the decrypted `Data` carries EXACTLY `keys` (sorted compare) —
/// the strongest wire pin: a serde rename typo, a new/removed field, or a
/// stray default breaks the set, exactly as a real ECPay payload mismatch
/// would.
fn assert_data_keys(data: &serde_json::Value, keys: &[&str]) {
    let mut got: Vec<String> = data
        .as_object()
        .expect("Data is an object")
        .keys()
        .cloned()
        .collect();
    got.sort();
    let mut want: Vec<&str> = keys.to_vec();
    want.sort();
    assert_eq!(got, want, "exact Data key set");
    assert_eq!(data["MerchantID"], MERCHANT_ID, "Data MerchantID rides too");
}

/// The generic query/confirm reply the untyped endpoints pass through.
fn ok_reply(rtn_msg: &str) -> (u16, String, Vec<u8>) {
    aes_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": rtn_msg}))
}

/// Issue: the full PHP-example payload rides verbatim inside `Data`, and the
/// typed output decodes the stage-proven response (integer RtnCode,
/// InvoiceNumber + RandomNumber).
#[tokio::test]
async fn issue_b2b_sends_the_php_example_payload_and_decodes_the_typed_output() {
    let srv = spawn_http_server(move |path, body| {
        let data = assert_envelope_and_decrypt(path, body, "Issue");
        // Field names + values verbatim from example/Invoice/B2B/Issue.php —
        // the exact request the ed87553 stage probe proved live (RtnCode=1).
        assert_eq!(
            data["MerchantID"], MERCHANT_ID,
            "Data carries MerchantID too"
        );
        assert_eq!(data["RelateNumber"], "B2BTEST001");
        assert_eq!(data["CustomerIdentifier"], "23165448");
        assert_eq!(data["CustomerEmail"], "test-buyer@ecpay.com.tw");
        assert_eq!(data["InvType"], "07");
        assert_eq!(data["TaxType"], "1");
        assert_eq!(data["Items"][0]["ItemSeq"], 1);
        assert_eq!(data["Items"][0]["ItemName"], "測試商品01");
        assert_eq!(
            data["Items"][0]["ItemCount"], 3.0,
            "f64 rides as a JSON number"
        );
        assert_eq!(data["Items"][0]["ItemPrice"], 10.0);
        assert_eq!(data["Items"][0]["ItemTaxType"], "1");
        assert_eq!(data["Items"][0]["ItemAmount"], 30.0);
        assert_eq!(data["SalesAmount"], 30);
        assert_eq!(data["TaxAmount"], 2);
        assert_eq!(data["TotalAmount"], 32);
        aes_reply(&issue_success_data())
    });
    let client = b2b_client(srv);
    let out = client
        .issue_b2b(&IssueB2bInput {
            merchant_id: MERCHANT_ID.into(),
            relate_number: "B2BTEST001".into(),
            customer_identifier: "23165448".into(),
            customer_email: "test-buyer@ecpay.com.tw".into(),
            inv_type: "07".into(),
            tax_type: "1".into(),
            items: vec![B2bItem {
                item_seq: 1,
                item_name: "測試商品01".into(),
                item_count: 3.0,
                item_price: 10.0,
                item_tax_type: "1".into(),
                item_amount: 30.0,
                ..Default::default()
            }],
            sales_amount: 30,
            tax_amount: 2,
            total_amount: 32,
            ..Default::default()
        })
        .await
        .expect("issue_b2b succeeds against the stage-shaped reply");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.rtn_msg, "發票開立成功");
    assert_eq!(out.invoice_number, "LP30000931");
    assert_eq!(out.random_number, "3990");
}

/// The Issue `Data` carries EXACTLY the documented B2B field set: the
/// customer-contact optionals use the B2B wire names (`CustomerAddress` /
/// `CustomerTelephoneNumber` — NOT B2C's `CustomerAddr`/`CustomerPhone`),
/// and the B2C-style block B2B never reads (`Print`/`Donation`/`LoveCode`/
/// `CarrierType`/`CarrierNum`/`CustomerName`/`CustomerID`/`TaxCenterFlag`/
/// `ClearInvoice`) is not modeled at all — the B2B spec has no carrier or
/// donation fields ("B2B 發票無載具/捐贈欄位,必填買方統編"; spec pages
/// 24230/14850, 2026-04 snapshot) and the official `Issue.php` example
/// sends none of them. Every documented optional is populated here — the
/// wire-shape pin, not a semantically valid invoice (e.g. ZeroTaxRateReason
/// alongside SpecialTaxType would never both ride a real request).
#[tokio::test]
async fn issue_b2b_data_is_exactly_the_documented_field_set() {
    let srv = spawn_http_server(move |path, body| {
        let data = assert_envelope_and_decrypt(path, body, "Issue");
        assert_eq!(data["CustomerAddress"], "台北市大安區復興南路一段390號");
        assert_eq!(data["CustomerTelephoneNumber"], "0223456789");
        assert_eq!(data["InvoiceTime"], "2026-09-22 10:00:00");
        assert_eq!(data["ClearanceMark"], 2, "Number per the spec table");
        assert_eq!(data["ZeroTaxRateReason"], "71");
        assert_eq!(data["SpecialTaxType"], 8);
        assert_eq!(data["InvoiceRemark"], "remark");
        let mut keys: Vec<&str> = data
            .as_object()
            .expect("Data is a JSON object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "ClearanceMark",
                "CustomerAddress",
                "CustomerEmail",
                "CustomerIdentifier",
                "CustomerTelephoneNumber",
                "InvType",
                "InvoiceRemark",
                "InvoiceTime",
                "Items",
                "MerchantID",
                "RelateNumber",
                "SalesAmount",
                "SpecialTaxType",
                "TaxAmount",
                "TaxType",
                "TotalAmount",
                "ZeroTaxRateReason",
            ],
            "no B2C-style field may appear: {keys:?}"
        );
        aes_reply(&issue_success_data())
    });
    let client = b2b_client(srv);
    let out = client
        .issue_b2b(&IssueB2bInput {
            merchant_id: MERCHANT_ID.into(),
            relate_number: "B2BTEST002".into(),
            customer_identifier: "23165448".into(),
            customer_email: "test-buyer@ecpay.com.tw".into(),
            customer_address: Some("台北市大安區復興南路一段390號".into()),
            customer_telephone_number: Some("0223456789".into()),
            invoice_time: Some("2026-09-22 10:00:00".into()),
            clearance_mark: Some(2),
            zero_tax_rate_reason: Some("71".into()),
            special_tax_type: Some(8),
            invoice_remark: Some("remark".into()),
            inv_type: "07".into(),
            tax_type: "1".into(),
            items: vec![B2bItem {
                item_seq: 1,
                item_name: "測試商品01".into(),
                item_count: 3.0,
                item_price: 10.0,
                item_tax_type: "1".into(),
                item_amount: 30.0,
                ..Default::default()
            }],
            sales_amount: 30,
            tax_amount: 2,
            total_amount: 32,
        })
        .await
        .expect("issue_b2b succeeds against the stage-shaped reply");
    assert_eq!(out.rtn_code, 1);
}

/// Allowance: the Details array and the original-invoice references ride
/// verbatim; the untyped Value output passes the decrypted payload through.
#[tokio::test]
async fn allowance_b2b_sends_the_details_array_verbatim() {
    let srv = spawn_http_server(move |path, body| {
        let data = assert_envelope_and_decrypt(path, body, "Allowance");
        assert_eq!(data["MerchantID"], MERCHANT_ID);
        assert_eq!(data["TaxAmount"], 1);
        assert_eq!(data["TotalAmount"], 10);
        let detail = &data["Details"][0];
        assert_eq!(detail["OriginalInvoiceNumber"], "LP30000931");
        assert_eq!(detail["OriginalInvoiceDate"], "2026-09-01");
        assert_eq!(detail["ItemName"], "測試商品01");
        assert_eq!(detail["OriginalSequenceNumber"], 1);
        assert_eq!(detail["ItemCount"], 1.0);
        assert_eq!(detail["ItemPrice"], 10.0);
        assert_eq!(detail["ItemAmount"], 10.0);
        aes_reply(&serde_json::json!({
            "RtnCode": 1,
            "RtnMsg": "折讓開立成功",
            "AllowanceNo": "2109011200000001",
        }))
    });
    let client = b2b_client(srv);
    let out = client
        .allowance_b2b(&AllowanceInput {
            merchant_id: MERCHANT_ID.into(),
            tax_amount: 1,
            total_amount: 10,
            details: vec![B2bAllowanceDetail {
                original_invoice_number: "LP30000931".into(),
                original_invoice_date: "2026-09-01".into(),
                item_name: "測試商品01".into(),
                original_sequence_number: 1,
                item_count: 1.0,
                item_price: 10.0,
                item_amount: 10.0,
            }],
        })
        .await
        .expect("allowance_b2b succeeds");
    assert_eq!(out["RtnCode"], 1, "untyped output passes Data through");
    assert_eq!(out["RtnMsg"], "折讓開立成功");
    assert_eq!(out["AllowanceNo"], "2109011200000001");
}

/// Invalid: InvoiceNumber/InvoiceDate/Reason verbatim, and the reply decrypts.
#[tokio::test]
async fn invalid_b2b_sends_the_php_example_fields() {
    let srv = spawn_http_server(move |path, body| {
        let data = assert_envelope_and_decrypt(path, body, "Invalid");
        assert_eq!(data["MerchantID"], MERCHANT_ID);
        assert_eq!(data["InvoiceNumber"], "LP30000931");
        assert_eq!(data["InvoiceDate"], "2026-09-01");
        assert_eq!(data["Reason"], "Testing reason");
        aes_reply(&serde_json::json!({
            "RtnCode": 1,
            "RtnMsg": "發票作廢成功",
            "InvoiceNumber": "LP30000931",
        }))
    });
    let client = b2b_client(srv);
    let out = client
        .invalid_b2b(&InvalidInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_number: "LP30000931".into(),
            invoice_date: "2026-09-01".into(),
            reason: "Testing reason".into(),
        })
        .await
        .expect("invalid_b2b succeeds");
    assert_eq!(out["RtnCode"], 1);
    assert_eq!(out["RtnMsg"], "發票作廢成功");
}

/// GetInvoiceWordSetting: the 民國年 year and the B2B InvoiceCategory=2 ride
/// verbatim on the query path.
#[tokio::test]
async fn get_invoice_word_setting_b2b_sends_the_php_example_fields() {
    let srv = spawn_http_server(move |path, body| {
        let data = assert_envelope_and_decrypt(path, body, "GetInvoiceWordSetting");
        assert_eq!(data["MerchantID"], MERCHANT_ID);
        assert_eq!(data["InvoiceYear"], "109", "民國年 as a string");
        assert_eq!(data["InvoiceTerm"], 0);
        assert_eq!(data["UseStatus"], 0);
        assert_eq!(data["InvoiceCategory"], 2, "the B2B example value");
        aes_reply(&serde_json::json!({
            "RtnCode": 1,
            "RtnMsg": "查詢成功",
            "InvoiceInfo": [],
        }))
    });
    let client = b2b_client(srv);
    let out = client
        .get_invoice_word_setting_b2b(&GetInvoiceWordSettingInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_year: "109".into(),
            invoice_term: 0,
            use_status: 0,
            invoice_category: 2,
        })
        .await
        .expect("get_invoice_word_setting_b2b succeeds");
    assert_eq!(out["RtnCode"], 1);
    assert!(out["InvoiceInfo"]
        .as_array()
        .expect("InvoiceInfo array")
        .is_empty());
}

/// MaintainMerchantCustomerData: the wire field is ECPay's own lowercase
/// "type" — pinned by asserting the EXACT decrypted key set (a "Type"
/// rename would fail this set).
#[tokio::test]
async fn maintain_merchant_customer_data_keeps_the_lowercase_type_wire_name() {
    let srv = spawn_http_server(move |path, body| {
        let data = assert_envelope_and_decrypt(path, body, "MaintainMerchantCustomerData");
        let mut keys: Vec<String> = data
            .as_object()
            .expect("Data is an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "Action",
                "CompanyName",
                "EmailAddress",
                "ExchangeMode",
                "Identifier",
                "MerchantID",
                "TradingSlang",
                "type",
            ],
            "exact key set, with lowercase type (ASCII sort puts it last)"
        );
        assert_eq!(data["MerchantID"], MERCHANT_ID);
        assert_eq!(data["Action"], "Add");
        assert_eq!(data["Identifier"], "53538851");
        assert_eq!(data["type"], "2");
        assert_eq!(data["CompanyName"], "綠界科技");
        assert_eq!(data["TradingSlang"], "Testing Slang");
        assert_eq!(data["ExchangeMode"], "0");
        assert_eq!(data["EmailAddress"], "test-company@ecpay.com.tw");
        aes_reply(&serde_json::json!({
            "RtnCode": 1,
            "RtnMsg": "新增成功",
        }))
    });
    let client = b2b_client(srv);
    let out = client
        .maintain_merchant_customer_data(&MaintainMerchantCustomerDataInput {
            merchant_id: MERCHANT_ID.into(),
            action: "Add".into(),
            identifier: "53538851".into(),
            r#type: "2".into(),
            company_name: "綠界科技".into(),
            trading_slang: "Testing Slang".into(),
            exchange_mode: "0".into(),
            email_address: "test-company@ecpay.com.tw".into(),
        })
        .await
        .expect("maintain_merchant_customer_data succeeds");
    assert_eq!(out["RtnCode"], 1);
    assert_eq!(out["RtnMsg"], "新增成功");
}

/// A TransCode ≠ 1 envelope must surface as `Error::TransCode` (the crate's
/// AES gate), never as a decoded payload or a panic.
#[tokio::test]
async fn transcode_not_one_surfaces_as_a_transcode_error() {
    let srv = spawn_http_server(move |_path, _body| {
        let body = r#"{"TransCode":7,"TransMsg":"驗證失敗","Data":""}"#.to_owned();
        (
            200,
            "application/json; charset=utf-8".to_owned(),
            body.into_bytes(),
        )
    });
    let client = b2b_client(srv);
    let err = client
        .issue_b2b(&IssueB2bInput {
            merchant_id: MERCHANT_ID.into(),
            ..Default::default()
        })
        .await
        .expect_err("TransCode=7 must be an error");
    assert!(
        matches!(err, ecpay::Error::TransCode { code: 7, .. }),
        "expected Error::TransCode(7), got {err:?}"
    );
}

/// The Data-level MerchantID must be set and equal the client's — ECPay
/// rejects a mismatch opaquely (RtnCode != 1, no message), so the guard must
/// trip BEFORE any bytes leave the process.
#[tokio::test]
async fn mismatched_data_merchant_id_is_rejected_before_the_wire() {
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit2 = hit.clone();
    let srv = spawn_http_server(move |_path, _body| {
        hit2.store(true, std::sync::atomic::Ordering::SeqCst);
        aes_reply(&issue_success_data())
    });
    let client = b2b_client(srv);
    let err = client
        .issue_b2b(&IssueB2bInput::default()) // merchant_id: "" on purpose
        .await
        .expect_err("an empty Data MerchantID must be rejected locally");
    assert!(
        matches!(&err, ecpay::Error::Validation(m) if m.contains("Data MerchantID")),
        "expected the Data-MerchantID guard, got {err:?}"
    );
    assert!(
        !hit.load(std::sync::atomic::Ordering::SeqCst),
        "no request may be sent for a locally-rejected envelope"
    );
}
// --- The remaining 18 endpoints: each pinned to its exact `Data` key set
// (sorted) and its action path, in the module's own order. ---

macro_rules! b2b_wire_test {
    ($name:ident, $action:literal, $keys:expr, $call:expr) => {
        #[tokio::test]
        async fn $name() {
            let srv = spawn_http_server(move |path, body| {
                let data = assert_envelope_and_decrypt(path, body, $action);
                assert_data_keys(&data, $keys);
                ok_reply("測試成功")
            });
            let client = b2b_client(srv);
            let out = ($call)(&client)
                .await
                .expect(concat!(stringify!($name), " succeeds"));
            assert_eq!(out["RtnCode"], 1, "untyped output passes Data through");
            assert_eq!(out["RtnMsg"], "測試成功");
        }
    };
}

use ecpay::invoice_b2b::*;

async fn call_issue_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.issue_confirm(&IssueConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    issue_confirm_pins_the_exact_data_key_set,
    "IssueConfirm",
    &["MerchantID", "InvoiceNumber", "InvoiceDate"],
    call_issue_confirm
);

async fn call_allowance_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.allowance_confirm(&AllowanceConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
    })
    .await
}
b2b_wire_test!(
    allowance_confirm_pins_the_exact_data_key_set,
    "AllowanceConfirm",
    &["MerchantID", "AllowanceNo"],
    call_allowance_confirm
);

async fn call_cancel_allowance(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.cancel_allowance(&CancelAllowanceInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
        reason: "Testing reason".into(),
    })
    .await
}
b2b_wire_test!(
    cancel_allowance_pins_the_exact_data_key_set,
    "CancelAllowance",
    &["MerchantID", "AllowanceNo", "Reason"],
    call_cancel_allowance
);

async fn call_cancel_allowance_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.cancel_allowance_confirm(&CancelAllowanceConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
    })
    .await
}
b2b_wire_test!(
    cancel_allowance_confirm_pins_the_exact_data_key_set,
    "CancelAllowanceConfirm",
    &["MerchantID", "AllowanceNo"],
    call_cancel_allowance_confirm
);

async fn call_invalid_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.invalid_confirm(&InvalidConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    invalid_confirm_pins_the_exact_data_key_set,
    "InvalidConfirm",
    &["MerchantID", "InvoiceNumber", "InvoiceDate"],
    call_invalid_confirm
);

async fn call_notify(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.notify(&NotifyInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_date: "2026-09-01".into(),
        invoice_number: "LP30000931".into(),
        notify_mail: "test-buyer@ecpay.com.tw".into(),
        invoice_tag: "1".into(),
        notified: "C".into(),
    })
    .await
}
b2b_wire_test!(
    notify_pins_the_exact_data_key_set,
    "Notify",
    &[
        "MerchantID",
        "InvoiceDate",
        "InvoiceNumber",
        "NotifyMail",
        "InvoiceTag",
        "Notified"
    ],
    call_notify
);

async fn call_reject(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.reject(&RejectInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
        reason: "Testing reason".into(),
    })
    .await
}
b2b_wire_test!(
    reject_pins_the_exact_data_key_set,
    "Reject",
    &["MerchantID", "InvoiceNumber", "InvoiceDate", "Reason"],
    call_reject
);

async fn call_reject_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.reject_confirm(&RejectConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    reject_confirm_pins_the_exact_data_key_set,
    "RejectConfirm",
    &["MerchantID", "InvoiceNumber", "InvoiceDate"],
    call_reject_confirm
);

async fn call_get_issue_b2b(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_issue_b2b(&GetIssueInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_category: 0,
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    get_issue_b2b_pins_the_exact_data_key_set,
    "GetIssue",
    &[
        "MerchantID",
        "InvoiceCategory",
        "InvoiceNumber",
        "InvoiceDate"
    ],
    call_get_issue_b2b
);

async fn call_get_issue_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_issue_confirm(&GetIssueConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_category: 0,
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    get_issue_confirm_pins_the_exact_data_key_set,
    "GetIssueConfirm",
    &[
        "MerchantID",
        "InvoiceCategory",
        "InvoiceNumber",
        "InvoiceDate"
    ],
    call_get_issue_confirm
);

async fn call_get_invalid_b2b(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_invalid_b2b(&GetInvalidInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_category: 0,
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    get_invalid_b2b_pins_the_exact_data_key_set,
    "GetInvalid",
    &[
        "MerchantID",
        "InvoiceCategory",
        "InvoiceNumber",
        "InvoiceDate"
    ],
    call_get_invalid_b2b
);

async fn call_get_invalid_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_invalid_confirm(&GetInvalidConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_category: 0,
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    get_invalid_confirm_pins_the_exact_data_key_set,
    "GetInvalidConfirm",
    &[
        "MerchantID",
        "InvoiceCategory",
        "InvoiceNumber",
        "InvoiceDate"
    ],
    call_get_invalid_confirm
);

async fn call_get_allowance_b2b(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_allowance_b2b(&GetAllowanceInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
    })
    .await
}
b2b_wire_test!(
    get_allowance_b2b_pins_the_exact_data_key_set,
    "GetAllowance",
    &["MerchantID", "AllowanceNo"],
    call_get_allowance_b2b
);

async fn call_get_allowance_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_allowance_confirm(&GetAllowanceConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
    })
    .await
}
b2b_wire_test!(
    get_allowance_confirm_pins_the_exact_data_key_set,
    "GetAllowanceConfirm",
    &["MerchantID", "AllowanceNo"],
    call_get_allowance_confirm
);

async fn call_get_allowance_invalid_b2b(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_allowance_invalid_b2b(&GetAllowanceInvalidInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
    })
    .await
}
b2b_wire_test!(
    get_allowance_invalid_b2b_pins_the_exact_data_key_set,
    "GetAllowanceInvalid",
    &["MerchantID", "AllowanceNo"],
    call_get_allowance_invalid_b2b
);

async fn call_get_allowance_invalid_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_allowance_invalid_confirm(&GetAllowanceInvalidConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        allowance_no: "2109011200000001".into(),
    })
    .await
}
b2b_wire_test!(
    get_allowance_invalid_confirm_pins_the_exact_data_key_set,
    "GetAllowanceInvalidConfirm",
    &["MerchantID", "AllowanceNo"],
    call_get_allowance_invalid_confirm
);

async fn call_get_reject(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_reject(&GetRejectInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
        reason: "Testing reason".into(),
    })
    .await
}
b2b_wire_test!(
    get_reject_pins_the_exact_data_key_set_and_its_odd_reason_field,
    "GetReject",
    // 官方 PHP 範例在這個查詢端點的 Data 也帶 Reason（照抄，見模組註解）。
    &["MerchantID", "InvoiceNumber", "InvoiceDate", "Reason"],
    call_get_reject
);

async fn call_get_reject_confirm(c: &Ecpay) -> ecpay::Result<serde_json::Value> {
    c.get_reject_confirm(&GetRejectConfirmInput {
        merchant_id: MERCHANT_ID.into(),
        invoice_category: 0,
        invoice_number: "LP30000931".into(),
        invoice_date: "2026-09-01".into(),
    })
    .await
}
b2b_wire_test!(
    get_reject_confirm_pins_the_exact_data_key_set,
    "GetRejectConfirm",
    &[
        "MerchantID",
        "InvoiceCategory",
        "InvoiceNumber",
        "InvoiceDate"
    ],
    call_get_reject_confirm
);

/// ECPay's B2B wire contract carries `RqHeader.RqID` (GUID format, unique
/// per request) on every call; the official PHP examples always send one.
/// An empty `b2b_rq_id` used to go out as `"RqID": ""` — whether the stage
/// accepts that is unverified — so the crate now refuses locally with an
/// actionable message instead of gambling the request.
#[tokio::test]
async fn empty_b2b_rq_id_is_refused_before_any_bytes_go_out() {
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sent_srv = sent.clone();
    let srv = spawn_http_server(move |path, body| {
        sent_srv.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = assert_envelope_and_decrypt(path, body, "Invalid");
        aes_reply(&serde_json::json!({"RtnCode": 1, "RtnMsg": "ok"}))
    });
    let client = Ecpay {
        b2b_rq_id: String::new(),
        ..b2b_client(srv)
    };
    let err = client
        .invalid_b2b(&InvalidInput {
            merchant_id: MERCHANT_ID.into(),
            invoice_number: "AB12345678".into(),
            invoice_date: "2026-09-01".into(),
            reason: "test".into(),
        })
        .await
        .expect_err("empty b2b_rq_id must be refused");
    assert!(matches!(err, ecpay::Error::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("RqID"), "{err}");
    assert!(
        !sent.load(std::sync::atomic::Ordering::SeqCst),
        "no bytes may reach the wire without an RqID"
    );
}
