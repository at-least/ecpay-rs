//! The typed B2C invoice methods against a hermetic mock: the
//! command-vs-query contract on a non-1 RtnCode, the wire action names
//! (only the sandbox pinned them before), `issue()`'s error contract, and
//! the Data-decode failure paths of `call_invoice_api`.

use std::sync::{Arc, Mutex};

use ecpay::{
    encrypt, encrypt_data, ApiError, Ecpay, Error, IssueInput, IssueModel, VoidModel,
    VoidWithReIssueInput,
};

mod common;
use common::spawn_http_server;

const INVOICE_HASH_KEY: &str = "ejCk326UnaZWKisg";
const INVOICE_HASH_IV: &str = "q9jcZX8Ib9LM8wYk";

fn client(base_url: String) -> Ecpay {
    Ecpay {
        merchant_id: "2000132".to_owned(),
        invoice_hash_key: INVOICE_HASH_KEY.to_owned(),
        invoice_hash_iv: INVOICE_HASH_IV.to_owned(),
        invoice_api_url: base_url,
        ..Default::default()
    }
}

fn envelope(data: String) -> (u16, String, Vec<u8>) {
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
}

/// A mock B2CInvoice base that answers every action with the same decrypted
/// `Data` payload and records the request paths in order.
fn mock(data: serde_json::Value) -> (Ecpay, Arc<Mutex<Vec<String>>>) {
    let paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = paths.clone();
    let srv = spawn_http_server(move |path, body| {
        // Every request must be a well-formed envelope from this merchant.
        let req: ecpay::client::Request = serde_json::from_slice(body).expect("decode envelope");
        assert_eq!(req.merchant_id, "2000132");
        assert_eq!(req.rq_header.revision, "3.0.0");
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_owned());
        envelope(
            encrypt_data(
                &data,
                INVOICE_HASH_KEY.as_bytes(),
                INVOICE_HASH_IV.as_bytes(),
            )
            .unwrap(),
        )
    });
    (client(srv), paths)
}

fn assert_api_rejection(err: Error, what: &str) {
    match err {
        Error::Api(ApiError { code, msg }) => {
            assert_eq!(code, 2, "{what}");
            assert_eq!(msg, "mock rejection", "{what}");
        }
        other => panic!("{what}: expected Error::Api, got {other:?}"),
    }
}

/// Command calls raise `Error::Api` on RtnCode != 1, and each one hits its
/// spec action name (VoidWithReIssue, not the Go port's VoidWithIssue).
#[tokio::test]
async fn commands_raise_api_errors_and_hit_their_action_names() {
    let (ec, paths) = mock(serde_json::json!({"RtnCode": 2, "RtnMsg": "mock rejection"}));

    macro_rules! command {
        ($call:expr, $name:literal) => {{
            let err = $call
                .await
                .expect_err(concat!($name, " is a command: RtnCode!=1 must be an error"));
            assert_api_rejection(err, $name);
            let last = paths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .last()
                .cloned()
                .unwrap();
            assert_eq!(last, concat!("/", $name), "wire action name");
        }};
    }

    command!(ec.issue(&Default::default()), "Issue");
    command!(ec.void_with_reissue(&Default::default()), "VoidWithReIssue");
    command!(ec.invalid(&Default::default()), "Invalid");
    command!(ec.invoice_notify(&Default::default()), "InvoiceNotify");
    command!(ec.delay_issue(&Default::default()), "DelayIssue");
    command!(
        ec.cancel_delay_issue(&Default::default()),
        "CancelDelayIssue"
    );
    command!(ec.allowance(&Default::default()), "Allowance");
    command!(
        ec.allowance_invalid(&Default::default()),
        "AllowanceInvalid"
    );
    command!(
        ec.allowance_by_collegiate(&Default::default()),
        "AllowanceByCollegiate"
    );
    command!(
        ec.allowance_invalid_by_collegiate(&Default::default()),
        "AllowanceInvalidByCollegiate"
    );
    assert_eq!(
        paths.lock().unwrap_or_else(|e| e.into_inner()).len(),
        10,
        "every command was sent once"
    );
}

/// Query calls return RtnCode verbatim (a "not found" is a normal result),
/// and hit their spec action names (GetAllowance, not the spec page's
/// GetAllowanceList).
#[tokio::test]
async fn queries_return_rtn_code_verbatim_and_hit_their_action_names() {
    let (ec, paths) = mock(serde_json::json!({"RtnCode": 2, "RtnMsg": "查無資料"}));

    macro_rules! query {
        ($call:expr, $name:literal) => {{
            let out = $call
                .await
                .expect(concat!($name, " is a query: RtnCode!=1 must be Ok"));
            assert_eq!(out.rtn_code, 2, $name);
            assert_eq!(out.rtn_msg, "查無資料", $name);
            let last = paths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .last()
                .cloned()
                .unwrap();
            assert_eq!(last, concat!("/", $name), "wire action name");
        }};
    }

    query!(ec.check_barcode(&Default::default()), "CheckBarcode");
    query!(
        ec.get_company_name_by_tax_id(&Default::default()),
        "GetCompanyNameByTaxID"
    );
    query!(
        ec.get_gov_invoice_word_setting(&Default::default()),
        "GetGovInvoiceWordSetting"
    );
    query!(
        ec.get_invoice_word_setting(&Default::default()),
        "GetInvoiceWordSetting"
    );
    query!(ec.get_issue(&Default::default()), "GetIssue");
    query!(ec.trigger_issue(&Default::default()), "TriggerIssue");
    query!(ec.get_invalid(&Default::default()), "GetInvalid");
    query!(ec.check_love_code(&Default::default()), "CheckLoveCode");
    query!(ec.get_allowance(&Default::default()), "GetAllowance");
    query!(
        ec.get_allowance_invalid(&Default::default()),
        "GetAllowanceInvalid"
    );
    assert_eq!(
        paths.lock().unwrap_or_else(|e| e.into_inner()).len(),
        10,
        "every query was sent once"
    );
}

/// A successful command returns the decoded output (RtnCode 1 plus the
/// payload fields).
#[tokio::test]
async fn commands_return_the_decoded_output_on_success() {
    let (ec, _) = mock(serde_json::json!({
        "RtnCode": 1, "RtnMsg": "開立發票成功",
        "InvoiceNo": "AB12345678", "InvoiceDate": "2024-01-02 15:04:05", "RandomNumber": "1234"
    }));
    let out = ec.issue(&IssueInput::default()).await.expect("Issue");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.invoice_no, "AB12345678");
    assert_eq!(out.invoice_date, "2024-01-02 15:04:05");
    assert_eq!(out.random_number, "1234");
}

/// `issue()` surfaces failures as plain `Result` errors: a business
/// rejection as `Error::Api` (code + RtnMsg carried in the error — ECPay
/// returns empty InvoiceNo/InvoiceDate on failure, so no partial output is
/// needed), a TransCode gate failure as `Error::TransCode`.
#[tokio::test]
async fn issue_surfaces_api_and_transcode_failures_as_errors() {
    let (ec, _) = mock(serde_json::json!({
        "RtnCode": 2, "RtnMsg": "mock rejection", "InvoiceDate": "2024-01-02 15:04:05"
    }));
    let err = ec
        .issue(&IssueInput::default())
        .await
        .expect_err("RtnCode 2 is a business rejection");
    assert_api_rejection(err, "issue");

    // TransCode gate failure: TransCode != 1 → Error::TransCode, no output.
    let srv = spawn_http_server(|_path, _body| {
        let res = ecpay::client::Response {
            trans_code: 128,
            trans_msg: "System exception".to_owned(),
            ..Default::default()
        };
        (
            200,
            "application/json".to_owned(),
            serde_json::to_vec(&res).unwrap(),
        )
    });
    match client(srv)
        .issue(&IssueInput::default())
        .await
        .expect_err("TransCode 128 is an error")
    {
        Error::TransCode { code, msg } => {
            assert_eq!(code, 128);
            assert_eq!(msg, "System exception");
        }
        other => panic!("expected Error::TransCode, got {other:?}"),
    }
}

/// A TransCode=1 envelope whose Data cannot be decoded is an error, never a
/// zero-valued Ok — for a query too.
#[tokio::test]
async fn undecodable_data_is_an_error() {
    // Encrypted under a different key: decrypts to garbage (bad padding or
    // non-UTF-8), never to a valid payload.
    let srv = spawn_http_server(|_path, _body| {
        envelope(
            encrypt_data(
                &serde_json::json!({"RtnCode": 1}),
                b"0000000000000000",
                INVOICE_HASH_IV.as_bytes(),
            )
            .unwrap(),
        )
    });
    let err = client(srv)
        .get_issue(&Default::default())
        .await
        .expect_err("Data under the wrong key must not decode");
    assert!(
        matches!(err, Error::Padding | Error::Message(_)),
        "a wrong-key decrypt must fail at unpad or UTF-8, got {err:?}"
    );

    // Decrypts fine but is not JSON.
    let srv = spawn_http_server(|_path, _body| {
        envelope(
            encrypt(
                b"not-json",
                INVOICE_HASH_KEY.as_bytes(),
                INVOICE_HASH_IV.as_bytes(),
            )
            .unwrap(),
        )
    });
    let err = client(srv)
        .get_issue(&Default::default())
        .await
        .expect_err("non-JSON Data must not decode");
    assert!(matches!(err, Error::Json(_)), "{err:?}");

    // An empty Data string (ECPay's TransCode=1 with nothing to say) is a
    // decrypt error, not a panic.
    let srv = spawn_http_server(|_path, _body| envelope(String::new()));
    let err = client(srv)
        .get_issue(&Default::default())
        .await
        .expect_err("empty Data must not decode");
    assert!(matches!(err, Error::InvalidCiphertextLength(0)), "{err:?}");
}

/// The envelope carries the client's PlatformID verbatim (empty when unset).
#[tokio::test]
async fn envelope_carries_the_platform_id() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = captured.clone();
    let srv = spawn_http_server(move |_path, body| {
        let req: ecpay::client::Request = serde_json::from_slice(body).unwrap();
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(req.platform_id);
        envelope(
            encrypt_data(
                &serde_json::json!({"RtnCode": 1}),
                INVOICE_HASH_KEY.as_bytes(),
                INVOICE_HASH_IV.as_bytes(),
            )
            .unwrap(),
        )
    });
    client(srv.clone())
        .get_issue(&Default::default())
        .await
        .unwrap();
    Ecpay {
        platform_id: "3002599".into(),
        ..client(srv)
    }
    .get_issue(&Default::default())
    .await
    .unwrap();
    assert_eq!(
        *captured.lock().unwrap_or_else(|e| e.into_inner()),
        vec![String::new(), "3002599".to_owned()]
    );
}

/// The Data-level MerchantID contract covers B2C invoice inputs too: a
/// set-but-mismatched Data MerchantID is rejected locally — before any
/// bytes go out (the unreachable base URL below is never touched) —
/// instead of surfacing as ECPay's opaque `RtnCode != 1`. An EMPTY value is
/// deliberately passed through unchanged (legacy wire behavior; whether
/// ECPay accepts it is service-specific and unproven for B2C).
/// `VoidWithReIssue` nests its two MerchantIDs below the top level and is
/// checked field-by-field (`IssueModel` fails even with a valid `VoidModel`).
/// Both refusals are `Error::Validation` — the variant its doc promises for
/// every per-family request guard.
#[tokio::test]
async fn b2c_inputs_carrying_a_mismatched_data_merchant_id_are_rejected_locally() {
    // Port 1 is reserved and never served; an outbound request would fail
    // with Error::Http, so matching Error::Validation proves the local guard.
    let client = client("http://127.0.0.1:1/B2CInvoice/".to_owned());

    let mismatch = IssueInput {
        merchant_id: "someone_else".into(),
        ..Default::default()
    };
    let err = client.issue(&mismatch).await.unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("Data MerchantID"), "{err}");

    // Empty passes through to the wire (fails here only as the transport).
    let empty = IssueInput {
        merchant_id: String::new(),
        ..Default::default()
    };
    let err = client.issue(&empty).await.unwrap_err();
    assert!(matches!(err, Error::Http(_)), "{err:?}");

    let nested = VoidWithReIssueInput {
        void_model: VoidModel {
            merchant_id: "2000132".into(),
            ..Default::default()
        },
        issue_model: IssueModel {
            merchant_id: "someone_else".into(),
            ..Default::default()
        },
    };
    let err = client.void_with_reissue(&nested).await.unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("IssueModel.MerchantID"), "{err}");
}
