//! Port of Go `api_error_test.go`.

use ecpay::{ApiError, Error};

#[test]
fn test_api_error() {
    let err: Error = Error::Api(ApiError {
        code: 99,
        msg: "boom".to_owned(),
    });

    // errors.As equivalent: the Api variant carries the ApiError.
    let api_err = match &err {
        Error::Api(e) => e,
        _ => panic!("errors.As should match the Api variant"),
    };
    assert_eq!(api_err.code, 99, "Code = {}, want 99", api_err.code);

    let s = err.to_string();
    assert!(
        s.contains("99") && s.contains("boom"),
        "Error() = {s:?}, want it to contain the code and message"
    );
}

/// `ApiError`'s Display renders the server's `RtnMsg` — the same log
/// surface `HttpStatus`/`TransCode` already bound (see their tests above):
/// a hostile endpoint that answers a successfully-encrypted `Data` with a
/// megabyte `RtnMsg` must not turn one log line into a megabyte. The
/// Go-parity `RtnMsg=%q` shape is unchanged for normal messages, and the
/// `msg` field keeps the full verbatim string for programmatic access.
#[test]
fn api_error_display_bounds_the_server_message() {
    // Normal messages keep the Go-parity shape, verbatim.
    assert_eq!(
        ApiError {
            code: 1,
            msg: "Succeeded".to_owned(),
        }
        .to_string(),
        "ecpay: RtnCode=1, RtnMsg=\"Succeeded\""
    );

    let big = "x".repeat(1000);
    let err = ApiError {
        code: 2,
        msg: big.clone(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("ecpay: RtnCode=2, RtnMsg="),
        "{rendered}"
    );
    assert!(
        rendered.contains("truncated") && rendered.chars().count() < 1200,
        "a long RtnMsg must render bounded, got {} chars",
        rendered.chars().count()
    );
    assert_eq!(err.msg.len(), 1000, "the field keeps the full message");

    // Control characters render SINGLE-escaped, exactly like the
    // HttpStatus/TransCode Displays (see their tests above) — not
    // double-escaped by an extra Debug quote — and no raw newline reaches
    // a log line.
    let err = ApiError {
        code: 2,
        msg: "line1\nline2\tTAIL\u{7}".to_owned(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains(r"line1\nline2\tTAIL\u{7}"),
        "control characters must be single-escaped in Display, got {rendered:?}"
    );
    assert!(
        !rendered.contains('\n'),
        "raw newline must not reach Display, got {rendered:?}"
    );
    assert_eq!(err.msg, "line1\nline2\tTAIL\u{7}");
}

/// Every [`ecpay::Service`] gets its own label in the `HttpStatus` Display —
/// a logistics 500 must not render as "ecpay payment API error" (the reason
/// the service-tagged variant replaced `PaymentStatus`/`InvoiceStatus`).
/// The body shape stays Go-parity: `status=%d body=%s`, verbatim within the
/// 512-char bound.
#[test]
fn http_status_display_names_the_service() {
    for (service, want_prefix) in [
        (ecpay::Service::Payment, "ecpay payment API error"),
        (ecpay::Service::Invoice, "ecpay invoice API error"),
        (ecpay::Service::Logistics, "ecpay logistics API error"),
        (ecpay::Service::Ecpg, "ecpay ecpg API error"),
        (ecpay::Service::B2bInvoice, "ecpay b2b invoice API error"),
    ] {
        let err: Error = Error::HttpStatus {
            service,
            status: 500,
            body: "boom".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            format!("{want_prefix}: status=500 body=boom"),
            "wrong label for {service:?}"
        );
    }

    // A long body renders bounded (same 512-char contract the renamed
    // variants had); the field keeps the full body.
    let big = "x".repeat(1000);
    let err: Error = Error::HttpStatus {
        service: ecpay::Service::Logistics,
        status: 502,
        body: big.clone(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("ecpay logistics API error: status=502 body=")
            && rendered.ends_with("… (truncated; 1000 bytes total)"),
        "{rendered}"
    );
    match &err {
        Error::HttpStatus { body, .. } => assert_eq!(body.len(), 1000),
        other => panic!("expected HttpStatus, got {other:?}"),
    }
}

/// `Error::HttpStatus`'s Display echoes a response body into the merchant's
/// logs. Printable text renders verbatim (Go-parity `body=%s`), but control
/// characters are escaped in the RENDERING — raw newlines forge log lines
/// when a hostile body reaches this rendering (defense-in-depth beyond the
/// own-TLS assumption: an injected client or a defeated transport must not
/// turn Display into log injection) — while the `body` field keeps the
/// full verbatim bytes for programmatic access.
#[test]
fn http_status_display_escapes_control_characters() {
    let err: Error = Error::HttpStatus {
        service: ecpay::Service::Payment,
        status: 500,
        body: "line1\nline2\tTAIL\u{7}".to_owned(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains(r"line1\nline2\tTAIL\u{7}"),
        "control characters must be escaped in Display, got {rendered:?}"
    );
    assert!(
        !rendered.contains('\n'),
        "raw newline must not reach Display, got {rendered:?}"
    );
    match &err {
        Error::HttpStatus { body, .. } => {
            assert_eq!(body, "line1\nline2\tTAIL\u{7}");
        }
        other => panic!("expected HttpStatus, got {other:?}"),
    }
}

/// `Error::TransCode`'s Display renders server-supplied `TransMsg` that
/// arrived raw off the AES-JSON API paths — the same log-injection surface
/// `HttpStatus`'s Display already guards (see
/// `http_status_display_escapes_control_characters`): control characters are
/// escaped and long messages bounded in the RENDERING, while the `msg` field
/// keeps the full verbatim string for programmatic access.
#[test]
fn trans_code_display_escapes_and_bounds_the_server_message() {
    let err: Error = Error::TransCode {
        code: 910,
        msg: "line1\nline2\tTAIL\u{7}".to_owned(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains(r"msg=line1\nline2\tTAIL\u{7}"),
        "control characters must be escaped in Display, got {rendered:?}"
    );
    assert!(
        !rendered.contains('\n'),
        "raw newline must not reach Display, got {rendered:?}"
    );
    match &err {
        Error::TransCode { msg, .. } => assert_eq!(msg, "line1\nline2\tTAIL\u{7}"),
        other => panic!("expected TransCode, got {other:?}"),
    }

    // A long message renders bounded (the same 512-char contract); the
    // field keeps the full message.
    let big = "x".repeat(1000);
    let err: Error = Error::TransCode {
        code: 910,
        msg: big.clone(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("ecpay TransCode error: code=910 msg=")
            && rendered.ends_with("… (truncated; 1000 bytes total)"),
        "{rendered}"
    );
    match &err {
        Error::TransCode { msg, .. } => assert_eq!(msg.len(), 1000),
        other => panic!("expected TransCode, got {other:?}"),
    }
}
