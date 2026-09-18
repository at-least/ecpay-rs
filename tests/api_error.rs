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
