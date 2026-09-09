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
