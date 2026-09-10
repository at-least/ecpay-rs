//! The `go_float` serializer writes the AES wire bytes for every
//! Item/AllowanceItem ItemCount/ItemPrice/ItemAmount, so its output must be
//! byte-identical to Go's `encoding/json` (the reference port). Expected
//! strings below are ground truth from `go1.27 json.Marshal` on each value
//! (scratch program, 2026-09):
//!
//! ```text
//! 1 => 1                      100.25 => 100.25
//! 0 => 0                      12345678.9 => 12345678.9
//! -0 => -0                    1e+20 => 100000000000000000000
//! 0.5 => 0.5                  1.2345678901234568e+20 => 123456789012345680000
//! 0.1 => 0.1                  1e+21 => 1e+21
//! 100 => 100                  1.5e+21 => 1.5e+21
//! 1e-06 => 0.000001           1e-07 => 1e-7
//! 3e-07 => 3e-7               1e-05 => 0.00001
//! 2.5e-05 => 0.000025         -2.5 => -2.5
//! 123456.789 => 123456.789    1e+300 => 1e+300
//! 5e-324 => 5e-324            1e+06 => 1000000
//! 652171443578374.25 => 652171443578374.2
//! NaN / +Inf / -Inf => json: unsupported value: NaN / +Inf / -Inf
//! ```

use ecpay::Item;

#[derive(serde::Serialize, serde::Deserialize)]
struct F {
    #[serde(with = "ecpay::crypto::go_float")]
    v: f64,
}

fn render(v: f64) -> String {
    let s = serde_json::to_string(&F { v }).expect("finite f64 serializes");
    s.strip_prefix("{\"v\":")
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or_else(|| panic!("unexpected shape {s}"))
        .to_owned()
}

#[test]
fn integral_values_have_no_trailing_zero() {
    assert_eq!(render(1.0), "1");
    assert_eq!(render(0.0), "0");
    assert_eq!(render(-0.0), "-0");
    assert_eq!(render(100.0), "100");
    assert_eq!(render(1e6), "1000000");
    assert_eq!(render(1e20), "100000000000000000000");
    assert_eq!(render(1.2345678901234568e20), "123456789012345680000");
}

#[test]
fn fractional_values_use_the_shortest_round_trip_digits() {
    assert_eq!(render(0.5), "0.5");
    assert_eq!(render(0.1), "0.1");
    assert_eq!(render(100.25), "100.25");
    assert_eq!(render(12345678.9), "12345678.9");
    assert_eq!(render(-2.5), "-2.5");
    assert_eq!(render(123456.789), "123456.789");
    // Exact halfway case: Go and ryu both round to even here.
    // The literal 652171443578374.25 is exactly representable (ulp 0.125
    // at this magnitude) and both Go and ryu print it as ...374.2; the
    // shortest-form literal parses to the same f64 (clippy rejects the
    // longer spelling as excessive precision).
    assert_eq!(render(652_171_443_578_374.2), "652171443578374.2");
}

#[test]
fn small_magnitudes_stay_plain_down_to_1e_minus_6() {
    assert_eq!(render(1e-5), "0.00001");
    assert_eq!(render(2.5e-5), "0.000025");
    assert_eq!(render(1e-6), "0.000001");
}

#[test]
fn exponent_notation_matches_go_outside_the_plain_range() {
    assert_eq!(render(1e21), "1e+21", "plus sign kept, no zero padding");
    assert_eq!(render(1.5e21), "1.5e+21");
    assert_eq!(render(1e300), "1e+300");
    assert_eq!(
        render(1e-7),
        "1e-7",
        "Go strips the exponent's leading zero"
    );
    assert_eq!(render(3e-7), "3e-7");
    assert_eq!(render(5e-324), "5e-324");
}

#[test]
fn non_finite_values_are_a_serialization_error() {
    for (v, name) in [
        (f64::NAN, "NaN"),
        (f64::INFINITY, "+Inf"),
        (f64::NEG_INFINITY, "-Inf"),
    ] {
        let err = serde_json::to_string(&F { v }).expect_err(name);
        assert!(
            err.to_string()
                .contains(&format!("json: unsupported value: {name}")),
            "{name}: {err}"
        );
    }
}

#[test]
fn deserialize_accepts_integers_and_fractions() {
    let f: F = serde_json::from_str(r#"{"v":1}"#).unwrap();
    assert_eq!(f.v, 1.0);
    let f: F = serde_json::from_str(r#"{"v":1.5}"#).unwrap();
    assert_eq!(f.v, 1.5);
    let f: F = serde_json::from_str(r#"{"v":1e-7}"#).unwrap();
    assert_eq!(f.v, 1e-7);
}

/// The reason the serializer exists: an `Item` must hit the wire as Go
/// marshals it (`"ItemCount":1`), never as serde_json's `1.0`.
#[test]
fn item_serializes_like_go() {
    let s = serde_json::to_string(&Item {
        item_seq: 1,
        item_name: "x".into(),
        item_count: 1.0,
        item_word: "個".into(),
        item_price: 100.0,
        item_tax_type: "1".into(),
        item_amount: 100.0,
        item_remark: String::new(),
    })
    .unwrap();
    assert!(s.contains(r#""ItemCount":1,"#), "{s}");
    assert!(s.contains(r#""ItemPrice":100,"#), "{s}");
    assert!(s.contains(r#""ItemAmount":100,"#), "{s}");
    assert!(!s.contains("1.0"), "{s}");

    let s = serde_json::to_string(&Item {
        item_count: 2.5,
        item_price: 0.1,
        ..Default::default()
    })
    .unwrap();
    assert!(s.contains(r#""ItemCount":2.5,"#), "{s}");
    assert!(s.contains(r#""ItemPrice":0.1,"#), "{s}");
}
