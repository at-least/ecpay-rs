//! The AES wire bytes for every Item/AllowanceItem ItemCount/ItemPrice/
//! ItemAmount and logistics GoodsWeight come from serde_json's default f64
//! formatting via the `finite_f64` helper. This is a deliberate wire change
//! from the former `go_float` emulation of Go's `encoding/json`: integral
//! values now carry a trailing `.0` (`1.0`, not Go's `1`). ECPay's server
//! json-parses the decrypted payload, so `1.0` and `1` are the same JSON
//! number — and the B2B module has sent serde_json-formatted floats to the
//! stage server and been accepted (2026-09, RtnCode=1). Two properties are
//! always serialization errors, never a silently-corrupted payment field:
//! a NON-FINITE value (JSON cannot hold NaN/Infinity; serde_json would
//! silently write `null`), and a value whose rendering would use EXPONENT
//! notation (the plain-decimal window is a serde_json detail that shifts
//! between releases — the consumer's dependency resolution must not decide
//! the wire bytes, and no exponent form has been verified against ECPay).

use ecpay::Item;

#[derive(serde::Serialize, serde::Deserialize)]
struct F {
    #[serde(with = "ecpay::crypto::finite_f64")]
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
fn integral_values_carry_the_trailing_zero() {
    assert_eq!(render(1.0), "1.0");
    assert_eq!(render(0.0), "0.0");
    assert_eq!(render(-0.0), "-0.0");
    assert_eq!(render(100.0), "100.0");
    assert_eq!(render(1e6), "1000000.0");
}

#[test]
fn fractional_values_use_the_shortest_round_trip_digits() {
    assert_eq!(render(0.5), "0.5");
    assert_eq!(render(0.1), "0.1");
    assert_eq!(render(100.25), "100.25");
    assert_eq!(render(12345678.9), "12345678.9");
    assert_eq!(render(-2.5), "-2.5");
    assert_eq!(render(123456.789), "123456.789");
    // Exact halfway case, exactly representable at this magnitude (ulp
    // 0.125): shortest round-trip prints ...374.2 (the shorter literal
    // parses to the same f64; clippy rejects the longer spelling).
    assert_eq!(render(652_171_443_578_374.2), "652171443578374.2");
}

#[test]
fn exponent_notation_is_rejected_so_the_wire_form_is_version_stable() {
    // serde_json switches to exponent notation outside its plain-decimal
    // window (probed on 1.0.151: 1e-5 renders plain, 1e-6 exponent;
    // 1e15 plain, 1e16 exponent) and that window has already shifted
    // between releases (the former pin here recorded `1e+21` on the zmij
    // backend vs `1e21` on pre-zmij ryu). The consumer's dependency
    // resolution must not decide a payment field's wire bytes, and an
    // exponent-form wire value has never been verified against ECPay's
    // parser — so any rendering containing an exponent is a loud local
    // serialization error instead.
    for v in [1e-6, 1e-7, 5e-324, 1e16, 1e21, 1.5e21, 1e300] {
        let err =
            serde_json::to_string(&F { v }).expect_err("exponent rendering must not serialize");
        let msg = err.to_string();
        assert!(msg.contains("exponent notation"), "{v}: {msg}");
    }
    // The plain-decimal window itself is not pinned beyond this pair —
    // the boundary is a serde_json detail and may shift; the guarantee
    // is only "no exponent ever reaches the wire".
    assert_eq!(render(1e15), "1000000000000000.0");
    assert_eq!(render(1e-5), "0.00001");
}

#[test]
fn non_finite_values_are_a_serialization_error() {
    for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let err = serde_json::to_string(&F { v }).expect_err("must not serialize");
        assert!(err.to_string().contains("non-finite float"), "{v}: {err}");
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

/// An `Item` hits the wire with serde_json's formatting: `"ItemCount":1.0`
/// for integral values (the deliberate change), shortest digits otherwise.
#[test]
fn item_serializes_with_serde_json_floats() {
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
    assert!(s.contains(r#""ItemCount":1.0,"#), "{s}");
    assert!(s.contains(r#""ItemPrice":100.0,"#), "{s}");
    assert!(s.contains(r#""ItemAmount":100.0,"#), "{s}");

    let s = serde_json::to_string(&Item {
        item_count: 2.5,
        item_price: 0.1,
        ..Default::default()
    })
    .unwrap();
    assert!(s.contains(r#""ItemCount":2.5,"#), "{s}");
    assert!(s.contains(r#""ItemPrice":0.1,"#), "{s}");

    // A NaN money field never reaches the wire.
    let err = serde_json::to_string(&Item {
        item_price: f64::NAN,
        ..Default::default()
    })
    .expect_err("NaN price must not serialize");
    assert!(err.to_string().contains("non-finite float"), "{err}");
}
