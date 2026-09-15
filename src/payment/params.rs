//! Form-parameter validation and optional-field insertion helpers shared by
//! the All-in-One checkout builder ([`super::check_out`]) and the server-side
//! payment APIs ([`super`]).
//!
//! Error message wording (including the official SDK's "langth" typo) is
//! verbatim-pinned; do not "fix" it.

use std::collections::HashMap;

use super::Error;
use crate::wire::WireCode;

/// Python `len()` on a `str` counts Unicode scalar values.
pub(crate) fn py_len(s: &str) -> usize {
    s.chars().count()
}

/// The official SDK's "content is required." check on its own — for the
/// fields it never length-checks (the invoice item lists) and for the
/// wire-code enums.
pub(crate) fn required_nonempty(name: &str, v: &str) -> Result<(), Error> {
    if v.is_empty() {
        return Err(Error::Validation(format!("{name} content is required.")));
    }
    Ok(())
}

pub(crate) fn required_str(name: &str, v: &str, max: usize) -> Result<(), Error> {
    required_nonempty(name, v)?;
    if py_len(v) > max {
        // "langth" preserves the official SDK's exception message verbatim.
        return Err(Error::Validation(format!("{name} max langth is {max}.")));
    }
    Ok(())
}

pub(crate) fn optional_str(name: &str, v: &Option<String>, max: usize) -> Result<(), Error> {
    if let Some(v) = v {
        if py_len(v) > max {
            // "langth" preserves the official SDK's exception message verbatim.
            return Err(Error::Validation(format!("{name} max langth is {max}.")));
        }
    }
    Ok(())
}

/// Required wire-code check: the official SDK's message for a missing
/// value; the VALUE itself is adjudicated by ECPay (unknown codes pass
/// through as `Other`), so there is no length cap.
pub(crate) fn required_code<T: WireCode>(name: &str, v: &T) -> Result<(), Error> {
    required_nonempty(name, v.as_str())
}

/// filter_parameter: non-required values are dropped when empty. The single
/// body behind the typed entry points below.
fn insert_nonempty(m: &mut HashMap<String, String>, key: &str, v: Option<&str>) {
    if let Some(v) = v.filter(|v| !v.is_empty()) {
        m.insert(key.to_owned(), v.to_owned());
    }
}

/// filter_parameter for a `String` field.
pub(crate) fn insert_optional_str(m: &mut HashMap<String, String>, key: &str, v: &Option<String>) {
    insert_nonempty(m, key, v.as_deref());
}

/// filter_parameter for a wire-code field: `None` and unset (`Other("")`)
/// are dropped. A distinct entry point from [`insert_optional_str`] so a
/// `String` field and a code field cannot be swapped at a call site.
pub(crate) fn insert_optional_code<T: WireCode>(
    m: &mut HashMap<String, String>,
    key: &str,
    v: &Option<T>,
) {
    insert_nonempty(m, key, v.as_ref().map(T::as_str));
}

/// filter_parameter: non-required ints are dropped when negative; 0 stays.
pub(crate) fn insert_optional_int(m: &mut HashMap<String, String>, key: &str, v: &Option<i64>) {
    if let Some(n) = v {
        if *n >= 0 {
            m.insert(key.to_owned(), n.to_string());
        }
    }
}

/// Ordered-pairs form of [`insert_nonempty`] (AIO's grouped params keep
/// insertion order).
fn push_nonempty(v: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(s) = value.filter(|s| !s.is_empty()) {
        v.push((key.to_owned(), s.to_owned()));
    }
}

/// Ordered-pairs variant of [`insert_optional_str`].
pub(crate) fn insert_optional_str_seq(
    v: &mut Vec<(String, String)>,
    key: &str,
    value: &Option<String>,
) {
    push_nonempty(v, key, value.as_deref());
}

/// Ordered-pairs variant of [`insert_optional_code`].
pub(crate) fn insert_optional_code_seq<T: WireCode>(
    v: &mut Vec<(String, String)>,
    key: &str,
    value: &Option<T>,
) {
    push_nonempty(v, key, value.as_ref().map(T::as_str));
}

/// Ordered-pairs variant of [`insert_optional_int`].
pub(crate) fn insert_optional_int_seq(
    v: &mut Vec<(String, String)>,
    key: &str,
    value: &Option<i64>,
) {
    if let Some(n) = value {
        if *n >= 0 {
            v.push((key.to_owned(), n.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_str_rejects_empty_and_overlong() {
        assert_eq!(
            required_str("TradeDesc", "", 5).unwrap_err().to_string(),
            "ecpay: TradeDesc content is required."
        );
        // "langth" typo is verbatim from the official SDK.
        assert_eq!(
            required_str("TradeDesc", "abcdef", 5)
                .unwrap_err()
                .to_string(),
            "ecpay: TradeDesc max langth is 5."
        );
        // Python len(): counts chars, not bytes.
        assert!(required_str("TradeDesc", "中文中文中", 5).is_ok());
        assert!(required_str("TradeDesc", "中文中文中文", 5).is_err());
    }

    #[test]
    fn optional_str_only_checks_when_present() {
        assert!(optional_str("Remark", &None, 3).is_ok());
        assert!(optional_str("Remark", &Some("abcd".into()), 3).is_err());
        assert!(optional_str("Remark", &Some("abc".into()), 3).is_ok());
    }

    #[test]
    fn insert_optional_skips_none_and_empty() {
        let mut m = HashMap::new();
        insert_optional_str(&mut m, "A", &None);
        insert_optional_str(&mut m, "B", &Some(String::new()));
        insert_optional_int(&mut m, "C", &None);
        insert_optional_int(&mut m, "D", &Some(-1));
        assert!(m.is_empty());
        insert_optional_str(&mut m, "E", &Some("v".into()));
        insert_optional_int(&mut m, "F", &Some(0)); // 0 stays
        assert_eq!(m["E"], "v");
        assert_eq!(m["F"], "0");
    }

    #[test]
    fn code_variants_drop_none_and_unset_and_send_the_wire_string() {
        use crate::payment::PrintMark;
        let mut m = HashMap::new();
        insert_optional_code(&mut m, "A", &None::<PrintMark>);
        insert_optional_code(&mut m, "B", &Some(PrintMark::default())); // Other("")
        assert!(m.is_empty());
        insert_optional_code(&mut m, "C", &Some(PrintMark::Yes));
        insert_optional_code(&mut m, "D", &Some(PrintMark::Other("7".into())));
        assert_eq!(m["C"], "1");
        assert_eq!(m["D"], "7");

        let mut v = Vec::new();
        insert_optional_code_seq(&mut v, "A", &Some(PrintMark::default()));
        insert_optional_code_seq(&mut v, "B", &Some(PrintMark::No));
        assert_eq!(v, vec![("B".into(), "0".into())]);

        assert_eq!(
            required_code("Print", &PrintMark::default())
                .unwrap_err()
                .to_string(),
            Error::Validation("Print content is required.".into()).to_string()
        );
        assert!(required_code("Print", &PrintMark::Other("7".into())).is_ok());
    }

    #[test]
    fn seq_variants_keep_insertion_order_and_same_filter() {
        let mut v = Vec::new();
        insert_optional_str_seq(&mut v, "A", &None);
        insert_optional_str_seq(&mut v, "B", &Some("b".into()));
        insert_optional_int_seq(&mut v, "C", &Some(-5));
        insert_optional_int_seq(&mut v, "D", &Some(7));
        assert_eq!(v, vec![("B".into(), "b".into()), ("D".into(), "7".into())]);
    }
}
