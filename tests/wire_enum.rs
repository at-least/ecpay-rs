//! `wire_enum!` 生成的代碼 enum:as_str 值表逐一釘死(抓 macro/值表筆誤)、
//! Display→From 往返、未知值 serde 往返透明、Default/is_unset 的空字串
//! zero-value 語意。

use ecpay::payment::{
    CarruerType, ClearanceMark, CreditAction, Donation, InvType, PeriodType, PrintMark, TaxType,
};

/// 每個 variant 的 wire 值——與官方規格一一對照的單一真相表。
#[test]
fn as_str_tables_are_pinned() {
    assert_eq!(TaxType::Dutiable.as_str(), "1");
    assert_eq!(TaxType::ZeroRate.as_str(), "2");
    assert_eq!(TaxType::Free.as_str(), "3");
    assert_eq!(TaxType::Mixed.as_str(), "9");
    assert_eq!(Donation::Yes.as_str(), "1");
    assert_eq!(Donation::No.as_str(), "2");
    assert_eq!(PrintMark::No.as_str(), "0");
    assert_eq!(PrintMark::Yes.as_str(), "1");
    assert_eq!(CarruerType::Member.as_str(), "1");
    assert_eq!(CarruerType::Citizen.as_str(), "2");
    assert_eq!(CarruerType::Cellphone.as_str(), "3");
    assert_eq!(ClearanceMark::Yes.as_str(), "1");
    assert_eq!(ClearanceMark::No.as_str(), "2");
    assert_eq!(InvType::General.as_str(), "07");
    assert_eq!(InvType::Special.as_str(), "08");
    assert_eq!(PeriodType::Year.as_str(), "Y");
    assert_eq!(PeriodType::Month.as_str(), "M");
    assert_eq!(PeriodType::Day.as_str(), "D");
    assert_eq!(CreditAction::Close.as_str(), "C");
    assert_eq!(CreditAction::Refund.as_str(), "R");
    assert_eq!(CreditAction::Cancel.as_str(), "E");
    assert_eq!(CreditAction::Abandon.as_str(), "N");
}

/// Display → From 的往返:每個已建模 variant 的字串都映射回自己。
#[test]
fn every_modeled_variant_round_trips_through_from() {
    fn rt<T>(v: T)
    where
        T: for<'a> From<&'a str> + PartialEq + std::fmt::Debug + Clone + std::fmt::Display,
    {
        let s = v.to_string();
        assert_eq!(T::from(s.as_str()), v.clone(), "round-trip failed: {s:?}");
    }
    for v in [
        TaxType::Dutiable,
        TaxType::ZeroRate,
        TaxType::Free,
        TaxType::Mixed,
    ] {
        rt(v);
    }
    rt(Donation::Yes);
    rt(Donation::No);
    rt(PrintMark::No);
    rt(PrintMark::Yes);
    rt(CarruerType::Member);
    rt(ClearanceMark::Yes);
    rt(InvType::Special);
    rt(PeriodType::Month);
    rt(CreditAction::Close);
}

/// 未知值(ECPay 未來新增的代碼)以 `Other` 原樣穿隧:序列化是裸字串、
/// 反序列化映射回同一個 `Other`——wire bytes 與 `String` 欄位無異。
#[test]
fn unknown_values_pass_through_serde_verbatim() {
    let unknown = TaxType::from("42");
    assert_eq!(unknown.as_str(), "42");
    assert_eq!(serde_json::to_string(&unknown).unwrap(), r#""42""#);
    let back: TaxType = serde_json::from_str(r#""42""#).unwrap();
    assert_eq!(back, TaxType::Other("42".to_owned()));

    // 與 String 欄位的 wire bytes 完全一致(嵌在 struct 裡也一樣)。
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct S {
        #[serde(rename = "TaxType")]
        tax_type: TaxType,
    }
    let s = S { tax_type: unknown };
    assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"TaxType":"42"}"#);
    let s2: S = serde_json::from_str(r#"{"TaxType":"42"}"#).unwrap();
    assert_eq!(s2, s);
}

/// `Default` = `Other("")`:wire struct `#[serde(default)]` 的未設定欄位
/// 在 wire 上就是空字串(官方 SDK 的 zero-value 語意),且 `is_unset()` 為真。
#[test]
fn default_is_the_empty_zero_value() {
    assert!(TaxType::default().is_unset());
    assert_eq!(TaxType::default().as_str(), "");
    let unset: TaxType = serde_json::from_str(r#""""#).unwrap();
    assert!(unset.is_unset());
    assert_eq!(serde_json::to_string(&TaxType::default()).unwrap(), r#""""#);
}

#[test]
fn modeled_values_are_never_unset() {
    assert!(!TaxType::Dutiable.is_unset());
    assert!(!PrintMark::No.is_unset());
    // 非空的其他未知值也不是 unset。
    assert!(!TaxType::from("42").is_unset());
}
