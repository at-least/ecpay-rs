//! `wire_enum!` 生成的代碼 enum:as_str 值表逐一釘死(抓 macro/值表筆誤)、
//! Display→From 往返、未知值 serde 往返透明、Default/is_unset 的空字串
//! zero-value 語意。

use ecpay::invoice;
use ecpay::payment::{
    self, CarruerType, ClearanceMark, CreditAction, Donation, InvType, PeriodType, PrintMark,
    TaxType,
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
    assert_eq!(ClearanceMark::ViaCustoms.as_str(), "1");
    assert_eq!(ClearanceMark::NotViaCustoms.as_str(), "2");
    assert_eq!(InvType::General.as_str(), "07");
    assert_eq!(InvType::Special.as_str(), "08");
    assert_eq!(PeriodType::Year.as_str(), "Y");
    assert_eq!(PeriodType::Month.as_str(), "M");
    assert_eq!(PeriodType::Day.as_str(), "D");
    assert_eq!(CreditAction::Close.as_str(), "C");
    assert_eq!(CreditAction::Refund.as_str(), "R");
    assert_eq!(CreditAction::Cancel.as_str(), "E");
    assert_eq!(CreditAction::Abandon.as_str(), "N");

    // B2C 發票語彙(與 AIO 相同欄位名、不同值域/語意的 per-service 型別)。
    assert_eq!(invoice::TaxType::Dutiable.as_str(), "1");
    assert_eq!(invoice::TaxType::ZeroRate.as_str(), "2");
    assert_eq!(invoice::TaxType::Free.as_str(), "3");
    assert_eq!(invoice::TaxType::SpecialTaxable.as_str(), "4");
    assert_eq!(invoice::TaxType::Mixed.as_str(), "9");
    // ⚠ 語意陷阱的實體檢驗:同名欄位在兩個服務的 wire 值相反——
    // AIO Donation 捐贈=1,B2C 發票 Donation 捐贈=1 但不捐贈=0(AIO=2);
    // ClearanceMark 的 1/2 海關語意兩服務互換。型別分開後互抄無法編譯。
    assert_eq!(invoice::Donation::No.as_str(), "0");
    assert_eq!(invoice::Donation::Yes.as_str(), "1");
    assert_eq!(payment::Donation::Yes.as_str(), "1");
    assert_eq!(payment::Donation::No.as_str(), "2");
    assert_eq!(invoice::ClearanceMark::NotViaCustoms.as_str(), "1");
    assert_eq!(invoice::ClearanceMark::ViaCustoms.as_str(), "2");
    assert_eq!(payment::ClearanceMark::ViaCustoms.as_str(), "1");
    assert_eq!(payment::ClearanceMark::NotViaCustoms.as_str(), "2");
    assert_eq!(invoice::PrintMark::No.as_str(), "0");
    assert_eq!(invoice::PrintMark::Yes.as_str(), "1");
    assert_eq!(invoice::CarrierType::Ecpay.as_str(), "1");
    assert_eq!(invoice::CarrierType::Citizen.as_str(), "2");
    assert_eq!(invoice::CarrierType::Cellphone.as_str(), "3");
    assert_eq!(invoice::InvType::General.as_str(), "07");
    assert_eq!(invoice::InvType::Special.as_str(), "08");

    // B2B:值域是 B2C 減去混合 '9'(獨立型別,送 '9' 需刻意 Other)。
    assert_eq!(ecpay::invoice_b2b::TaxType::Dutiable.as_str(), "1");
    assert_eq!(ecpay::invoice_b2b::TaxType::ZeroRate.as_str(), "2");
    assert_eq!(ecpay::invoice_b2b::TaxType::Free.as_str(), "3");
    assert_eq!(ecpay::invoice_b2b::TaxType::SpecialTaxable.as_str(), "4");
    assert_eq!(ecpay::invoice_b2b::InvType::General.as_str(), "07");
    assert_eq!(ecpay::invoice_b2b::InvType::Special.as_str(), "08");
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
    rt(ClearanceMark::ViaCustoms);
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
