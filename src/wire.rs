//! The `wire_enum!` generator for ECPay 的代碼欄位 (TaxType、Donation…).
//!
//! 產生的 enum 是「前向相容的半開集合」：已知值是 variant，未建模的值
//! 以 [`Other`](#variant.Other) 原樣穿隧（ECPay 會不預警新增值——子付款
//! 方式就發生過；封閉 enum 會把使用者擋到 SDK 更新為止，而
//! `AioCheckOutParams::extra` 逃生口不涵蓋已建模欄位）。
//!
//! 語意約定：
//! - `Default` = `Other("")`——官方 SDK 的空字串 zero-value（wire struct
//!   全欄位 `#[serde(default)]`，未設定的欄位在 wire 上就是 `""`）；
//!   `is_unset()` 即「wire 值為空」。
//! - 序列化輸出裸字串（`serialize_str`），與 `String` 欄位的 wire bytes
//!   完全一致（conformance 測試逐位元組釘死）。
//! - 反序列化先取 `String` 再 `From`：已知值正規化為 variant，未知值 →
//!   `Other`，往返透明。
//! - `From<&str>`/`From<String>` 讓 `"1".into()` 建構點繼續可用。
//! - `PartialEq`/`Hash` 是結構比對（derive），與 `match` 一致：手工建構的
//!   `Other("0")` **不等於** 建模的 `No`，即使 wire 值相同。已建模的值請經
//!   `From`/`.into()` 建構；要把手工 `Other` 也算進去時比較 `as_str()`。

/// 巨集產生之 enum 的共用介面（crate 私有）：讓 form 參數 helper 有一個
/// 只接受代碼 enum 的入口，`String` 欄位與代碼欄位在呼叫點無法互換。
pub(crate) trait WireCode {
    /// The exact wire string.
    fn as_str(&self) -> &str;
}

/// Generate a `#[non_exhaustive]` wire-code enum with `Other(String)`
/// passthrough. See the [module](self) docs for the semantics contract.
macro_rules! wire_enum {
    (
        $(#[$outer:meta])*
        $name:ident {
            $(
                $(#[$meta:meta])*
                $variant:ident => $value:literal
            ),* $(,)?
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $(
                $(#[$meta])*
                $variant,
            )*
            /// 此 SDK 版本尚未建模的 wire 值——原樣穿隧（ECPay 會新增值；
            /// 何謂合法由伺服器裁定，與官方 SDK 行為一致）。
            ///
            /// 相等比較是結構性的：`Other("0")` 不等於同 wire 值的建模
            /// variant（與 `match` 一致）。已建模的值請用 `From`/`.into()`
            /// 建構（`From` 與 serde 反序列化都會正規化為 variant）；要接受
            /// 手工 `Other` 時比較 `as_str()`。
            Other(String),
        }

        impl $name {
            /// The modeled variant for a wire string, if this SDK models it.
            fn modeled(s: &str) -> Option<Self> {
                match s {
                    $($value => Some(Self::$variant),)*
                    _ => None,
                }
            }

            /// The exact wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)*
                    Self::Other(s) => s,
                }
            }

            /// `true` when the field carries no value: the wire string is
            /// empty (`Other("")`, the `Default`).
            pub fn is_unset(&self) -> bool {
                self.as_str().is_empty()
            }
        }

        impl crate::wire::WireCode for $name {
            fn as_str(&self) -> &str {
                self.as_str()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::Other(String::new())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self::modeled(s).unwrap_or_else(|| Self::Other(s.to_owned()))
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                // The owned String is kept for `Other` rather than re-allocated.
                Self::modeled(&s).unwrap_or_else(|| Self::Other(s))
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                Ok(Self::from(String::deserialize(d)?))
            }
        }
    };
}

pub(crate) use wire_enum;
