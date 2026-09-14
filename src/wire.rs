//! The `wire_enum!` generator for ECPay 的代碼欄位 (TaxType、Donation…).
//!
//! 產生的 enum 是「前向相容的半開集合」：已知值是 variant，未建模的值
//! 以 [`Other`](#variant.Other) 原樣穿隧（ECPay 會不預警新增值——子付款
//! 方式就發生過；封閉 enum 會把使用者擋到 SDK 更新為止，而
//! `AioCheckOutParams::extra` 逃生口不涵蓋已建模欄位）。
//!
//! 語意約定：
//! - `Default` = `Other("")`——官方 SDK 的空字串 zero-value（wire struct
//!   全欄位 `#[serde(default)]`，未設定的欄位在 wire 上就是 `""`）。
//! - 序列化輸出裸字串（`serialize_str`），與 `String` 欄位的 wire bytes
//!   完全一致（conformance 測試逐位元組釘死）。
//! - 反序列化先取 `String` 再 `From`：未知值 → `Other`，往返透明。
//! - `From<&str>`/`From<String>` 讓 `"1".into()` 建構點繼續可用。
//! - `PartialEq`/`Hash` 以 wire 字串為準：手工建構的 `Other("0")` 與建模的
//!   `No` 相等（`==`）；只有 `match`/`matches!` 仍是結構比對。
//! - `AsRef<str>` 讓 `String` 與 enum 欄位共用同一組插入 helper。

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
        #[derive(Debug, Clone, Eq)]
        #[non_exhaustive]
        pub enum $name {
            $(
                $(#[$meta])*
                $variant,
            )*
            /// 此 SDK 版本尚未建模的 wire 值——原樣穿隧（ECPay 會新增值；
            /// 何謂合法由伺服器裁定，與官方 SDK 行為一致）。
            Other(String),
        }

        impl $name {
            /// The exact wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)*
                    Self::Other(s) => s,
                }
            }

            /// `true` when the field carries no value (`Other("")`).
            pub fn is_unset(&self) -> bool {
                matches!(self, Self::Other(s) if s.is_empty())
            }
        }

        // Identity is the wire string, not the variant: `Other("0")` and the
        // modeled `No` are the same field value to ECPay.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.as_str().hash(state)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
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
                match s {
                    $($value => Self::$variant,)*
                    other => Self::Other(other.to_owned()),
                }
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self::from(s.as_str())
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
