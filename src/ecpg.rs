//! ECPG 站內付 2.0 (EC Payment Gateway) — 綠界線上金流的 AES-JSON API 家族：
//! 站內付取號與建立交易、綁定信用卡 (綁卡)、交易查詢、信用卡請款/退款/
//! 取消/放棄 (DoAction) 與定期定額動作，共 14 個端點。
//!
//! # ⚠️ 雙網域 (dual domain) — 接錯網域必 404
//!
//! ECPG 的端點分散在兩個網域，混用是此服務最經典的 404 陷阱：
//!
//! * 取號 / 建立交易 / 綁卡（8 個）：
//!   `{ecpg_base_url}Merchant/<Action>`，即
//!   `https://ecpg-stage.ecpay.com.tw/Merchant/`
//!   （設定欄位 [`crate::Ecpay::ecpg_api_url`]）。
//! * 查詢 / 請退款 / 動作（6 個）：
//!   `{ecpayment_base_url}<Path>`，Path 本身已含 `Cashier/`、`Credit/`、
//!   `CreditDetail/` 前綴，即
//!   `https://ecpayment-stage.ecpay.com.tw/1.0.0/`
//!   （設定欄位 [`crate::Ecpay::ecpayment_api_url`]）。
//!
//! 每個方法的文件都標示所屬網域；`QueryTrade` 打去 `ecpg` 網域（或反向）
//! 只會拿到 404，不帶任何 ECPay 錯誤碼。
//!
//! # 信封 (envelope)
//!
//! `{"MerchantID", "RqHeader": {"Timestamp"}, "Data": <AES 加密的
//! url-encoded compact JSON>}`。RqHeader **只帶 `Timestamp`**，不帶
//! `Revision`/`RqID`（與 B2C 發票、物流 v2、B2B 不同；2026-09 對 stage
//! 實測：以此信封 `GetTokenbyTrade` 成功取得真實 Token，見
//! `tests/stage_probes.rs`）。加密金鑰使用 **PAYMENT 組**
//! [`crate::Ecpay::hash_key`] / [`crate::Ecpay::hash_iv`]（ECPG 沒有另外
//! 一組金鑰）。
//!
//! # 回應與雙層錯誤檢查
//!
//! 回應為 `{TransCode, TransMsg, Data}`。TransCode != 1（信封層）會以
//! [`crate::Error::TransCode`] 回報；Data 解密後的業務層 `RtnCode` 由呼叫端
//! 自行檢查（1 = 成功）。雙層都要查：先 TransCode 後 RtnCode。
//!
//! 僅 [`GetTokenbyTradeOutput`] 有 stage 實測過的完整欄位型別；其餘 13 個
//! 端點的 Data 欄位集尚未逐一經 stage 驗證，故以 [`serde_json::Value`]
//! 原樣回傳，不做猜測性的強型別。
//!
//! 欄位名稱為 ECPay 規格的逐字名（來源：官方 PHP 範例
//! `ECPay/SDK_PHP/example/Payment/Ecpg/`；GetTokenbyTrade 於 2026-09 對
//! stage 實測驗證）。選用的子物件/欄位以 `Option` 表示，未設定時整個
//! **自 Data 省略**（官方 PHP 範例的做法 — 送空物件或 null 是偏差）。

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Result, Service};
use crate::wire::wire_enum;
use crate::Ecpay;

wire_enum! {
    /// `Credit/DoAction` 的動作 (`Action`,C/R/E/N)。與付款家族的
    /// [`crate::payment::CreditAction`](「信用卡關帳/退刷/取消/放棄」)
    /// 是同一組 wire 代碼,但依本 crate 各家族自有型別的慣例刻意分開
    /// (同 `InvType` 在 invoice/invoice_b2b 各自建模)——兩個 API 家族
    /// 的值域可能各自演進。
    EcpgCreditAction {
        /// 請款/關帳 (C)
        Close => "C",
        /// 退款 (R)
        Refund => "R",
        /// 取消 (E)
        Cancel => "E",
        /// 放棄 (N)
        Abandon => "N",
    }
}

// --- 共用子物件（巢狀 JSON 物件） ---

/// `OrderInfo`：訂單資訊（GetTokenbyTrade / CreatePaymentWithCardID /
/// GetTokenbyBindingCard 共用的巢狀物件）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OrderInfo {
    /// 特店交易時間，格式 `yyyy/MM/dd HH:mm:ss`（UTC+8 台灣時間；海外伺服器
    /// 需先轉時區，ECPay 拒絕時差過大的訂單）。
    #[serde(rename = "MerchantTradeDate")]
    pub merchant_trade_date: String,
    /// 特店交易編號，≤20 字英數字，需唯一。
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    /// 交易金額（TWD 正整數）。ECPay 同時接受 JSON 數字與字串（官方 PHP
    /// 範例送字串、stage 探測送字串皆取得 Token）；本 crate 送 JSON 數字。
    #[serde(rename = "TotalAmount")]
    pub total_amount: i64,
    /// 付款完成通知回呼網址（server 端 JSON POST，須回純文字 `1|OK`）。
    #[serde(rename = "ReturnURL")]
    pub return_url: String,
    /// 交易描述（不可含系統關鍵字，綠界 WAF 會直接攔截）。
    #[serde(rename = "TradeDesc")]
    pub trade_desc: String,
    /// 商品名稱（不可含系統關鍵字，綠界 WAF 會直接攔截）。
    #[serde(rename = "ItemName")]
    pub item_name: String,
}

/// `CardInfo`：信用卡專屬參數（選用子物件 — 未提供時整個自 Data 省略）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CardInfo {
    /// 是否使用紅利折抵 0:不用 1:使用 2:部分折抵。
    #[serde(rename = "Redeem", skip_serializing_if = "Option::is_none")]
    pub redeem: Option<i64>,
    /// 前端結果轉導網址（消費者瀏覽器 form POST 帶 `ResultData`，與
    /// ReturnURL 的 server 端 JSON POST 不同；不用回 `1|OK`）。
    /// `RememberCard=1` 時必填（stage 實測缺漏回 5100010）。
    #[serde(rename = "OrderResultURL", skip_serializing_if = "Option::is_none")]
    pub order_result_url: Option<String>,
    /// 分期期數清單，逗號分隔，如 `"3,6,12"`。
    #[serde(rename = "CreditInstallment", skip_serializing_if = "Option::is_none")]
    pub credit_installment: Option<String>,
    /// 圓夢分期期數。
    #[serde(
        rename = "FlexibleInstallment",
        skip_serializing_if = "Option::is_none"
    )]
    pub flexible_installment: Option<i64>,
}

/// `UnionPayInfo`：銀聯卡專屬參數（選用子物件）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UnionPayInfo {
    /// 前端結果轉導網址（同 [`CardInfo::order_result_url`] 的說明）。
    #[serde(rename = "OrderResultURL", skip_serializing_if = "Option::is_none")]
    pub order_result_url: Option<String>,
}

/// `ATMInfo`：ATM 轉帳專屬參數（選用子物件）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AtmInfo {
    /// 繳費有效天數（天）。
    #[serde(rename = "ExpireDate", skip_serializing_if = "Option::is_none")]
    pub expire_date: Option<i64>,
}

/// `CVSInfo`：超商代碼專屬參數（選用子物件）。注意 `StoreExpireDate` 的
/// 單位是**分鐘**（與 [`BarcodeInfo::store_expire_date`] 的天數不同）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CvsInfo {
    /// 繳費有效時間（分鐘；官方範例值 10080 = 7 天）。
    #[serde(rename = "StoreExpireDate", skip_serializing_if = "Option::is_none")]
    pub store_expire_date: Option<i64>,
}

/// `BarcodeInfo`：超商條碼專屬參數（選用子物件）。`StoreExpireDate` 的
/// 單位是**天**（與 [`CvsInfo::store_expire_date`] 的分鐘不同）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BarcodeInfo {
    /// 繳費有效天數（天）。
    #[serde(rename = "StoreExpireDate", skip_serializing_if = "Option::is_none")]
    pub store_expire_date: Option<i64>,
}

/// `ConsumerInfo`：消費者資訊。stage 實測（2026-09，`tests/sandbox_ecpg.rs`
/// 釘住）：`RememberCard = 1` 時整個 `ConsumerInfo` 為必要——缺漏回
/// `RtnCode 5100010 "The parameter [ConsumerInfo] cannot be empty"`（官方文件
/// 並標 `MerchantMemberID` 此時必填）；`RememberCard = 0` 時可整個省略，仍
/// 取得 Token（官方文件仍把 `ConsumerInfo` 列為必填；以上以 stage 實測為
/// 準）。官方文件另標 `Email` 或 `Phone` 擇一必填，本 crate 不在本機驗證。
/// 參數驗證失敗時 `RtnMsg` 會點名該參數（實測 5100010 / 5100080 /
/// 5100074），並非空白。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsumerInfo {
    /// 會員綁卡代號（綁卡流程用；一般取號可省略）。
    #[serde(rename = "MerchantMemberID", skip_serializing_if = "Option::is_none")]
    pub merchant_member_id: Option<String>,
    /// 消費者電子信箱（官方文件：`Email` 或 `Phone` 擇一必填；見型別層級說明）。
    /// 留空時仍以空字串上 wire（非省略）——這對 ECPay 是無效請求，由伺服器
    /// 點名回錯（5100010 系）；本 crate 不在本機擋，讓錯誤訊息保持伺服器真相。
    #[serde(rename = "Email")]
    pub email: String,
    /// 消費者手機號碼（官方文件：`Email` 或 `Phone` 擇一必填；見型別層級說明）。
    /// 留空時仍以空字串上 wire（非省略），同 [`Self::email`] 的理由。
    #[serde(rename = "Phone")]
    pub phone: String,
    /// 消費者姓名。
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 國別碼，`"158"` = 台灣。
    #[serde(rename = "CountryCode", skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    /// 消費者地址。
    #[serde(rename = "Address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// --- ecpg 網域（Merchant/）家族的輸入 ---

/// `GetTokenbyTrade`（站內付 2.0 取號，站內付流程的第一歩）的 Data 內容。
/// 取得的 Token 交給前端 JS SDK 建立付款畫面，之後以 [`CreatePaymentInput`]
/// 的 `PayToken` 送回。
///
/// stage 實測（2026-09，公開測試帳號 3002607）：缺漏的參數會被**逐一**點名
/// 回 RtnCode 5100010 "The parameter \[&lt;Param&gt;\] cannot be empty"
/// （實測中 `CardInfo.OrderResultURL` 與 `ATMInfo` 都曾被點名）；官方 PHP
/// CreateAllOrder 範例送 OrderInfo + CardInfo + UnionPayInfo + ATMInfo +
/// CVSInfo + BarcodeInfo + ConsumerInfo。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetTokenbyTradeInput {
    /// 特店編號。ECPay 要求 Data 內也要帶（信封另由 client 的
    /// `merchant_id` 帶一次），兩處必須一致 — 方法會在本機先檢查。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 是否記憶卡號 0:不記憶 1:記憶。設 1 時 `CardInfo.OrderResultURL`
    /// 必填 — stage 實測（2026-09）缺漏回 RtnCode 5100010
    /// "The parameter \[OrderResultURL\] cannot be empty"。
    #[serde(rename = "RememberCard", skip_serializing_if = "Option::is_none")]
    pub remember_card: Option<i64>,
    /// 付款畫面呈現類型（ECPay 規格代碼；官方 stage 範例用 2）。
    #[serde(rename = "PaymentUIType", skip_serializing_if = "Option::is_none")]
    pub payment_ui_type: Option<i64>,
    /// 付款方式清單：逗號分隔的付款方式代碼。`"0"` = **全部**（信用卡 +
    /// 銀聯 + ATM + 超商代碼 + 條碼——官方 CreateAllOrder 範例因此帶齊
    /// CardInfo/UnionPayInfo/ATMInfo/CVSInfo/BarcodeInfo）、`"1"` = 信用卡、
    /// `"2,8"` = 分期、`"3"` = ATM、`"4"` = 超商代碼、`"5"` = 條碼、`"6"` =
    /// 銀聯、`"7"` = Apple Pay（guides/02 §8 種付款方式的 GetToken 差異）。
    #[serde(rename = "ChoosePaymentList")]
    pub choose_payment_list: String,
    /// 訂單資訊。
    #[serde(rename = "OrderInfo", skip_serializing_if = "Option::is_none")]
    pub order_info: Option<OrderInfo>,
    /// 信用卡參數。
    #[serde(rename = "CardInfo", skip_serializing_if = "Option::is_none")]
    pub card_info: Option<CardInfo>,
    /// 銀聯卡參數。
    #[serde(rename = "UnionPayInfo", skip_serializing_if = "Option::is_none")]
    pub union_pay_info: Option<UnionPayInfo>,
    /// ATM 轉帳參數。
    #[serde(rename = "ATMInfo", skip_serializing_if = "Option::is_none")]
    pub atm_info: Option<AtmInfo>,
    /// 超商代碼參數。
    #[serde(rename = "CVSInfo", skip_serializing_if = "Option::is_none")]
    pub cvs_info: Option<CvsInfo>,
    /// 超商條碼參數。
    #[serde(rename = "BarcodeInfo", skip_serializing_if = "Option::is_none")]
    pub barcode_info: Option<BarcodeInfo>,
    /// 消費者資訊（`RememberCard = 1` 時必要，見 [`ConsumerInfo`]）。
    #[serde(rename = "ConsumerInfo", skip_serializing_if = "Option::is_none")]
    pub consumer_info: Option<ConsumerInfo>,
    /// 客戶編號。
    #[serde(rename = "CustomerID", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    /// 特店自訂參數。
    #[serde(rename = "CustomField", skip_serializing_if = "Option::is_none")]
    pub custom_field: Option<String>,
    /// 語系代碼。
    #[serde(rename = "Language", skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// `GetTokenbyTrade` 的 Data 回應。這是 ECPG 家族唯一一個欄位集經 stage
/// 實測（2026-09，取得真實 Token）後做成強型別的端點。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetTokenbyTradeOutput {
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 業務層回應代碼：1 = 成功（信封層 TransCode 已由 crate 閘門檢查）。
    #[serde(rename = "RtnCode")]
    pub rtn_code: i64,
    /// 業務層回應訊息（參數驗證失敗時點名該參數，例如 `5100010 "The
    /// parameter [ConsumerInfo] cannot be empty"`）。
    #[serde(rename = "RtnMsg")]
    pub rtn_msg: String,
    /// 交易用 Token（交給前端 JS SDK；不可存檔長期使用）。
    #[serde(rename = "Token")]
    pub token: String,
    /// Token 到期時間。
    #[serde(rename = "TokenExpireDate")]
    pub token_expire_date: String,
}

/// `CreatePayment`（送出付款；`PayToken` 來自前端 JS SDK）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CreatePaymentInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 前端 JS SDK 取得的付款 Token。因為來自瀏覽器端，此端點無法在
    /// server 端單獨 E2E 測試。
    #[serde(rename = "PayToken")]
    pub pay_token: String,
    /// 特店交易編號 — 必須與取得此 PayToken 的 `GetTokenbyTrade` 所用的
    /// 編號相同。
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
}

/// `CreatePaymentWithCardID`（以已綁定的卡直接付款）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CreatePaymentWithCardIdInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 綁卡代號（綁卡成功後取得）。
    #[serde(rename = "BindCardID")]
    pub bind_card_id: String,
    /// 訂單資訊。
    #[serde(rename = "OrderInfo", skip_serializing_if = "Option::is_none")]
    pub order_info: Option<OrderInfo>,
    /// 消費者資訊。
    #[serde(rename = "ConsumerInfo", skip_serializing_if = "Option::is_none")]
    pub consumer_info: Option<ConsumerInfo>,
    /// 特店自訂參數。
    #[serde(rename = "CustomField", skip_serializing_if = "Option::is_none")]
    pub custom_field: Option<String>,
}

/// `CreateBindCard`（送出綁卡；`BindCardPayToken` 來自前端 JS SDK）的
/// Data 內容。與 [`CreatePaymentInput`] 同樣無法在 server 端單獨 E2E 測試。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CreateBindCardInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 前端 JS SDK 取得的綁卡 Token。
    #[serde(rename = "BindCardPayToken")]
    pub bind_card_pay_token: String,
    /// 會員綁卡代號（特店自訂，需唯一）。
    #[serde(rename = "MerchantMemberID")]
    pub merchant_member_id: String,
}

/// `GetTokenbyBindingCard`（綁卡取號）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetTokenbyBindingCardInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 消費者資訊。
    #[serde(rename = "ConsumerInfo", skip_serializing_if = "Option::is_none")]
    pub consumer_info: Option<ConsumerInfo>,
    /// 訂單資訊。
    #[serde(rename = "OrderInfo", skip_serializing_if = "Option::is_none")]
    pub order_info: Option<OrderInfo>,
    /// 前端結果轉導網址。
    #[serde(rename = "OrderResultURL", skip_serializing_if = "Option::is_none")]
    pub order_result_url: Option<String>,
    /// 特店自訂參數。
    #[serde(rename = "CustomField", skip_serializing_if = "Option::is_none")]
    pub custom_field: Option<String>,
}

/// `GetTokenbyUser`（綁卡會員取號）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetTokenbyUserInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 消費者資訊。
    #[serde(rename = "ConsumerInfo", skip_serializing_if = "Option::is_none")]
    pub consumer_info: Option<ConsumerInfo>,
}

/// `GetMemberBindCard`（查詢會員綁卡）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GetMemberBindCardInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 會員綁卡代號。
    #[serde(rename = "MerchantMemberID")]
    pub merchant_member_id: String,
    /// 特店交易編號。
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
}

/// `DeleteMemberBindCard`（刪除會員綁卡）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeleteMemberBindCardInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 要刪除的綁卡代號。
    #[serde(rename = "BindCardID")]
    pub bind_card_id: String,
}

// --- ecpayment 網域（查詢/動作）家族的輸入 ---

/// 查詢類端點（`Cashier/QueryTrade`、`Cashier/QueryPaymentInfo`、
/// `CreditDetail/QueryTrade`）共用的交易參照。`PlatformID` 未設定
/// （`None`）時自 Data 省略（stage 實測可省）。`MerchantID` 為**必要**且須
/// 等於 client 的 [`Ecpay::merchant_id`]：stage 對省略回
/// `5000220 "The parameter [MerchantID] is required."`、對不一致回
/// `5000261 "The parameter [MerchantID] does not match."`（2026-09 以原始
/// 信封對三個查詢端點與 DoAction/CreditCardPeriodAction 逐一實測，
/// `tests/stage_probes.rs` 釘住）——「以信封 MerchantID 為準」的舊假設已
/// 證偽，方法會在出網前擋下空值與不一致，與 DoAction/CreditCardPeriodAction
/// 同一防呆。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EcpgTradeRefInput {
    /// 平台商代號（平台商模式才需要）。
    #[serde(rename = "PlatformID", skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,
    /// 特店編號（Data 層必填，須等於 client 的 `merchant_id`；空值或不一致
    /// 由方法在出網前拒絕——stage 的對應回應見 [`EcpgTradeRefInput`]）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 特店交易編號。
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
}

/// `Cashier/QueryTradeMedia`（查詢撥款對帳明細）的 Data 內容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QueryTradeMediaInput {
    /// 特店編號（需與 client 的 merchant_id 一致）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 日期類別（ECPay 規格代碼）。
    #[serde(rename = "DateType")]
    pub date_type: String,
    /// 起始日期，格式 `yyyy-MM-dd`。
    #[serde(rename = "BeginDate")]
    pub begin_date: String,
    /// 結束日期，格式 `yyyy-MM-dd`。
    #[serde(rename = "EndDate")]
    pub end_date: String,
    /// 付款方式代碼（如 `"01"` = 信用卡）；省略時查全部。
    #[serde(rename = "PaymentType", skip_serializing_if = "Option::is_none")]
    pub payment_type: Option<String>,
}

/// `Cashier/CreditCardPeriodAction`（信用卡定期定額動作）的 Data 內容。
/// `PlatformID` 未設定時自 Data 省略；`MerchantID` 為必要（見
/// [`EcpgTradeRefInput`] 的說明）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EcpgPeriodActionInput {
    /// 平台商代號（平台商模式才需要）。
    #[serde(rename = "PlatformID", skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,
    /// 特店編號（Data 層必填，須等於 client 的 `merchant_id`；空值或不一致
    /// 由方法在出網前拒絕——stage 的對應回應見 [`EcpgTradeRefInput`]）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 特店交易編號。
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    /// 動作代碼，如 `"ReAuth"`（重新授權）。
    #[serde(rename = "Action")]
    pub action: String,
}

/// `Credit/DoAction`（信用卡請款/退款/取消/放棄：C/R/E/N）的 Data 內容。
/// 僅適用於**信用卡**交易 — ATM/超商代碼/條碼不支援線上退款 API。
/// `PlatformID` 未設定時自 Data 省略；`MerchantID` 為必要（見
/// [`EcpgTradeRefInput`] 的說明，方法在本機擋下）。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EcpgDoActionInput {
    /// 平台商代號（平台商模式才需要）。
    #[serde(rename = "PlatformID", skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,
    /// 特店編號（Data 層必填，須等於 client 的 `merchant_id`；空值或不一致
    /// 由方法在出網前拒絕——stage 的對應回應見 [`EcpgTradeRefInput`]）。
    #[serde(rename = "MerchantID")]
    pub merchant_id: String,
    /// 特店交易編號。
    #[serde(rename = "MerchantTradeNo")]
    pub merchant_trade_no: String,
    /// 綠界交易編號（ECPay 端的 `TradeNo`，不是特店自訂編號）。
    #[serde(rename = "TradeNo")]
    pub trade_no: String,
    /// 動作:[`EcpgCreditAction`](C=請款/關帳、R=退款、E=取消、N=放棄)。
    #[serde(rename = "Action")]
    pub action: EcpgCreditAction,
    /// 交易金額。
    #[serde(rename = "TotalAmount")]
    pub total_amount: i64,
}

impl Ecpay {
    /// ECPG 全家族共用的送出路徑：Timestamp-only 的 RqHeader、信封
    /// MerchantID 一律是 client 的 [`Ecpay::merchant_id`]，並以 **PAYMENT
    /// 組** HashKey/HashIV（[`Ecpay::hash_key`] / [`Ecpay::hash_iv`]）
    /// 加解密。
    async fn ecpg_post<I: Serialize, O: DeserializeOwned>(
        &self,
        endpoint: String,
        input: &I,
    ) -> Result<O> {
        self.post_aes_json(
            crate::client::AesEndpoint {
                service: Service::Ecpg,
                url: endpoint,
            },
            serde_json::json!({ "Timestamp": crate::client::unix_now() }),
            &self.merchant_id,
            input,
            self.hash_key.as_bytes(),
            self.hash_iv.as_bytes(),
        )
        .await
    }

    /// ECPG 兩個網域的 Data 內都要重複帶一次 MerchantID，且須等於信封的：
    /// stage 對省略與不一致都回**點名參數**的業務錯誤（2026-09 實測，
    /// `tests/stage_probes.rs`：`Merchant/GetTokenbyTrade` 回 5100080 /
    /// 5100074，五支 ecpayment 端點回 5000220 / 5000261），本 crate 在出網前
    /// 先擋下。
    ///
    /// 刻意不提供「Data 帶子特店編號」的逃生口：官方平台商範例的 Data 仍是
    /// `PlatformID` + 特店自己的 `MerchantID` 並列（guides/02 的 DoAction
    /// 範例、guides/03 的 CreditCardPeriodAction 範例），而共用的信封建構
    /// （`post_aes_json`）目前不送 PlatformID——在此現狀下「Data MerchantID
    /// ≠ 信封」的請求只會被 stage 拒絕，本機先擋不會擋掉任何原本可行的
    /// 流程。所有 ECPG 輸入結構的 `MerchantID` 因此一律是 `String`，每個
    /// 方法都先經過這裡；共用 serializer 的 `encrypt_checked` 是第二道防線。
    fn require_data_merchant_id(&self, data_merchant_id: &str) -> Result<()> {
        self.require_data_merchant_id_with(
            data_merchant_id,
            "; ECPay requires it inside Data too and rejects an omitted or \
             mismatched value by name (live 2026-09: 5100080/5100074 on \
             Merchant/GetTokenbyTrade, 5000220/5000261 on the ecpayment domain)",
        )
    }

    /// `GetTokenbyTrade`（站內付 2.0 取號）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：`{ecpg_base_url}Merchant/GetTokenbyTrade`。
    /// 查詢/請款動作請走 [`Self::ecpg_query_trade`] 等 ecpayment 網域方法，
    /// 打錯網域會 404。
    ///
    /// 回傳的 [`GetTokenbyTradeOutput::rtn_code`] 由呼叫端檢查（1 = 成功）；
    /// 參數驗證失敗時 `RtnMsg` 會點名該參數（5100010，例如 `RememberCard = 1`
    /// 而缺 `ConsumerInfo`）。
    pub async fn get_token_by_trade(
        &self,
        input: &GetTokenbyTradeInput,
    ) -> Result<GetTokenbyTradeOutput> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "GetTokenbyTrade"),
            input,
        )
        .await
    }

    /// `CreatePayment`（送出付款；`PayToken` 來自前端 JS SDK）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：`{ecpg_base_url}Merchant/CreatePayment`。
    ///
    /// 回傳 `serde_json::Value`（欄位集尚未經 stage 逐一驗證）。回應中的
    /// `ThreeDInfo.ThreeDURL` 非空時前端**必須**導向 3D 驗證頁（2025/8 起
    /// 幾乎必出現，略過會交易逾時）。
    pub async fn create_payment(&self, input: &CreatePaymentInput) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "CreatePayment"),
            input,
        )
        .await
    }

    /// `CreatePaymentWithCardID`（以已綁定的卡直接付款，幕後授權）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：
    /// `{ecpg_base_url}Merchant/CreatePaymentWithCardID`。
    ///
    /// 決策備註：官方 PHP 範例的 Data 內還帶一個**空字串** `PlatformID`；
    /// 本 crate 刻意省略它 — stage 對 absence 與 `''` 同樣接受，空欄位不
    /// 攜帶資訊，送出反而誤導平台商模式的判斷。
    pub async fn create_payment_with_card_id(
        &self,
        input: &CreatePaymentWithCardIdInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "CreatePaymentWithCardID"),
            input,
        )
        .await
    }

    /// `CreateBindCard`（送出綁卡；`BindCardPayToken` 來自前端 JS SDK）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：`{ecpg_base_url}Merchant/CreateBindCard`。
    pub async fn create_bind_card(&self, input: &CreateBindCardInput) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "CreateBindCard"),
            input,
        )
        .await
    }

    /// `GetTokenbyBindingCard`（綁卡取號）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：
    /// `{ecpg_base_url}Merchant/GetTokenbyBindingCard`。
    pub async fn get_token_by_binding_card(
        &self,
        input: &GetTokenbyBindingCardInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "GetTokenbyBindingCard"),
            input,
        )
        .await
    }

    /// `GetTokenbyUser`（綁卡會員取號）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：`{ecpg_base_url}Merchant/GetTokenbyUser`。
    pub async fn get_token_by_user(
        &self,
        input: &GetTokenbyUserInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "GetTokenbyUser"),
            input,
        )
        .await
    }

    /// `GetMemberBindCard`（查詢會員綁卡）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：
    /// `{ecpg_base_url}Merchant/GetMemberBindCard`。
    pub async fn get_member_bind_card(
        &self,
        input: &GetMemberBindCardInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "GetMemberBindCard"),
            input,
        )
        .await
    }

    /// `DeleteMemberBindCard`（刪除會員綁卡）。
    ///
    /// ⚠️ 端點在 **ecpg 網域**：
    /// `{ecpg_base_url}Merchant/DeleteMemberBindCard`。
    pub async fn delete_member_bind_card(
        &self,
        input: &DeleteMemberBindCardInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpg_base_url(), "DeleteMemberBindCard"),
            input,
        )
        .await
    }

    /// `Cashier/QueryTrade`（查詢站內付訂單狀態）。
    ///
    /// ⚠️ 端點在 **ecpayment 網域**（查詢不走 ecpg，打錯會 404）：
    /// `{ecpayment_base_url}Cashier/QueryTrade`。
    /// stage 實測(2026-09,查無訂單):`Data` 解密後為
    /// `{"RtnCode":10000185,"RtnMsg":"Cant not find the trade data"}`
    /// (RtnCode 為整數)。
    ///
    /// ⚠️ Data 內的 `MerchantID` 為**必要**且須等於 client 的 `merchant_id`
    /// （方法在出網前檢查；stage 對省略回 `5000220`、不一致回 `5000261`，
    /// 見 [`EcpgTradeRefInput`]）。
    pub async fn ecpg_query_trade(&self, input: &EcpgTradeRefInput) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpayment_base_url(), "Cashier/QueryTrade"),
            input,
        )
        .await
    }

    /// `Cashier/QueryPaymentInfo`（查詢 ATM/CVS/條碼取號結果）。
    ///
    /// ⚠️ 端點在 **ecpayment 網域**：
    /// `{ecpayment_base_url}Cashier/QueryPaymentInfo`。
    /// stage 實測(2026-09,查無訂單):`Data` 解密後為
    /// `{"RtnCode":10000185,"RtnMsg":"Cant not find the trade data"}`
    /// (RtnCode 為整數)。
    ///
    /// ⚠️ Data 內的 `MerchantID` 為**必要**且須等於 client 的 `merchant_id`
    /// （方法在出網前檢查；stage 對省略回 `5000220`、不一致回 `5000261`，
    /// 見 [`EcpgTradeRefInput`]）。
    pub async fn ecpg_query_payment_info(
        &self,
        input: &EcpgTradeRefInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpayment_base_url(), "Cashier/QueryPaymentInfo"),
            input,
        )
        .await
    }

    /// `Cashier/QueryTradeMedia`（查詢撥款對帳明細）。
    ///
    /// ⚠️ 端點在 **ecpayment 網域**：
    /// `{ecpayment_base_url}Cashier/QueryTradeMedia`。
    pub async fn ecpg_query_trade_media(
        &self,
        input: &QueryTradeMediaInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpayment_base_url(), "Cashier/QueryTradeMedia"),
            input,
        )
        .await
    }

    /// `Cashier/CreditCardPeriodAction`（定期定額動作：暫停/終止/重新授權）。
    ///
    /// ⚠️ 端點在 **ecpayment 網域**：
    /// `{ecpayment_base_url}Cashier/CreditCardPeriodAction`。
    ///
    /// ⚠️ Data 內的 `MerchantID` 為**必要**（stage 實測 2026-09：省略時回
    /// `5000220 "The parameter [MerchantID] is required."`；帶了則正確回
    /// 業務錯誤，例如查無訂單 `90100150 不存在的訂單` 並原樣回響
    /// MerchantID/MerchantTradeNo）。
    /// 官方 PHP 範例另帶 `PlatformID`，實測可省略。
    pub async fn ecpg_credit_card_period_action(
        &self,
        input: &EcpgPeriodActionInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpayment_base_url(), "Cashier/CreditCardPeriodAction"),
            input,
        )
        .await
    }

    /// `Credit/DoAction`（信用卡請款 C / 退款 R / 取消 E / 放棄 N）。
    /// 僅適用信用卡交易 — ATM/超商不支援線上退款。
    ///
    /// ⚠️ 端點在 **ecpayment 網域**：
    /// `{ecpayment_base_url}Credit/DoAction`。
    ///
    /// ⚠️ Data 內的 `MerchantID` 為**必要**（stage 實測 2026-09：省略時回
    /// `5000220 "The parameter [MerchantID] is required."`；帶了則查無訂單回
    /// `RtnCode 10000185 "Cant not find the trade data"`）。
    pub async fn ecpg_do_action(&self, input: &EcpgDoActionInput) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        // A negative amount is never a valid wire value (same stance as the
        // payment family's money fields); zero stays allowed — whether zero
        // is accepted is a server-side rule.
        if input.total_amount < 0 {
            return Err(crate::error::Error::Validation(
                "TotalAmount cannot be negative.".into(),
            ));
        }
        self.ecpg_post(
            crate::client::join_url(self.ecpayment_base_url(), "Credit/DoAction"),
            input,
        )
        .await
    }

    /// `CreditDetail/QueryTrade`（查詢信用卡交易明細）。
    ///
    /// ⚠️ 端點在 **ecpayment 網域**：
    /// `{ecpayment_base_url}CreditDetail/QueryTrade`。
    /// stage 實測(2026-09,查無訂單):`Data` 解密後為
    /// `{"RtnCode":10000185,"RtnMsg":"Cant not find the trade data"}`
    /// (RtnCode 為整數)。
    ///
    /// ⚠️ Data 內的 `MerchantID` 為**必要**且須等於 client 的 `merchant_id`
    /// （方法在出網前檢查；stage 對省略回 `5000220`、不一致回 `5000261`，
    /// 見 [`EcpgTradeRefInput`]）。
    pub async fn ecpg_query_credit_trade(
        &self,
        input: &EcpgTradeRefInput,
    ) -> Result<serde_json::Value> {
        self.require_data_merchant_id(&input.merchant_id)?;
        self.ecpg_post(
            crate::client::join_url(self.ecpayment_base_url(), "CreditDetail/QueryTrade"),
            input,
        )
        .await
    }
}

impl Ecpay {
    /// 解密站內付 2.0 的 `ReturnURL` 付款結果回呼（JSON POST）。
    ///
    /// 官方處理順序（guides/21 引官方規格 9058.md）：
    /// 1. 解析 JSON body（`{TransCode, TransMsg, Data}`；不是帶 `TransCode`
    ///    鍵的 JSON 物件、或鍵存在但值不符信封型別時回
    ///    [`crate::Error::Message`]，訊息只引用有界、跳脫過的 body 節錄）；
    /// 2. 檢查外層 `TransCode == 1`（信封層；否則回 [`crate::Error::TransCode`]）；
    /// 3. 用 **PAYMENT 組** HashKey/HashIV AES 解密 `Data`；
    /// 4. 內層 `RtnCode`（業務層，1 = 付款成功）由呼叫端自行檢查 —— 本方法
    ///    刻意不做業務層判斷；
    /// 5. 回應**純文字** `1|OK`（精確格式，含引號/小寫/換行都會觸發重送）。
    ///
    /// # 錯誤形狀（padding oracle 防護）
    ///
    /// 此端點解密的是攻擊者可篡改的 CBC 密文，而信封不認證 `Data`，因此
    /// 解密失敗的**內容相關**分支（padding/UTF-8/JSON/URL-escape）一律收斂
    /// 為同一則固定訊息 [`crate::Error::Message`]（"callback payload failed
    /// to decrypt or parse"），讓 oracle 無從區分；僅 base64/長度/金鑰長度
    /// 這類只取決於攻擊者已輸入資訊的錯誤保持原樣。**呼叫端（商戶
    /// handler）也必須配合**：對所有回呼錯誤回同一個 HTTP 回應、加
    /// rate limit、絕不把 `Error` 的 Display 原文回進 response —— 見
    /// README 的回呼處理清單。
    ///
    /// 與物流側的 [`Ecpay::decrypt_logistics_callback`] 對稱：差別只在金鑰
    /// （ECPG 用 PAYMENT 組、物流用 LOGISTICS 組）。
    pub fn decrypt_ecpg_callback<T: serde::de::DeserializeOwned>(
        &self,
        posted_json: &str,
    ) -> Result<T> {
        Self::decode_envelope_opaque(
            posted_json,
            self.hash_key.as_bytes(),
            self.hash_iv.as_bytes(),
        )
    }
}
