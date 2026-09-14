# Changelog

## Unreleased

_breaking changes（0.x，未上線前的一次 Rust 慣例清理——移除為了逐字對照
Go 參考移植而保留的形狀）：_

- `Ecpay::issue()` 改回 `Result<IssueOutput>`：原本的 Go named-return 形狀
  `(IssueOutput, Option<Error>)` 移除，`try_issue()` 刪除（與 `issue()` 同
  義）。業務層失敗的 RtnCode/RtnMsg 都在 `Error::Api(ApiError)` 內；ECPay
  規格載明開立失敗時 `InvoiceNo`/`InvoiceDate` 為空值，失敗路徑不需要部分
  輸出。
- `Error::Transport { code, msg }` 更名為 `Error::TransCode { code, msg }`
  （它代表 AES 信封的 TransCode 閘門失敗，不是網路傳輸錯誤；Display 訊息
  一併從 "ecpay transport error" 改為 "ecpay TransCode error"）。
- `Error` 加上 `#[non_exhaustive]`（`ChoosePayment` 亦同）——下游比對需保留
  萬用臂。
- `ecpay::DATE_TIME_FORMAT`（Go 佈局字串 `"2006/01/02 15:04:05"`，在 Rust
  無意義且無人使用）移除。
- `Request` / `Response` / `RqHeader` / `RqHeaderResponse` 不再從 crate
  root re-export（`ecpay::Request` 名稱過泛）；改由 `ecpay::client::` 取用。
- `AioCheckOutParams::payment_type` 欄位移除——AIO 收銀台 wire 上永遠是
  `"aio"`，改為內部固定值，`PaymentType content is required.` 驗證隨欄位
  消失。

_非破壞性：_

- README：安裝版本 `0.2` → `0.3`；「必填欄位編譯期檢查」的過度陳述改為
  如實描述（必填欄位是非 `Option` 型別，值仍於執行期驗證）。

## Unreleased（續）

_go_float 移除（wire 變更）：_

- `crypto::go_float`（逐位元組模擬 Go `encoding/json` 的 float 序列化，
  約 100 行 + ryu 依賴）移除，改為極簡的 `crypto::finite_f64`：有限值用
  serde_json 預設格式（整數值帶尾 `.0`，如 `1.0`；ECPay 伺服器解 JSON，
  `1.0` 與 `1` 是同一個 JSON number），非有限值（NaN/±Inf，serde_json 會
  靜默序列化為 `null`）保持為序列化錯誤。`ItemCount`/`ItemPrice`/
  `ItemAmount`/`GoodsWeight` 的 wire 位元組因此改變。
  Live 證據（2026-09，stage 實測）：B2C Issue/GetIssue/Invalid 往返、
  折讓生命週期、作廢重開、B2B 開立全數 RtnCode=1 通過。
- `Cargo.toml`：移除 `ryu` 與 serde_json 的 `raw_value` feature（皆僅
  go_float 使用）。

## Unreleased（續）

_金鑰型別統一：_

- `Ecpay::invoice_hash_key` / `invoice_hash_iv` / `logistics_hash_key` /
  `logistics_hash_iv` 從 `Vec<u8>` 改為 `String`，與 `hash_key`/`hash_iv`
  一致（呼叫端從 `b"...".to_vec()` 變成 `"...".into()`）；`as_bytes()`
  收斂到單一私有存取點 `invoice_keys()` / `logistics_keys()`。

## Unreleased（續）

_HTTP client 注入：_

- `Ecpay` 新增 `http: Option<reqwest::Client>` 欄位：注入自訂 client
  （連線池/逾時政策、測試 mock）；`None`（預設）沿用共用的 hardened
  client（不跟隨重導、10s 連線/30s 總逾時、不池化閒置連線）。注入的
  client 原樣使用——hardening 不會（也無法）套用到它。
- 內部：`http_client()` / `unix_now()` 從 `crypto.rs` 搬到 `client.rs`
  （運輸層關注點歸位；均為 crate 私有）。

_審查跟進：_

- B2B 的 `B2bItem`/`B2bAllowanceDetail` 金額欄位（ItemCount/ItemPrice/
  ItemAmount）也套上 `finite_f64`——NaN/±Inf 拒絕的保證現在涵蓋全部
  金額欄位（B2B 先前為裸 f64，NaN 會靜默序列化為 `null`）。
- README 補上自訂 HTTP client 段落；英文版「compile-time」過度陳述一併
  修正；`Ecpay` 的 Debug 文件列出全部六個遮蔽的金鑰欄位。

_選擇性 enumify(監管級穩定代碼欄位;advisor 裁決 per-service + Other 穿隧):_

- 新增 `wire_enum!` 生成的 `#[non_exhaustive]` enum(`Other(String)`
  原樣穿隧未知代碼;`Default`=`Other("")` 維持 wire zero-value 語意;
  `From<&str>` 讓 `"1".into()` 建構點續用):
  - `ecpay::payment`:`TaxType`(1/2/3/9)、`Donation`(AIO 語彙 1/2)、
    `PrintMark`、`CarruerType`、`ClearanceMark`、`InvType`、`PeriodType`、
    `CreditAction`——取代同名的 String 常數 module(已移除)。
    `AioCheckOutParams.period_type`、`InvoiceExtend` 的對應欄位、
    `CreditDoActionParams.action`/`CreditCardPeriodActionParams.action`
    改為 enum 型別。
  - `ecpay::invoice`:`TaxType`(1/2/3/4/9)、`Donation`(0/1)、`PrintMark`、
    `CarrierType`、`ClearanceMark`(1=非經海關——與 AIO 相反)、`InvType`。
    `IssueInput`/`IssueModel`/`DelayIssueInput` 與字軌查詢結構的對應欄位
    改為 enum。
  - `ecpay::invoice_b2b`:`TaxType`(1/2/3/4,無混合 9)、`InvType`。
  - 同名欄位跨服務值域/語意不同(Donation、TaxType、ClearanceMark)——
    per-service 型別讓互抄無法編譯;`payment::ClearanceMark` 的
    `Yes`/`No` 變體改名 `ViaCustoms`/`NotViaCustoms`(語意明確)。
  - enum 欄位的本地「max langth」長度檢查隨 String 欄位移除;必填檢查
    保留官方訊息(`content is required.`),值(含未知代碼)由綠界裁定。

_新增：_

- `ecpay::MERCHANT_TRADE_DATE_FORMAT`（chrono 格式 `"%Y/%m/%d %H:%M:%S"`）：
  ECPay `MerchantTradeDate`／付款查詢日期欄位的樣式，RFC 上取代被移除的
  Go 佈局常數 `DATE_TIME_FORMAT`。crate 本身不格式化日期，常數附帶執行
  驗證的 doctest（chrono 為 dev-dependency）。
