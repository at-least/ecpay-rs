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
- `rust-version` 由 1.82 修正為 1.89：`aes = "0.9"` 解析到的 0.9.3 是
  edition 2024、要求 rustc 1.89（0.9.1/0.9.2 也要 1.85），1.82 從未能編譯。
- AES-JSON 信封檢查統一：`call_invoice_api`（B2C 發票全部 API）、
  `decrypt_logistics_callback`、`decrypt_ecpg_callback` 改走與 AES-JSON
  （物流 v2 / ECPG / B2B）相同的信封判定——body 不是帶 `TransCode` 鍵的
  JSON 物件時回 `Error::Message("ecpay: body is not an AES-JSON envelope:
  <body 節錄>")`（節錄最多 512 字元、`Debug` 跳脫——回呼 body 來自公開
  端點，不可無上限原樣回灌 log），不再解成無意義的 `TransCode{code:0}`（`Response` 全欄位
  serde default）或丟掉 body 的 JSON 解析錯誤。判定看鍵是否存在而非值：
  `"TransCode":0` 的真實信封（ECPay 的查無資料）回 `Error::TransCode`——
  在 AES-JSON 路徑上 2xx 與非 2xx 皆然（先前 2xx 誤判為「不是信封」、
  非 2xx 回 `InvoiceStatus`；HTTP 狀態碼不再另行呈現，TransMsg 才是有用
  的訊號）。鍵存在但值不符信封型別（如 `"TransCode":"1"`）同樣回
  `Error::Message`——先前回 serde 的 `Error::Json`，其訊息會原樣引用整段
  違規字串，在公開回呼端點上等於無上限回灌。
- 物流 form 端點的 `0|<訊息>` 拒絕（`0|找不到訂單`、`0|CheckMacValue驗證錯誤`
  在 stage 走 HTTP 500，`0|TimeStamp Is Expired` 走 HTTP 200）統一回
  `Error::Message("ecpay logistics: status 0: <訊息>")`，不再依 HTTP 狀態碼
  分成 `PaymentStatus` 與 `Message` 兩種；訊息也不再夾帶 `Some("0")` 的
  Debug 格式。
- 沙盒測試改成釘住 stage 的實際回應（不只是「有回應」）：B2C 發票生命週期的
  錯誤碼（重複 RelateNumber 5070357、重複作廢 5070453、GetIssue 以鍵存在與否
  決定查詢模式、GetInvalid 必填 2013001）、未建模代碼由伺服器裁決
  （2001096/2001019）、GetAllowance 三種 SearchType 皆必填 AllowanceNo 與
  InvoiceNo（2014003/2014001）、B2B 作廢原因長度先於查詢檢查（2103005）、
  物流 v2 查無訂單 85002 與錯誤金鑰 TransCode 712/114、ECPG 查無訂單
  10000185 與定期定額 90100150 回響。
- `AioCheckOutParams.credit_installment = Some("")` 改為不送出（與其他選填字串
  相同的過濾規則）；先前會送出空的 `CreditInstallment=`。
- CheckMacValue 簽章/驗證改走借用的 `(key, value)` 迭代器核心
  （`check_mac_value` 公開簽章不變）；form POST 的編碼統一為單一
  `encode_query`。內部整理，wire bytes 不變（`encode_query` 單元測試釘死
  排序與跳脫，簽章由 conformance 測試釘死）。

_選擇性 enumify(監管級穩定代碼欄位;advisor 裁決 per-service + Other 穿隧):_

- 新增 `wire_enum!` 生成的 `#[non_exhaustive]` enum(`Other(String)`
  原樣穿隧未知代碼;`Default`=`Other("")` 維持 wire zero-value 語意;
  `From<&str>`/`From<String>` 讓 `"1".into()` 建構點續用(已知值正規化為
  variant);`PartialEq`/`Hash` 為結構比對,與 `match` 一致):
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
