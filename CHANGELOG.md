# Changelog

## Unreleased

_非破壞性：_

- **`logistics_notify_reply` 的 ack 格式調查記錄**（全庫審查 🟡）：兩個
  官方來源對全方位物流 v2 狀態通知應答體的 `TransCode`/`RtnCode` 型別
  **互相矛盾**——官方 PHP SDK 的出貨範例
  (`LogisticsStatusNotify.php`)送字串 `"1"`，官方 AI-skill 指南片段送
  整數 `1`，且無 stage 探測能證實接收端的嚴格度。本 crate 維持與官方
  SDK 出貨程式碼一致的**字串形式**（wire 不變），docstring 與測試註解
  記錄衝突來源與後續動作（上線觀察到 ack 被重送時，先對 stage 探測
  整數形式是否被接受）。
- 文件補強（全庫審查 🟡/🟢）：README「API 一覽」精確列出平台商
  （`PlatformID`）模式的缺口——AIO 與 B2C 發票支援帶入 PlatformID；ECPG/
  物流 v2/
  跨境/B2B 的共用 AES-JSON 信封路徑**不送信封層 `PlatformID`**（ECPG 的
  Data 層雖有選填 `platform_id` 欄位，但官方平台商契約的信封半邊無法
  表達，Data 層 `MerchantID` 並強制等於 client 的 `merchant_id`），
  完整平台商模式在這三族目前無法組出；回呼處理清單與
  `verify_check_mac_value` 文件補註「驗證不綁定 `MerchantID`/金額，
  出貨前須自行比對」；crate 根文件的首個範例由物流測試帳號改為金流
  測試帳號 3002607（原範例照抄會帳號/金鑰不符）；`Error::HttpStatus`
  文件不再以 intra-doc 連結指向私有函數（該連結在 CI 的
  `RUSTDOCFLAGS=-D warnings` 下使 `cargo doc` 失敗，main 的 doc 步驟
  因此是紅的）。

_breaking changes（程式碼審查後的 API 衛生修正）：_

- **`Error::PaymentStatus` / `Error::InvoiceStatus` 由帶服務標籤的
  `Error::HttpStatus { service, status, body }` 取代**（全庫審查 🟢）：
  `service` 是新的 closed enum `ecpay::Service::{Payment, Invoice,
  Logistics, Ecpg, B2bInvoice}`。動機：共用 helper 的服務歸屬只有呼叫端
  知道——先前 `logistics_create` 的 HTTP 500 會渲染成「ecpay **payment**
  API error」（`post_logistics_form` 重用 `PaymentStatus`）、ECPG/物流
  v2/B2B 的非 2xx 會渲染成「ecpay **invoice** API error」（`post_aes_json`
  重用 `InvoiceStatus`），log 與告警會被錯誤標籤誤導。現在每個服務族
  以正確標籤呈現：`ecpay {service} API error: status=… body=…`——Go 參考
  移植的 `payment`/`invoice` 兩族文字逐字不變，`body` 欄位與 512 字元
  bounded Display 契約不變（`tests/api_error.rs::http_status_display_
  names_the_service` 逐服務釘住）。移轉：`Error::PaymentStatus { status,
  body }` → `Error::HttpStatus { service: Service::Payment, status, body }`、
  `InvoiceStatus` → `Service::Invoice`。
- **reqwest 移除未用的 `json` feature**（全庫審查 🟢）：全庫從不呼叫
  `.json()`（信封與表單 body 皆自行序列化），依賴面照舊、feature 標記
  如實。

_非破壞性：_

- **`Ecpay::relate_number` / `return_url` / `payment_info_url` 標記
  `#[deprecated]`**（全庫審查 🟡）：grep 全庫證實這三個 client 欄位是
  write-only——除 `Debug` 外沒有任何程式路徑讀取，從官方 SDK 移植的
  使用者把回呼網址設在 client 上會**靜默無效**（最壞情況：簽出一張沒有
  `ReturnURL` 的付款表單）。現在欄位帶 deprecation 警告與指向正確位置
  的文件（`AioCheckOutParams::return_url`、`InvoiceExtend::relate_number`
  等），並以 `compile_fail` doctest 釘住：移除 `#[deprecated]` 而不讓欄位
  真正生效會使該測試失敗。欄位本體保留（`Debug` 仍顯示，已有設定值不
  受影響）；是否在未來版本改為「params 留空時 fallback 到 client 欄位」
  需先實證 Go 參考移植的行為，目前不做。
- 內部整理（全庫審查 🟢）：`hex_val` 收斂為 `crypto.rs` 單一定義（
  `client.rs` 的 lenient `unquote_plus` 改用之）；`read_body_limited`
  文件補註「超過 1 MiB 的非 2xx 錯誤頁會以 body 上限的 `Error::Message`
  呈現、而非該端點的 `Error::HttpStatus`」；`shared_http_client` 文件
  補註 builder 失敗時 lazy panic 的取捨（無可用 HTTP client 時大聲失敗
  優於靜默吞掉）。

_breaking changes（程式碼審查後的安全/一致性修正）：_

- **`EncryptType` enum 取代 `check_mac_value` 的 `encrypt_type: i64`**：
  `ecpay::EncryptType::{Sha256, Md5}`（closed enum——wire 上只有 0/1，第三
  種摘要會是新協定、必為破壞性更新）。移轉：`1` → `EncryptType::Sha256`、
  `0` → `EncryptType::Md5`。`EncryptType::try_from(i64)`（以及 crate 內部
  讀取 wire `EncryptType` 欄位的解析）對 0/1 以外的值回**同一個**
  `Error::UnsupportedEncryptType(n)`——對
  [`Ecpay::generate_check_value`] 的呼叫端，`EncryptType=2` 的錯誤形狀與
  位置（出網前）皆不變。連帶清掉
  不可能的 `Result`：`check_mac_value` 現在直接回 `String`（enum 使
  「不支援的摘要」無法表示）、`verify_mac`（crate 內部）直接回 `bool`，
  `verify_check_mac_value` / `verify_logistics_check_mac_value` 的
  `unwrap_or(false)` 不可達分支同時消失。`AioCheckOutParams.encrypt_type`
  維持 `i64`（表單 wire 欄位，已驗證 ==1）。
- **CBC padding oracle 防護**：AES-JSON 回呼解密器
  （`decrypt_ecpg_callback` / `decrypt_logistics_callback` /
  `decrypt_temp_trade_established`）解密的是公開端點上攻擊者可篡改的 CBC
  密文，而信封不認證 `Data`——先前 padding 失敗與後續 UTF-8/JSON 失敗可
  區分，構成 CBC padding oracle（可用 CBC-R 在不知金鑰下偽造回呼密文）。
  內容相關的解密失敗現在收斂為同一則固定訊息
  （`Error::Message` "callback payload failed to decrypt or parse"）；
  base64/長度/金鑰長度錯誤保持原樣（只取決於攻擊者已輸入的資訊）。
  伺服器回應路徑（發票/ECPG/物流 API 呼叫）維持原有詳細錯誤。商戶 handler
  應配合：所有回呼錯誤回同一 HTTP 回應、加 rate limit、不把 `Error`
  Display 原文回進 response——見 README 新增的回呼處理清單。
- **`Error::PaddingValue(u8)` 與 `Error::PaddingBytes` 移除**，合併為不透明
  的 `Error::Padding`：padding 失敗不再區分模式、不再把 pad byte 值帶進
  訊息（該值曾可被攻擊者觀察）。`matches!` 這兩個變體的呼叫端改比對
  `Error::Padding`。
- **`aio_check_out` 補齊延伸欄位長度驗證**：`Redeem`(≤1)、
  `MerchantMemberID`(≤30)、`PaymentInfoURL`/`ClientRedirectURL`(≤200)、
  `Desc_1..4`(≤20)、`Language`(≤3)、`PeriodReturnURL`(≤200)——過長值先前
  會被送出、換來綠界伺服器端錯誤；現在客戶端即以
  `Error::Validation("{name} max langth is {max}.")` 拒絕。（官方 SDK 本就
  不驗 optional 長度；本 crate 對基本 optional 欄位一直有驗，此舉補齊同一
  標準。）
- **B2B 發票要求 `b2b_rq_id`**：留空時每個 B2B 呼叫在出網前回
  `Error::Message`——wire 契約每個請求都帶 `RqHeader.RqID`（官方 PHP 範例
  一律送出），空值是否被伺服器接受未經實測，不再賭這一把。
- **ECPG 查詢家族要求 Data 層 MerchantID,`merchant_id` 改為 `String`**:
  `EcpgTradeRefInput` / `EcpgPeriodActionInput` / `EcpgDoActionInput` 的
  `merchant_id` 由 `Option<String>` 改為 `String`(呼叫端把
  `merchant_id: Some(x)` 改成 `merchant_id: x`);`ecpg_query_trade` /
  `ecpg_query_payment_info` / `ecpg_query_credit_trade` 對空值或與信封不
  一致的值改為出網前回 `Error::Message`,與 DoAction/CreditCardPeriodAction
  走同一個 `require_data_merchant_id`。依據:2026-09 以原始信封對五支
  ecpayment 端點逐一實測(`tests/stage_probes.rs` 的
  `ecpg_data_merchant_id_omitted_or_mismatched_is_named_by_stage` 釘住),
  省略一律回 `5000220 "The parameter [MerchantID] is required."`、不一致回
  `5000261 "The parameter [MerchantID] does not match."`——
  `EcpgTradeRefInput` 文件「省略時以信封 MerchantID 為準」的舊假設已證偽。
  `Option` 原為平台商模式預留,但官方平台商範例的 Data 仍是 `PlatformID` +
  特店自己的 `MerchantID` 並列,沒有可省略的形狀。先前錯誤訊息與文件引用
  的 `10200051` 並非 stage 對此形狀的回應,已全數更正。
- **物流 v2/跨境要求 Data 層 MerchantID**：輸入結構帶 `MerchantID` 欄位
  者（依官方範例慣例），留空或與信封不一致時出網前回 `Error::Message`——
  與 ECPG/B2B 模組同一防呆；先前空值會原樣送出、換來伺服器不帶訊息的
  拒絕。無 `MerchantID` 欄位的三個結構（`CreateByTempTradeInput`、
  `UpdateTempTradeInput`、`AllInOneRedirectInput`）不受影響。

- **`credit_card_period_action` 驗證回應 CheckMacValue**（全庫審查）：
  改走 `post_cmv_verified`——回應 MAC 不符或缺失時回
  `Error::CheckMacValueMismatch`，通過時回傳欄位不含 `CheckMacValue`。
  依據 stage 實測（2026-09，`tests/stage_probes.rs` 兩支新 probe 釘住）：
  `Cashier/CreditCardPeriodAction` 的回應**帶簽**（連查無訂單的
  `RtnCode=10100140` 回應都攜帶可驗證的 MAC，且 echo 的空
  MerchantID/MerchantTradeNo 必須「如收到般」納入雜湊——與
  QueryPaymentInfo 先例同款）；`CreditDetail/DoAction` 則**不帶簽**
  （`RtnCode=0&RtnMsg=訂單不存在`，另有重複 `Merchant=` 欄位的怪癖），
  故 `credit_do_action` 維持不驗證並在文件記載原因——查詢類有簽、指令類
  一簽一不簽的不對稱從此有實證註解。`order_search_period`（JSON 回應）
  無 MAC 可驗，不變。⚠ 升級注意：帶簽的查無訂單回應是唯一實測過的
  形狀（成功回應需真實定期定額訂單，伺服器端測試無法建立）——
  `Error::CheckMacValueMismatch` 應解讀為「不可信的回答」而非「指令未
  執行」：伺服器可能在回應驗證失敗前已套用動作，重試或告警前請先以
  `order_search_period` 查證。
- **空金鑰 client 拒絕「空金鑰偽造 MAC」**（全庫審查）：
  `verify_check_mac_value` 與 `verify_logistics_check_mac_value` 在
  HashKey/HashIV 為空時一律回 `false`——知道參數集的攻擊者可自行以空金鑰
  算出相同 MAC，未設定的 client 先前會「驗證通過」，構成偽造回呼的
  oracle。真正的綠界回呼（以真實金鑰簽署）行為不變（本就驗證失敗）。
- **`aio_check_out` 拒絕負數 `TotalAmount`**：負的台幣總額永遠不是合法
  wire 值，現在客戶端即以 `Error::Validation("TotalAmount cannot be
  negative.")` 拒絕，不再簽章送出後由綠界錯誤頁回答。零仍允許（是否
  接受零額屬伺服器端規則）。
- **`aio_check_out` 拒絕非 1 的 `EncryptType`**（全庫審查）：AIO 收銀台
  簽章只認 SHA-256——ECPay 已淘汰 MD5（`EncryptType=0`）。先前 `0` 會被
  簽成 MD5 送出（換來收銀台拒絕）、`2` 只在簽章階段才以
  `Error::UnsupportedEncryptType` 失敗；現在兩者都在驗證階段即回
  `Error::Validation("EncryptType must be 1 (SHA-256); ECPay has retired
  MD5 (EncryptType=0) on AIO.")`，與回應驗證
  （`verify_check_mac_value`，SHA-256 only）對稱。`generate_check_value`
  與 `check_mac_value` 的 `EncryptType=0`（MD5）路徑保留不變——國內物流
  仍以 MD5 簽章，官方 Python SDK 向量亦釘住該路徑。
- **國內物流（CMV-MD5 家族）補本地欄位驗證**（全庫審查）：`Express/Create`、
  `express/ReturnCVS`/`ReturnUniMartCVS`、`Express/ReturnHome`、
  `Helper/QueryLogisticsTradeInfo/V2`、`Helper/UpdateShipmentInfo`、
  `Express/UpdateStoreInfo`、`Express/CancelC2COrder` 的呼叫現在於簽章
  前驗證欄位——必填欄位留空、`MerchantTradeNo` 超過 20 字、`GoodsAmount`
  為負等，一律以 `Error::Validation` 在出網前拒絕（訊息與 payment 模組
  同一套，含官方 "langth" 拼字）。驗證僅限於官方明載、且不更嚴於它：
  長度上限只取官方欄位表明載者（`GoodsName`≤50、姓名≤10、手機≤20、
  地址≤60、`ReceiverStoreID`≤6），以字元數計——對伺服器端以 byte 或
  半形單位計數的實作而言是寬鬆子集，不會擋掉綠界會接受的值；
  `MerchantTradeNo`（可空，系統自動產生）與 `GoodsName`/
  `SenderCellPhone`（僅 C2C 子類別必填）三個欄位**只驗長度不驗必填**，
  留空的 B2C 訂單照常送出。金額上限依 `LogisticsSubType` 而異，仍由
  伺服器裁定。

_非破壞性：_

- README 新增「回呼處理清單」：MAC 只證明作者性與完整性，不證明新鮮度與
  金額正確——去重、金額綁定、主動查詢、統一錯誤回應等六步。
- `decrypt`/`decrypt_data` 文件警告勿用於攻擊者可達的回呼端點（詳細錯誤
  僅適合自家 TLS 連線上的綠界回應），並指向回呼解密器。
- 移除 `verify_check_mac_value` / `hash_mac` 內部不可達分支的 `.expect`
  （`verify_check_mac_value` 改回 `false`）；`hash_mac` 重構為直接走與
  `check_mac_value`（EncryptType=1 分支）共用的 SHA-256 前像路徑，
  不存在任何可吞掉的錯誤分支；`logistics_keys` 回傳
  `(&str, &str)`，刪除不可達的 UTF-8 錯誤路徑；CheckMacValue 前像改以
  `write!` 組字串（少一次 per-pair 配置）。`constant_time_eq` 改用
  audited 的 `subtle` crate 原語（長度先短路——長度不是祕密；語意與
  Go `crypto/subtle.ConstantTimeCompare` 不變，字元級行為由
  characterization 測試釘住）。
- **國內物流錯誤訊息文字加上界**（全庫審查）：`0|<訊息>` 業務拒絕與
  「2xx 非簽章 query（HTML 錯誤頁）」兩條 `Error::Message` 路徑，先前把
  回應 body 原文（上限 1 MiB）整段塞進錯誤字串；現在分別以
  `truncate_for_display`（verbatim-but-bounded，與 `PaymentStatus`/
  `InvoiceStatus` 的 Display 同一 512 字元契約）與 `body_excerpt`
  （有界 + 跳脫，與 AES-JSON "not an envelope" 錯誤同款）截斷——錯誤
  訊息不再可能被單一回應灌爆 log 行。
- **新增 `tests/sandbox_ecpg.rs`(進 CI 的 live stage suite)**:站內付 2.0
  家族此前只有手動 probe——現在以真實 `Ecpay` 方法覆蓋五個測項:
  - `GetTokenbyTrade` 取得真實 Token(官方 CreateAllOrder 範例欄位,未含
    UnionPayInfo;`ChoosePaymentList="0"` 依規格為「全部」付款方式);
  - 缺 `ConsumerInfo` 的拒絕形狀:`RememberCard=1` 時回 `5100010
    "The parameter [ConsumerInfo] cannot be empty"`(點名參數,並非無訊息),
    `RememberCard=0` 時可整個省略仍取號——`ConsumerInfo` 文件原稱
    「Email/Phone 載重、失敗不帶訊息」已依實測改寫;
  - 三支 ecpayment 查詢的查無訂單形狀(`RtnCode 10000185`,釘死 JSON
    **整數**型別);
  - `DoAction` 查無訂單同一形狀(ecpayment 網域路由);
  - `CreatePaymentWithCardID` 未知 `BindCardID` 回 `5100088 "The BindCard
    does not exist."`,兩種形狀都釘住:不帶 `MerchantMemberID` 時 stage 先以
    `5100010 "The parameter [MerchantMemberID] cannot be empty"` 擋下、到
    不了綁卡查詢。

  與其他三個 sandbox 套件同一 CI 步驟、預設並行(`unique_no` 帶程序內
  序號,不撞單號)。
- B2B 補 `GetIssue` 查無發票 probe(釘 `RtnCode` 為字串的型別怪癖)。
  `tests/sandbox_logistics.rs` 與 `tests/sandbox_ecpg.rs` 的 `unique_no`
  加原子序號,消除並行測試同毫秒撞單號的 flake(物流套件實測
  `0|廠商訂單編號重覆`)。審查後移除了同批新增的「瀏覽表單欄位順序 stage
  實證」測試:其 POST body 與 `logistics_create` 的 server-to-server body
  逐位元組相同(離線比對,同一 CheckMacValue),排序欄位序早已
  由 `domestic_create_then_query_roundtrip` 在 stage 上證明,該測試只多建
  一筆不清理的 stage 訂單。
- **`LogisticsForm` 欄位順序確定性**（全庫審查）：六個瀏覽器表單建構點
  改走統一的排序建構（鍵 bytewise 排序，同 `AioCheckOut`）。簽章本就算
  在 map 上、欄位順序對 wire 無差異，但先前 `HashMap` 迭代順序讓每次
  render 的 hidden input 順序隨機——無法測試、diff 噪音大。
- 新增 wire 釘序測試：ECPG `Data` 明文必須保持 struct 欄位宣告順序
  （`serde_json::Value` 的 BTreeMap 會重排金鑰——先前嘗試把
  `encrypt_checked` 改走 `to_value` 即因此改變加密位元組，已撤銷；
  舊測試解密成 Value 比對看不見順序，此測試釘住明文全文）。

- **`Ecpay::stage(merchant_id, hash_key, hash_iv)` 建構子**（全庫審查）：
  一次設定全部八個服務 base URL 到 stage 端點（含新常數
  `CREDIT_API_URL_STAGE` = `payment-stage…/CreditDetail/`、
  `VENDOR_API_URL_STAGE` = `vendor-stage…/PaymentMedia/`）。動機：每個
  `*_api_url` 欄位獨立空值回退**正式環境**，逐欄手設的 stage client 少設
  一個欄位就默默送出簽名過的正式流量——支付 API 動真錢。建構子的測試
  逐一釘住八個欄位，未來新增服務欄位未跟著設 stage 會使測試失敗而非
  靜默回退。
- 測試基礎設施（全庫審查）：五個 live 套件重複的
  `unique_no`/`taipei_now`/`taipei_today`/`urlencode` helper 合併進
  `tests/common/mod.rs` 的 `sandbox` 模組（counter 版與 millis 版並存，
  語意各歸各位）；`stage_smoke`/`sandbox_b2b`/`stage_probes` 三支空洞或
  恆真的 live 測試補上真斷言（單筆交易查詢的 in-band 拒絕形狀、無資料
  區間餘額報告為 `Ok("")`、B2B 字軌查詢的 `RtnCode=1` 與非空
  `InvoiceInfo`、定期定額查詢的 `10200047`、DoAction 的 `0|訂單不存在`）；
  CI 新增 `workflow_dispatch` 手動 job `stage-manual` 執行
  `stage_smoke`/`stage_probes`（探測會建立真實 stage 紀錄故不自動跑，
  但可一鍵手動執行，parity 不再無人把關）；`need_extra_paid_info`
  常數與 injected-client 超時路徑補上測試。
- **B2B 發票型別 root 再導出**（全庫審查）：`invoice_b2b` 模組中 19 個
  不與 B2C 撞名的型別（`IssueB2bInput`、`B2bItem`、`B2bIssueOutput`、
  `B2bAllowanceDetail`、各 `*ConfirmInput`、`NotifyInput`/`RejectInput`
  等）可直接從 crate root `use`，與其他模組一致；七個與 B2C 同名的型別
  （`AllowanceInput`、`InvalidInput`、`GetIssueInput`、`GetInvalidInput`、
  `GetAllowanceInput`、`GetAllowanceInvalidInput`、
  `GetInvoiceWordSettingInput`）維持在 `ecpay::invoice_b2b` 底下（與
  `_b2b` 方法後綴同一規則），root 匯出測試逐名釘住。同批文件修正（全庫
  審查）：`invoice_b2b` 模組文件誤稱 B2C `RtnCode` 為「字串型」的過時
  註解（兩服務的 typed 輸出皆為 `i64`，真正的差異是回應欄位名
  `InvoiceNumber` vs B2C 的 `InvoiceNo`）；`encrypt_checked` 補上
  「檢查後仍加密原 wire 字串」的理由（`to_value` 再序列化會經
  BTreeMap 重排鍵序、改變 conformance 釘死的 wire bytes）；表單 builder
  文件標明「一頁一表單」（自動提交腳本以固定 id `data_set` 定位）。

## 0.4.0 — 2026-09-16

_breaking changes（全庫審查後的安全/一致性修正）：_

- `Ecpay::query_trade_info` 改為驗證回應的 CheckMacValue（原先沿襲 Go 參考
  移植不驗證——與打同一端點、會驗的 `order_search` 並存是安靜的 footgun），
  並補上與 `order_search` 相同的 `MerchantTradeNo` 長度驗證（≤20 字元）。
  解析也從 Go `url.ParseQuery`（重複鍵取第一個）改為 `parse_qsl`（取最後
  一個）——ECPay 回應為單值，實務無差。回應缺漏/不符簽名時回
  `Error::CheckMacValueMismatch`。
- AES-JSON 全路徑新增 Data 層 MerchantID 防呆：`Data` 內帶「非空且不等於
  信封 MerchantID」的請求（B2C 發票、物流 v2/跨境、ECPG/B2B）改為出網前回
  `Error::Message`——ECPay 對不一致只回不帶訊息的 `RtnCode != 1`。空值照舊
  放行（僅 ECPG/B2B 有 stage 實證空值會被拒，兩模組保留原本較嚴的欄位級
  檢查）。`VoidWithReIssue` 的 `VoidModel`/`IssueModel` 巢狀 MerchantID
  同規則就地檢查。平台商/子特店式「Data 帶不同 MerchantID」的用法會被
  本地擋下。
- `Ecpay::call_payment_api` 現在「簽與送同一份 map」：`MerchantID` 強制為
  client 的設定值（取代呼叫端自帶值），簽名恆覆蓋實際送出的欄位；先前是
  呼叫端 map 原樣簽、原樣送。簽名改走 `generate_check_value`：呼叫端自帶
  `EncryptType=0` 時改簽 MD5（與 ECPay 對 EncryptType=0 的預期一致；0.3
  恆為 SHA-256——帶 0 卻簽 SHA-256 本來就過不了真實伺服器）。
- `Error::PaymentStatus` / `InvoiceStatus` 的 `Display` 改為有界呈現：
  body 最多原樣引用 512 字元後接 `… (truncated; N bytes total)`（欄位
  本身仍保留完整 body 供程式存取）。先前會把回應體（至多 1 MiB 上限）
  整段帶進錯誤訊息。

_非破壞性：_

- `post_cmv_verified`（`order_search` / `query_payment_info` /
  `query_trade_info` 共用）的驗證摘要改由**請求**的 `EncryptType` 決定
  （未帶即 SHA-256），不再採用回應自帶的 `EncryptType`——驗證器不應從
  被驗證的訊息取得演算法選擇器。
- `Ecpay::call_payment_api` 的回應仍不驗證（維持 Go port 相容面）；文件
  明確指引需要驗證的查詢改用 `order_search` / `query_trade_info`。
- 測試：`tests/sandbox.rs`、`tests/sandbox_b2b.rs`、
  `tests/sandbox_logistics.rs` 全部 `#[ignore]`——預設 `cargo test` 完全
  離線；live E2E 以 `cargo test --test sandbox --test sandbox_b2b --test
  sandbox_logistics -- --ignored` 執行（CI 新增同一步驟，涵蓋範圍與先前
  相同）。
- 內部：CheckMacValue 排序改為 decorate-sort-undecorate（每鍵只小寫一次，
  wire bytes 不變，差分向量套件釘死）；README 移除重複的「以官方實作為
  測試基準」bullet、API 對照表補 `query_trade_info`；安裝版本 `0.3` →
  `0.4`。

## 0.3.0 — 2026-09-16

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


_金鑰型別統一：_

- `Ecpay::invoice_hash_key` / `invoice_hash_iv` / `logistics_hash_key` /
  `logistics_hash_iv` 從 `Vec<u8>` 改為 `String`，與 `hash_key`/`hash_iv`
  一致（呼叫端從 `b"...".to_vec()` 變成 `"...".into()`）；`as_bytes()`
  收斂到單一私有存取點 `invoice_keys()` / `logistics_keys()`。


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
