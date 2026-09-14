# ecpay-rs

ECPay(綠界科技)All-in-One 金流 SDK 的 Rust 版本 —— 完整移植官方
[ECPayAIO_Python](https://github.com/ECPay/ECPayAIO_Python),並額外收錄
B2C 電子發票(電信式 AES-JSON 介接)API。MIT 授權。

[![CI](https://github.com/at-least/ecpay-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/at-least/ecpay-rs/actions/workflows/ci.yml)

## 特色

- **付款 AIO 全涵蓋**:`create_order`(全付款方式 + 電子發票延伸)、查詢訂單
  (QueryTradeInfo)、查詢 ATM/CVS/BARCODE 取號結果(QueryPaymentInfo)、查詢
  信用卡定期定額、信用卡關帳/退刷/取消/放棄、單筆交易查詢、下載特店餘額明細
  (Big5)、下載撥款明細(Big5)、定期定額訂單狀態作業。
- **B2C 電子發票全涵蓋**:開立、延遲開立/觸發開立/取消延遲開立、作廢重開
  (VoidWithReIssue)、作廢、查詢(開立/作廢)、發送通知、折讓(紙本/線上合意)
  及其作廢/查詢、手機條碼驗證、愛心碼驗證、統一編號查詢、政府與商店字軌查詢
  共 20 支 API(AES-128-CBC + PKCS7 + Base64 信封,與官方規格及沙盒實測
  逐位元組比對過)。
- **ECPG 站內付 2.0 全涵蓋**(14 支):取號 GetTokenbyTrade(staging 實測取得
  真實 Token,typed 回應)、CreatePayment、綁卡家族(CreateBindCard /
  GetTokenbyBindingCard / GetTokenbyUser / GetMemberBindCard /
  DeleteMemberBindCard / CreatePaymentWithCardID)、查詢與請款動作
  (QueryTrade / QueryPaymentInfo / QueryTradeMedia / CreditCardPeriodAction /
  DoAction / CreditDetail QueryTrade)。雙 domain(ecpg vs ecpayment)由
  `ecpg_api_url` / `ecpayment_api_url` 分開承載,接錯必 404 的陷阱在文件中
  逐方法標示。
- **物流三家族全涵蓋**:國內物流(CMV-**MD5** form:建立訂單、查詢
  QueryLogisticsTradeInfo/V2、門市清單、更新出貨/門市、C2C 取消、逆物流
  CVS/UNIMART/HOME;瀏覽器表單:電子地圖、列印出貨單、四家 C2C 交貨便、
  產生測試資料)、全方位物流 v2(14 支 AES-JSON:暫存訂單建立/更新、
  查詢、逆物流、列印、物流選擇頁)與跨境物流(建立/查詢/列印/地圖)。
  staging 實測:國內建單(RtnCode=300 + AllPayLogisticsID)→查詢全程往返、
  v2 CreateTestData 成功;`1|<query>` 回應格式與 MD5 簽章範圍逐位元組釘死。
- **B2B 電子發票全涵蓋**(23 支):開立/確認、折讓/確認/取消、作廢、拒收、
  通知、客戶資料維護、字軌查詢與全部 Get* 查詢。staging 實測完整生命週期:
  開立(發票開立成功)→ 查詢 → 作廢全綠。
- **以官方實作為測試基準**:測試向量由「真的」官方 Python SDK 執行產生
  (17 種 `create_order` 情境逐欄位比對、11 條驗證錯誤訊息原樣比對、
  CheckMacValue SHA-256/MD5、AES-CBC 官方向量、.NET UrlEncode 契約)。
  - `Issue`/`IssueModel` 已補齊 `ChannelPartner`、`ProductServiceID`、
    `CarrierNum2`、`ZeroTaxRateReason`、`TaxAmount` 等官方規格欄位。
  - `GetIssue` 支援官方文件記載的兩種查詢模式(`RelateNumber` 或
    `InvoiceNo`+`InvoiceDate` 擇一),回應型別 `GetIssueOutput` 已對齊
    沙盒實測的完整欄位集。
  - ⚠️ 折讓查詢 `get_allowance`(`GetAllowance`)與官方規格頁有兩處落差,
    已依沙盒實測修正並記錄在型別文件註解:`AllowanceNo`/`InvoiceNo`
    不論 `SearchType` 為何都必填(規格頁說只在特定模式才必填);回應是
    攤平的單一物件,不是規格頁講的 `AllowanceInfo` 陣列。
  - ⚠️ 取消線上折讓是獨立端點 `AllowanceInvalidByCollegiate`(規格頁
    7913.md),官方 PHP SDK 沒有對應範例,容易誤用 `AllowanceInvalid`。
- **以官方實作為測試基準**:測試向量由「真的」官方 Python SDK 執行產生
  (17 種 `create_order` 情境逐欄位比對、11 條驗證錯誤訊息原樣比對、
  CheckMacValue SHA-256/MD5、AES-CBC 官方向量、.NET UrlEncode 契約)。
- **typed API + 逃生口**: `AioCheckOutParams` 型別化參數(必填欄位為
  非 `Option` 型別;空值/長度以官方 SDK 同款訊息在執行期驗證),另有
  `extra: BTreeMap<String, String>` 收容未模型化的新參數;
  低階的 `hash_mac` / `check_mac_value` / `call_payment_api` 也直接公開。

## 安裝

```toml
[dependencies]
ecpay = "0.3"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## 快速開始

### 產生訂單(超商代碼 + 發票)

```rust
use ecpay::payment::{donation, inv_type, print_mark, tax_type, AioCheckOutParams, ChoosePayment, InvoiceExtend};
use ecpay::Ecpay;

let client = Ecpay {
    merchant_id: "3002607".into(),
    hash_key: "pwFHCqoQZGmho4w6".into(),
    hash_iv: "EkRm7iFT261dpevs".into(),
    payment_api_url: "https://payment-stage.ecpay.com.tw/Cashier/".into(), // 測試環境
    ..Default::default()
};

let checkout = client.aio_check_out(&AioCheckOutParams {
    merchant_trade_no: "NO20240101120000".into(),          // 特店交易編號
    merchant_trade_date: "2024/01/01 12:00:00".into(),      // yyyy/MM/dd HH:mm:ss
    total_amount: 2000,
    trade_desc: "訂單測試".into(),
    item_name: "商品1#商品2".into(),
    return_url: "https://your.site/ecpay/return".into(),
    choose_payment: ChoosePayment::Cvs,
    store_expire_date: Some(10080),                          // 繳費期限(分鐘)
    // 發票(帶了就自動填 InvoiceMark=Y,並套用官方驗證規則)
    invoice: Some(InvoiceExtend {
        relate_number: "Tea0001".into(),
        customer_name: Some("客戶名稱".into()),
        customer_addr: Some("台北市中正區100號".into()),
        customer_phone: Some("0912345678".into()),
        tax_type: tax_type::DUTIABLE.into(),
        donation: donation::NO.into(),
        print: print_mark::NO.into(),
        invoice_item_name: "測試商品1#測試商品2".into(),
        invoice_item_count: "2#3".into(),
        invoice_item_word: "個#包".into(),
        invoice_item_price: "350#100".into(),
        delay_day: 0,
        inv_type: inv_type::GENERAL.into(),
        ..Default::default()
    }),
    ..Default::default()                                     // PaymentType=aio、EncryptType=1
})?;

// 直接輸出會自動 submit 的 HTML form,讓瀏覽器 POST 到綠界
println!("{}", checkout.html_form());
```

### 驗證付款結果通知(ReturnURL / PeriodReturnURL)

```rust
use std::collections::HashMap;
use ecpay::Ecpay;

async fn return_url(params: HashMap<String, String>) -> &'static str {
    let client = Ecpay {
        merchant_id: "3002607".into(),
        hash_key: std::env::var("ECPAY_HASH_KEY").unwrap(),
        hash_iv: std::env::var("ECPAY_HASH_IV").unwrap(),
        ..Default::default()
    };
    if client.verify_check_mac_value(&params) {
        "1|OK"
    } else {
        "0|ERR"
    }
}
```

### 查詢訂單、關帳退刷

```rust
# use ecpay::payment::{OrderSearchParams, CreditDoActionParams};
# use ecpay::Ecpay;
# async fn demo(client: &Ecpay) -> ecpay::Result<()> {
// 查詢訂單(會驗證回應的 CheckMacValue)
let info = client.order_search(&OrderSearchParams {
    merchant_trade_no: "NO20240101120000".into(),
    time_stamp: 1_700_000_000,
    platform_id: None,
}).await?;
println!("TradeStatus = {}", info["TradeStatus"]);

// 信用卡關帳(C)/退刷(R)/取消(E)/放棄(N)
let result = client.credit_do_action(&CreditDoActionParams {
    merchant_trade_no: "NO20240101120000".into(),
    trade_no: "2308150001".into(),
    action: ecpay::payment::action::CLOSE.into(),
    total_amount: 100,
    platform_id: None,
}).await?;
println!("RtnMsg = {}", result["RtnMsg"]);
# Ok(())
# }
```

更多範例見 [`examples/`](examples/)(對應官方 `sample_*.py`)。

### 自訂 HTTP client

預設共用一把 hardened client(不跟隨重導、10s 連線/30s 總逾時、不池化
閒置連線)。需要自己的連線池/逾時政策或測試 mock 時,注入 `reqwest::Client`:

```rust
# use ecpay::Ecpay;
let client = Ecpay {
    merchant_id: "3002607".into(),
    hash_key: "pwFHCqoQZGmho4w6".into(),
    hash_iv: "EkRm7iFT261dpevs".into(),
    http: Some(reqwest::Client::new()), // 原樣使用,hardening 不套用
    ..Default::default()
};
```

## API 一覽

| 官方 Python SDK | ecpay-rs |
| --- | --- |
| `create_order` | `Ecpay::aio_check_out` → [`AioCheckOut`](src/payment/check_out.rs)(含 `html_form`) |
| `order_search` | `Ecpay::order_search`(驗證回應 CheckMacValue) |
| —(比對 `ECPay/SDK_PHP` 官方範例後新增) | `Ecpay::query_payment_info`(查詢 ATM/CVS/BARCODE 取號結果,`Cashier/QueryPaymentInfo`,請求參數與 `order_search` 共用 `OrderSearchParams`) |
| `order_search_period` | `Ecpay::order_search_period` |
| `credit_do_action` | `Ecpay::credit_do_action` |
| `search_single_transaction` | `Ecpay::search_single_transaction` |
| `download_merchant_balance` | `Ecpay::download_merchant_balance`(Big5) |
| `download_disbursement_balance` | `Ecpay::download_disbursement_balance`(Big5) |
| `credit_card_period_action` | `Ecpay::credit_card_period_action` |
| `gen_html_post_form` | `AioCheckOut::html_form`(屬性值已做 HTML escape) |
| `generate_check_value` | `Ecpay::generate_check_value` / 自由函式 `check_mac_value` |
| —(Go 版移植) | 發票:`issue`、`void_with_reissue`、`invalid`、`get_issue`、`get_invalid`、`invoice_notify`、`check_barcode`、`check_love_code`、`get_company_name_by_tax_id`、`get_gov_invoice_word_setting`、`get_invoice_word_setting` |
| —(比對 `ECPay/SDK_PHP` 官方範例/規格頁後新增) | 發票延遲開立:`delay_issue`、`trigger_issue`、`cancel_delay_issue`;折讓:`allowance`、`allowance_invalid`、`allowance_by_collegiate`、`allowance_invalid_by_collegiate`、`get_allowance`、`get_allowance_invalid` |
| —(比對 `ECPay/SDK_PHP` 後新增) | **ECPG 站內付 2.0**(`ecpay::ecpg`):`get_token_by_trade`、`create_payment`、綁卡 6 支、查詢/請款動作 6 支,共 14 支 |
| —(比對 `ECPay/SDK_PHP` 後新增) | **物流**(`ecpay::logistics`):國內 9 支 MD5 form API + 6 種瀏覽器表單、全方位物流 v2 13 支、跨境 4 支 + 表單,含 MD5 回呼驗證與 AES 回呼解密 |
| —(比對 `ECPay/SDK_PHP` 後新增) | **B2B 電子發票**(`ecpay::invoice_b2b`):開立/折讓/作廢/拒收/通知/客戶資料/字軌與全部查詢,共 23 支 |

常數(付款方式、課稅類別、載具、捐贈、銀聯……)在 [`ecpay::payment`](src/payment/mod.rs)
模組,名稱對應官方 dict:`ChoosePayment`(enum)、`choose_sub_payment`、
`tax_type`、`donation`、`print_mark`、`carruer_type`、`clearance_mark`、
`inv_type`、`union_pay`、`period_type`、`action`、`need_extra_paid_info`;
另有 `reply_payment_type()` 對照回覆付款方式中文說明。

## 與官方 Python SDK 的三點刻意差異

三點都記錄在測試裡(見 `tests/python_conformance.rs`),其餘行為(含驗證
錯誤訊息原文)與官方 SDK 一致:

1. **CheckMacValue 的 `~` 編碼**:官方 Python 用 `quote_plus` 把 `~` 保留為
   原字元,但綠界後端(.NET)是把 `~` 編成 `%7e` 後才雜湊 — 帶 `~` 的參數
   會對不起來。本函式庫依後端行為(`%7e`),由官方 `~` 測試向量釘住。
2. **發票自由文字欄位不做小寫化**:官方 SDK 對 `CustomerName`/`CustomerAddr`/
   `CustomerEmail`/`InvoiceItemName`/`InvoiceItemWord`/`InvoiceRemark`
   url-encode 後整串 `.lower()`,會把客戶資料裡的英文大寫永久變小寫
   (`"AB市"` → 綠界收到 `"ab市"`)。本函式庫保留原文大小寫(與 PHP SDK 一致);
   兩邊的 CheckMacValue 仍會相同(雜湊前都會轉小寫)。
3. **組別衝突直接報錯**:官方 SDK 會把「非所選付款方式的延伸參數」或
   「同時填兩種信用卡方案(一次付清/分期/定期定額)」原樣簽署送出(綠界
   拒收)。本函式庫在 `aio_check_out` 直接回 `Error::Validation`,並提供
   `extra` 欄位作為未模型化參數的逃生口(碰撞會報錯)。

另外 `gen_html_post_form` 的屬性值加了 HTML escape(官方版遇 `"` 會壞掉
form,也是注入點)。

## 規格對照(官方 AI-skill 驗證)

本函式庫已對照 ECPay 官方維護的 [ECPay-API-Skill](https://github.com/ECPay/ECPay-API-Skill)
(`test-vectors/` 與 developers.ecpay.com.tw 即時規格)完成審查。該 repo 以
git submodule 掛在 `.claude/skills/ecpay`,讓 Claude Code 在本 repo 內直接讀到
官方規格、範例與向量(`tests/official_skill_vectors.rs` 內嵌了向量副本,測試
本身不依賴 submodule):

- `check_mac_value` 通過官方全部 CheckMacValue 向量(SHA-256、MD5、`'`、
  `~` 特殊字元)— 官方向量明文 `~` 須編碼為 `%7e`,證實「差異 1」是
  **跟隨官方後端**、官方 Python SDK 才是偏離方。
- AES 加密通過官方 AES-128-CBC 向量(含插入序與字母序 JSON key 兩種)。
- 依現行「產生訂單」規格修正:`ItemName` 上限 400 字元、`StoreID` 上限
  10 字元、`Language` 為所有付款方式的共同選填參數(舊 SDK 限定 Credit)。
- ⚠ 官方文件歧義:`Donation` 在 AIO 訂單(舊版)用 `'1'/'2'`、B2C 發票
  API 用 `'0'/'1'`;`ClearanceMark` 的 1/2 意義在 AIO 世代文件與現行 B2C
  指南正好相反。本函式庫 AIO 常數依官方 Python SDK,B2C 發票欄位為自由
  字串不做強制 — 上線前請以你的場景向綠界確認。

## 測試強度(金流等級)

除了 18 情境的 Python-SDK 一致性 fixtures 與官方向量,另含:

- **Property-based 測試**(`tests/properties.rs`,proptest,每條 512 個隨機案例):
  簽名→驗證對任意參數組合成立、MAC 任何一個位元組被改動必驗證失敗、
  CMV 與獨立 SHA-256 參考實作逐位元組一致、`url_encode` 對任意 Unicode
  (含 emoji/控制字元)符合 .NET 契約、AES 三種金鑰長度對任意明文往返、
  密文遭竄改必變明文或解密失敗。
- **差分測試**:156 組 seeded-random 參數由「真的」官方 Python SDK 簽署,
  本函式庫逐一比對(150 組無 `~` 逐位元組相同;6 組帶 `~` 釘住 `%7e` 偏差)。
- **傳輸層邊界**(`tests/transport_edge.rs`):回應體超過 1 MiB 必**回報錯誤**
  (不截斷不吞下 — Big5 對帳檔被切半行回 Ok 是靜默資料損毀;剛好 1 MiB
  則正常收下)、**302 帶真實 `Location` 時一律不跟隨**(帶簽名的 POST 被轉送
  是攻擊面;ECPay 端點從不轉導)、空回應必報錯、`aio_check_out` 為純函式
  (同參數位元組級確定,利於重試與稽核)。
- HTTP client 硬化:redirect 停用、connect timeout 10s、整體 timeout 30s。

## Staging 煙霧測試

`tests/stage_smoke.rs` 會打**真實的 ECPay 測試環境**(`payment-stage.ecpay.com.tw`,
使用官方公開測試帳號 3002607),預設 `#[ignore]`,離線套件不受影響:

```bash
cargo test --test stage_smoke -- --ignored --nocapture
```

實測結果(2026-09):QueryTradeInfo 往返 MAC 驗證、AioCheckOut/V5 接受
本函式庫簽名並渲染完整付款選擇頁、篡改 MAC 得到官方 10200073
CheckMacValue Error 頁(負向對照)、QueryCreditCardPeriodInfo / DoAction /
QueryTrade(V2) / vendor 對帳端點皆可達。

#### Staging 探測與實作:官方 PHP SDK 有、本來沒有的三個服務

這三個服務( ECPG 站內付 2.0、國內物流、B2B 電子發票)當初先用
`tests/stage_probes.rs`(#[ignore])以本函式庫的公開加密原語實測 staging、
釘死 wire 格式,再照探測結果實作成正式模組(見上方「特色」)。探測與後續
staging 實測(2026-09)確立的 server 真相,全部寫進了各模組文件:

- **ECPG**:`GetTokenbyTrade` 以 `{Timestamp}`-only 的 RqHeader 信封直接
  取得真實 Token(RtnCode=1);查詢走 `ecpayment-stage/1.0.0/` 雙 domain;
  壞 AES key 回 `TransCode=110`;`RememberCard=1` 必帶
  `CardInfo.OrderResultURL`(5100010)。
- **國內物流**:`Express/Create`(form + CheckMacValue **MD5**)實際建單
  (RtnCode=300 + AllPayLogisticsID)→ `QueryLogisticsTradeInfo/V2` 查得
  完整貨態。回應格式 `1|<urlencoded query>`,**CMV 只簽 `1|` 之後的
  query 部分**(MD5、排序鍵)— 逐位元組驗證並寫成斷言。
- **B2B 電子發票**:RqHeader 需帶 `RqID` + `Revision=1.0.0`,公開測試帳號
  2000132 開立成功(取得發票號)。`GetIssue` 回應包在 `RtnData`、RtnCode 是
  **字串** `"1"`;作廢原因上限 20 字元(2103005);RqID 不是冪等鍵(同一
  RqID 開出多張發票);回應信封是 `RpHeader`/`Reversion`(綠界原始拼字)。
- **全方位物流 v2 / 跨境**:同一段 AES 信封(`Revision 1.0.0`、物流金鑰)。
  v2 `CreateTestData` 開出測試單成功;跨境在該帳號回 `TransCode=128`
  (服務未開通,信封本身已驗)。v2 對「查無訂單」回 **HTTP 500 + 有效
  信封**,AES 核心會解出業務錯誤而非丟 HTTP 錯誤。
- **補充實測(2026-09 同日)**:v2 `PrintTradeDocument` 與
  `RedirectToLogisticsSelection` 回的是 **text/html 自動提交表單**(不是
  AES 信封)— 本 crate 以 `String` 回傳原文供輸出給瀏覽器;ECPG
  `DoAction`/`CreditCardPeriodAction` 的 Data 內 **`MerchantID` 必填**
  (省略回 `10200051 MerchantID Error.`,本 crate 已本地防呆);ECPG 三支
  查詢查無訂單回 `{"RtnCode":10000185,"RtnMsg":"Cant not find the trade
  data"}`;國內物流的業務拒絕可能是**未簽章短字串**(如
  `0|資料處理中,無法異動`),本 crate 以可讀訊息回報而非誤導的 MAC 錯誤;
  `UpdateShipmentInfo` 對 CVS 訂單需帶 `ReceiverStoreID`。

### Staging probes: how the three missing services were pinned

`tests/stage_probes.rs` (also `#[ignore]`d) is where the three services the
official PHP SDK covers were first probed with this crate's own public crypto
primitives before being implemented (see the feature list above — all three
are now full modules). The probes pinned the wire formats the implementations
follow: ECPG 站內付 2.0 (AES-JSON envelope with a `{Timestamp}`-only RqHeader;
live-issued a real Token), domestic logistics (form POST + MD5 CheckMacValue;
response is `1|<urlencoded query>` and the CMV signs only the query part —
verified byte-exact live), and B2B e-invoice (RqHeader carries `RqID` +
`Revision` 1.0.0; issued successfully with the public stage account; note
ECPay's own `RpHeader`/`Reversion` response spellings). Run:

```bash
cargo test --test stage_probes -- --ignored --test-threads=1 --nocapture
```

### 全流程 E2E(離線、零人工)

`tests/full_flow.rs` 在一般 `cargo test` 內跑完整協議流程,不需要瀏覽器、
帳號或任何人工步驟:本地 ECPay 行為模擬器(AioCheckOut 驗 MAC 並建單 →
「付款完成」事件 → 模擬器以 ECPay ServerPost 形式遞送**簽名回調**到
ReturnURL → merchant 端用 `verify_check_mac_value` 驗證並回 `1|OK` →
`order_search` 查得 `TradeStatus=1` + `SimulatePaid=1`,含篡改 MAC 負向對照)。

測試分層的誠實聲明:模擬器與本 crate 共用 MAC 實作,所以「MAC 算法與綠界
伺服器一致」這件事由**官方向量 + stage 實測**證明(見上),模擬器只負責
流程接線;「綠界自己對測試單執行模擬付款」是綠界後台的功能(其官方文件
指定的手動工具),不屬於本函式庫的程式碼,因此不在自動化範圍。

## 開發

```bash
git clone --recurse-submodules https://github.com/at-least/ecpay-rs.git
# 已 clone 的話:git submodule update --init
cargo test              # 160+ 測試:官方向量、Python SDK 一致性、mock transport
cargo test --test python_conformance   # 對官方 SDK 的逐欄位比對
cargo clippy --all-targets
```

submodule 只有 `.claude/skills/ecpay`(官方 ECPay-API-Skill,供 Claude Code
讀規格用),不初始化也能 build 與跑測試;發佈到 crates.io 的 crate 已排除該目錄。

⚠️ 上面的 `cargo test` **不是全離線**:`tests/sandbox.rs` 會打真實的 ECPay
stage 測試環境(公開測試特店 2000132),需要對外網路,CI 上以此做端對端驗證。
只有 `tests/stage_smoke.rs` 是刻意 `#[ignore]`(見上方「Staging 煙霧測試」),
離線環境跑 `cargo test` 時 `tests/sandbox.rs` 會因連不到網路而失敗。

`tests/fixtures/python_sdk_vectors.json` 由「真的」官方 Python SDK 執行產生
(`requests` 以 stub 取代;產生腳本 `gen_vectors.py` 同目錄),重新產生方式見
[tests/fixtures/README.md](tests/fixtures/README.md)。

## License

MIT — 見 [LICENSE](LICENSE)。歡迎 PR。

---

# ecpay-rs (English)

A Rust port of ECPay's official [ECPayAIO_Python](https://github.com/ECPay/ECPayAIO_Python)
payment SDK, extended with the B2C e-invoice AES-JSON APIs. MIT licensed.

- **Full AIO payment surface**: checkout creation with the invoice extension,
  order search (with response CheckMacValue verification), ATM/CVS/BARCODE
  payment-info lookup (`query_payment_info`), credit-card period queries,
  capture/refund/cancel/abandon, single-transaction lookup, merchant
  balance & disbursement downloads (Big5), and period-order status actions.
- **Full B2C e-invoice surface**: issue, delayed issue/trigger/cancel, void-
  and-reissue (`/B2CInvoice/VoidWithReIssue`), void, query (issued/voided),
  notify, allowance (paper and online-collegiate) plus its void/query,
  mobile-barcode check, love-code check, and word-setting queries — 20 APIs
  total, byte-exact against the official vectors and live-verified on stage.
  - `Issue`/`IssueModel` now cover `ChannelPartner`, `ProductServiceID`,
    `CarrierNum2`, `ZeroTaxRateReason`, and `TaxAmount`.
  - `GetIssue` supports both documented query modes (`RelateNumber`, or
    `InvoiceNo`+`InvoiceDate`), and `GetIssueOutput` matches the full
    field set observed live against the stage server.
  - ⚠️ `get_allowance` (`GetAllowance`) diverges from its spec page in two
    ways, fixed per live testing (documented on the type): `AllowanceNo`/
    `InvoiceNo` are required for every `SearchType` (not just the one the
    spec claims), and the response is a single flat object, not the
    documented `AllowanceInfo` array.
  - ⚠️ Cancelling an online/collegiate allowance is the separate
    `AllowanceInvalidByCollegiate` endpoint (spec page 7913.md) — the
    official PHP SDK has no example for it, so it's easy to assume
    `AllowanceInvalid` covers both.
- **ECPG 站內付 2.0, logistics (domestic / AllInOne v2 / cross-border), and
  B2B e-invoice — full parity with the official PHP SDK**, ported from its
  example files and live-verified on the stage server (issue → query → void
  B2B lifecycle, a real ECPG token, real domestic logistics orders; see the
  staging section below for the pinned server truths).
- **Verified against the real official SDK**: the conformance fixtures were
  generated by executing upstream `sdk/ecpay_payment_sdk.py` itself.
- **Typed API with an escape hatch**: required fields are non-`Option`
  (validated at runtime with the official SDK's messages),
  unknown/new ECPay params ride in `extra: BTreeMap<String, String>`.

## Quick start

```rust
use ecpay::payment::{AioCheckOutParams, ChoosePayment};
use ecpay::Ecpay;

let client = Ecpay {
    merchant_id: "3002607".into(),
    hash_key: "pwFHCqoQZGmho4w6".into(),
    hash_iv: "EkRm7iFT261dpevs".into(),
    payment_api_url: "https://payment-stage.ecpay.com.tw/Cashier/".into(), // stage
    ..Default::default()
};

let checkout = client.aio_check_out(&AioCheckOutParams {
    merchant_trade_no: "NO20240101120000".into(),
    merchant_trade_date: "2024/01/01 12:00:00".into(),
    total_amount: 2000,
    trade_desc: "order".into(),
    item_name: "item1#item2".into(),
    return_url: "https://your.site/ecpay/return".into(),
    choose_payment: ChoosePayment::Credit,
    ..Default::default()
})?;
println!("{}", checkout.html_form()); // auto-submitting form
```

Callback verification (`ReturnURL`): `client.verify_check_mac_value(&params)`.
See the table above for the full API mapping, and
[`examples/`](examples/) for ports of the official samples.

## Differences from the official Python SDK

Documented and pinned by tests (`tests/python_conformance.rs`); the
CheckMacValue implementation also passes every vector in ECPay's own
[ECPay-API-Skill](https://github.com/ECPay/ECPay-API-Skill) repository
(SHA-256, MD5, `'`, `~` — the official vectors escape `~` to `%7e`,
confirming this crate follows ECPay's backend):

1. CheckMacValue escapes `~` as `%7e` (the .NET contract ECPay's server
   hashes); the Python SDK hashes a literal `~` and mismatches on such params.
2. Invoice free-text fields are urlencoded **without** the SDK's `.lower()`,
   which corrupts ASCII letter case in customer data (the CheckMacValue is
   unaffected either way).
3. Setting fields outside the active `ChoosePayment` group, or combining two
   Credit plan groups, is a loud validation error instead of being silently
   signed and sent; use `extra` for parameters this crate does not model yet.

`AioCheckOut::html_form` also HTML-escapes attribute values (the upstream
form breaks on `"` and is an injection vector).

## License

MIT — see [LICENSE](LICENSE). PRs welcome.
