# ecpay-rs

ECPay(綠界科技)All-in-One 金流 SDK 的 Rust 版本 —— 完整移植官方
[ECPayAIO_Python](https://github.com/ECPay/ECPayAIO_Python),並額外收錄
B2C 電子發票(電信式 AES-JSON 介接)API。MIT 授權。

[![CI](https://github.com/OWNER/ecpay-rs/actions/workflows/ci.yml/badge.svg)](./.github/workflows/ci.yml)
<!-- 發佈到 crates.io 後,請自行加上版本與 docs.rs 徽章,並把 OWNER 換成你的 GitHub 帳號 -->

## 特色

- **付款 AIO 全涵蓋**:`create_order`(全付款方式 + 電子發票延伸)、查詢訂單
  (QueryTradeInfo)、查詢信用卡定期定額、信用卡關帳/退刷/取消/放棄、單筆交易
  查詢、下載特店餘額明細(Big5)、下載撥款明細(Big5)、定期定額訂單狀態作業。
- **B2C 電子發票**:開立、折讓、作廢、查詢、發送通知、手機條碼/愛心碼驗證、
  政府字軌查詢等九支 API(AES-128-CBC + PKCS7 + Base64 信封,與官方規格逐位元組一致)。
- **以官方實作為測試基準**:測試向量由「真的」官方 Python SDK 執行產生
  (17 種 `create_order` 情境逐欄位比對、11 條驗證錯誤訊息原樣比對、
  CheckMacValue SHA-256/MD5、AES-CBC 官方向量、.NET UrlEncode 契約)。
- **typed API + 逃生口**: `AioCheckOutParams` 型別化參數(必填欄位編譯期
  檢查),另有 `extra: BTreeMap<String, String>` 收容未模型化的新參數;
  低階的 `hash_mac` / `check_mac_value` / `call_payment_api` 也直接公開。

## 安裝

```toml
[dependencies]
ecpay = "0.1"
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

## API 一覽

| 官方 Python SDK | ecpay-rs |
| --- | --- |
| `create_order` | `Ecpay::aio_check_out` → [`AioCheckOut`](src/payment/check_out.rs)(含 `html_form`) |
| `order_search` | `Ecpay::order_search`(驗證回應 CheckMacValue) |
| `order_search_period` | `Ecpay::order_search_period` |
| `credit_do_action` | `Ecpay::credit_do_action` |
| `search_single_transaction` | `Ecpay::search_single_transaction` |
| `download_merchant_balance` | `Ecpay::download_merchant_balance`(Big5) |
| `download_disbursement_balance` | `Ecpay::download_disbursement_balance`(Big5) |
| `credit_card_period_action` | `Ecpay::credit_card_period_action` |
| `gen_html_post_form` | `AioCheckOut::html_form`(屬性值已做 HTML escape) |
| `generate_check_value` | `Ecpay::generate_check_value` / 自由函式 `check_mac_value` |
| —(Go 版移植) | 發票:`issue`/`try_issue`、`void_with_issue`、`invalid`、`get_issue`、`invoice_notify`、`check_barcode`、`get_company_name_by_tax_id`、`get_gov_invoice_word_setting`、`get_invoice_word_setting` |

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
(`test-vectors/` 與 developers.ecpay.com.tw 即時規格)完成審查:

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

## 開發

```bash
cargo test              # 63+ 測試:官方向量、Python SDK 一致性、mock transport
cargo test --test python_conformance   # 對官方 SDK 的逐欄位比對
cargo clippy --all-targets
```

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
  order search (with response CheckMacValue verification), credit-card period
  queries, capture/refund/cancel/abandon, single-transaction lookup, merchant
  balance & disbursement downloads (Big5), and period-order status actions.
- **B2C e-invoice**: issue, allowance, void, query, notify, barcode/love-code
  checks, and word-setting queries — byte-exact against the official vectors.
- **Verified against the real official SDK**: the conformance fixtures were
  generated by executing upstream `sdk/ecpay_payment_sdk.py` itself.
- **Typed API with an escape hatch**: required fields are compile-time,
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
