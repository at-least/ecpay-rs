# Changelog

## Unreleased

_breaking changes（程式碼審查後的型別/一致性修正）：_

- **建構期驗證重塑:無效狀態改為不可構造**(重新設計建議 #1,0.4.0
  發佈前的自由重塑窗口)。`Ecpay` 不再是 `#[derive(Default)]` 的公開欄位
  struct——空金鑰、靜默 fallback 到正式環境 URL、跨家族混搭金鑰,這三類
  「可構造的無效狀態」正是本輪審查修掉的空金鑰漏洞類的根因。新 API:
  - `Ecpay::new(merchant_id, env) -> Result<Ecpay>`:唯一建構路徑,空
    MerchantID 拒絕。`Env::{Stage, Production, Custom(Urls)}`:前兩者
    一次設定全部八個家族的端點;`Custom` 只用你給的——某家族 URL 沒給,
    該家族的呼叫**大聲拒絕**,不再靜默 fallback 到正式環境(舊的
    「空欄位 = 正式環境」陷阱移除)。`Urls` 各欄位 `Option<BaseUrl>`,
    `BaseUrl::new` 建構時就驗 https/loopback 規則(請求時再驗一次作為
    縱深)。
  - 金鑰改為整組 `Keys`(`Keys::new(key, iv) -> Result`:驗非空、key
    16/24/32 位元組、IV 恰 16 位元組——長度寫錯當場報,不再等到 AES
    層),以 `with_payment_keys` / `with_invoice_keys` /
    `with_logistics_keys` 附掛;`with_b2b_rq_id` / `with_platform_id` /
    `with_http` 對應舊欄位。某家族金鑰沒附掛,該家族的呼叫大聲拒絕
    (`Error::Validation`,出網前)——手動空金鑰守衛收斂進存取器。
  - 物流金鑰 fallback 改為**整組**(未設物流組時用整組金鑰組);舊的
    逐欄 fallback 可構造出「物流 key + 金流 IV」混搭,現在不可表示。
  - `Keys` drop 時自動清零(zeroize-on-drop);`zeroize_signing_keys()`
    改為清掉三組金鑰的**存在本身**——清零後的 client 對所有簽章/驗證
    呼叫大聲拒絕,不再「清了 bytes 但 pair 還在」。自動清零與建構慣用法
    的舊張力(文件明言不相容 `..Default::default()`)隨該慣用法一起消失。
  - **移除**三個從未被讀取的 deprecated 欄位(`relate_number` /
    `return_url` / `payment_info_url`)與其 compile_fail 釘;**移除**
    `Ecpay::stage(m, k, iv)`(以 `Ecpay::new(m, Env::Stage)?` 取代)。
  - 遷移對照:`Ecpay { merchant_id, hash_key, hash_iv,
    payment_api_url: stage_url, ..Default::default() }` →
    `Ecpay::new(m, Env::Custom(Urls { payment: Some(BaseUrl::new(stage_url)?),
    ..Default::default() }))?.with_payment_keys(Keys::new(k, iv)?)`;
    `Ecpay::stage(m, k, iv)` → `Ecpay::new(m, Env::Stage)?.with_payment_keys(Keys::new(k, iv)?)`。
    新契約由 `tests/client_construction.rs` 釘住(空 MerchantID、金鑰
    長度、非 https URL、缺家族大聲拒絕、zeroize 後拒絕、整組 fallback、
    Stage 八家族)。
  - 輸入結構(如 `AioCheckOutParams`)刻意**不加** `#[non_exhaustive]`:
    本 crate 的正式建構慣用法是 FRU(`..Default::default()`),E0639 使
    non_exhaustive 連 FRU 一起禁掉,而 FRU 本身已向前相容新欄位——
    「用 FRU」就是向前相容契約,exhaustive 字面量不受支援(重新設計
    建議 #2 的裁定,審查時以編譯探針驗證)。
- `EcpgDoActionInput::action` 由 `String` 改為 typed enum
  [`EcpgCreditAction`](C=請款/關帳、R=退款、E=取消、N=放棄;未建模值以
  `Other(String)` 原樣穿隧)。付款家族對同一 C/R/E/N 值域早有
  `payment::CreditAction`,raw string 讓 `"Close".into()`/`"c".into()` 這類
  拼錯直接編譯通過、送進加密請求;依本 crate 各家族自有型別的慣例
  (同 `InvType` 在 invoice/invoice_b2b 各自建模)獨立建模並交互參照。
- `IssueB2bInput` 移除九個無官方依據的 B2C 風格欄位(`customer_name`/
  `print`/`donation`/`love_code`/`carrier_type`/`carrier_num`/
  `tax_center_flag`/`clear_invoice`/`customer_id`),改正兩個欄位名
  (`customer_addr`→`customer_address`,wire `CustomerAddress`;
  `customer_phone`→`customer_telephone_number`,wire
  `CustomerTelephoneNumber`),補回規格頁記載的選填欄位(`invoice_time`/
  `clearance_mark`/`zero_tax_rate_reason`/`special_tax_type`/
  `invoice_remark`)(程式碼審查 🟡)。依據:B2B Issue 欄位表(存證模式
  https://developers.ecpay.com.tw/24230.md /交換模式
  https://developers.ecpay.com.tw/14850.md,2026-04 快照——即時抓取當日
  timeout/限流,未及重驗)沒有 Print/Donation/LoveCode/CarrierType/
  CarrierNum/CustomerName/TaxCenterFlag/ClearInvoice/CustomerID,官方
  PHP 範例 `Issue.php` 全部不送,且 B2B 明確無載具/捐贈;舊欄位名
  `CustomerAddr`/`CustomerPhone` 是 B2C 名,設了值綠界不會讀。wire
  key-set 由 `issue_b2b_data_is_exactly_the_documented_field_set` 逐鍵釘住。
- **四個出網前防護改回 `Error::Validation`**(程式碼審查 🟡):Data 層
  MerchantID 防呆(信封比對 `encrypt_checked` 與欄位級
  `require_data_merchant_id_with`,涵蓋 B2C 發票/ECPG/物流 v2/跨境/B2B)、
  B2B 空 `RqHeader.RqID` 拒絕、`void_with_reissue` 巢狀 MerchantID 比對——
  過去回 `Error::Message`,與 `Error::Validation` 文件契約
  (「出網前的各家族請求防護」)不一致:以
  `matches!(err, Error::Validation(_))` 區分「本地拒絕、未出網」的呼叫端
  會把這些歸進「其他/傳輸」分支。現在全部對齊為 `Error::Validation`
  (訊息原文不變);對 variant 做匹配的呼叫端需要跟著改。傳輸層的
  `Error::Message`(body 上限、非簽章回應、回呼解密統一訊息)不變。

_非破壞性：_

- **回呼入口的 panic-freedom 屬性測試**(審查後續項):`tests/properties.rs`
  新增兩條 proptest(各 512 案例),對攻擊者可達的公開回呼端點入口——
  `parse_form`、`decrypt_ecpg_callback`、`decrypt_logistics_callback`、
  `decrypt_temp_trade_established`,以及 `parse_form`→`verify_check_mac_value`
  整段進站管線——灌入敵意碎片組合(斷裂/截斷的 `%XX` 跳脫、跨跳脫邊界切半的
  多位元組 UTF-8、form/JSON metacharacter、控制字元、BOM):任何輸入都必須
  落在 `Ok`/`Err`,絕不 unwind(回呼 handler 的 panic 就是 DoS)。現況
  全綠(特性釘住,非 RED 修復——未有 panic 被發現)。
- **動錢動作的「未定結局」文件**(審查後續項):`credit_do_action` 與
  `ecpg_do_action` 的文件補上與 `credit_card_period_action` 同款的 ⚠ 規則:
  傳輸失敗(30 秒逾時、連線中斷)只代表回應遺失,不代表動作未執行——
  盲目重試可能重複請款/退款;任何 `Error::Http` 應視為「狀態未知」,
  先查詢(`query_trade_info`/`order_search`/`ecpg_query_trade`)確認再重試。
- **測試端五份本地 form 解碼器副本收編為 `ecpay::parse_form`**(程式碼審查
  🟢):`tests/{e2e_flows,logistics_wire,conformance,full_flow}.rs` 各自帶一份
  `parse_form`,其中兩份(`e2e_flows`、`logistics_wire`)已漂移——無 `=`
  的 valueless key 被靜默丟棄,而 crate 的 `parse_qsl`/`parse_form` 語意
  (Python `parse_qsl(keep_blank_values=True)`,空白值保留)把此行為文件化為
  載重契約;`tests/stage_probes.rs` 另有一份同名漂移的
  `parse_query`/`unquote_plus`。五份連同各自助手
  (與 crate `unquote_plus` 演算法逐位元組相同)全數刪除,改呼叫公開的
  `ecpay::parse_form`;四個離線套件在替換下全綠(行為保持),漂移同時歸零
  (stage_probes 為 `#[ignore]` 手動探測套件,僅編譯驗證)。
  另:`c2c_form_api_posts_the_c2c_field_set` 補上排序鍵集斷言(與
  `update_shipment_info` 同款)——過去只驗兩個欄位值與 MAC 重算,無法抓
  掉欄/多欄的回歸。
- **文件修正**(程式碼審查 🟡/🟢):README 英文版「Differences from the
  official Python SDK」補上第五點刻意差異(InvoiceMark 衝突大聲報錯,
  過去僅中文版「五點」列表有——只讀英文段的整合者會以為差異清單到此
  為止);`tests/python_conformance.rs` 模組標頭的「Three deliberate
  divergences」過時計數改為指向 README 權威清單並標明其餘兩點釘在
  `tests/check_out.rs`;`tests/official_skill_vectors.rs` 的向量出處註記
  從機器特定路徑 `~/.zcode/skills/ecpay` 改為 repo 內可重現的
  `.claude/skills/ecpay` submodule(同一 commit);`B2C_INVOICE_REVISION`
  的文件修正為如實描述——ECPG 信封**不帶 `Revision`**(RqHeader 只有
  `Timestamp`,沙盒實測釘住),舊文字「AES-JSON families in ecpg/… speak
  1.0.0」會誤導維護者對 ECPG 加上 Revision、送出未經實測的 wire 形狀。
- **`ApiError` 的 Display 與 `HttpStatus`/`TransCode` 同款有界**(程式碼審查 🟢):
  `RtnMsg` 過去原樣、無界輸出——被注入的 client 或被擊穿的傳輸可在加密
  成功的回應裡塞近 1 MiB 的 `RtnMsg`,一條 log 就被撐成百萬字元。現在
  經共用的 `truncate_for_display`(512 字元上限)渲染,引號保留 Go-parity
  的 `%q` 外觀、控制字元與兩個兄弟 variant 同款**單層**跳脫
  (終審回歸修正:先前的 `{:?}` 疊層會把 `\n` 再跳一次變 `\\n`)——
  不含引號與控制字元的訊息形狀與 Go parity 完全一致,含引號的訊息中
  `"` 不再跳脫(僅外觀差異,非偽造向量:控制字元仍全部跳脫);
  `msg` 欄位仍保留完整原文供程式化取用
  (`tests/api_error.rs::api_error_display_bounds_the_server_message`)。
- **`get_issue` 強制互斥查詢模式**(程式碼審查 🟢):`GetIssueInput` 文件的
  「擇一」過去只是文件——兩邊都填、或 `invoice_no`/`invoice_date` 只填
  半對,三個 key 都會簽進信封送出;伺服器以 key 是否存在決定查詢模式
  (struct 文件釘住的沙盒實測),衝突時每張真實發票都回
  `RtnCode=2 查無資料` 且無任何本地提示。現在衝突直接回
  `Error::Validation`(與組別衝突、InvoiceMark 衝突同款大聲報錯);
  任一完整模式照常出網,全空交給伺服器
  (`tests/invoice_apis.rs::get_issue_rejects_conflicting_or_half_filled_query_modes`)。
- **金額欄位補上負數防護**(程式碼審查 🟢):`aio_check_out` 的 `TotalAmount`
  與物流 `GoodsAmount` 早有「負數永遠不是合法 wire 值」的本地拒絕,但
  `credit_do_action`/`ecpg_do_action` 的 `TotalAmount`、
  `search_single_transaction` 的 `CreditAmount`、發票開立家族
  (`issue`/`delay_issue`/`void_with_reissue` 的 `IssueModel`)的
  `SalesAmount` 會把負數簽名送出,換一個不透明的伺服器端錯誤(退款金額的
  正負號手誤正是這種)。現在這些欄位一律在出網前以
  `Error::Validation("{name} cannot be negative.")` 拒絕;零維持放行——
  是否接受零值是伺服器端規則(`issue` 的 `SalesAmount` 欄位文件註明的
  金額不可為 0 元由綠界裁定),`credit_do_action` 的零值出網由
  `credit_do_action_zero_amount_still_reaches_the_wire` 釘住。
- **出網的 MAC 簽署/驗證路徑拒絕未設定的金鑰**(程式碼審查 🟡):金流查詢的
  `post_cmv_verified`(`order_search`/`query_trade_info`/`query_payment_info`/
  `credit_card_period_action` 共用)過去對空 `hash_key`/`hash_iv` 照簽照驗——
  空金鑰的 MAC 任何知道參數集的人都算得出來,端點回應被掌控時
  (base URL 誤填/遭劫、注入的 client),偽造的「已付款」查詢回應會通過
  驗證。進站驗證器(`verify_check_mac_value`)早有同一拒絕
  (`tests/verify.rs::empty_key_client_rejects_empty_key_forged_mac` 釘住),
  出站這半邊現在對齊:空金鑰直接回 `Error::Validation`,且在出網前生效
  (`tests/payment_apis.rs::order_search_refuses_an_empty_key_client_before_sending`
  同時釘住「mock 收到零個請求」)。國內物流的 MD5 form 家族同日補上同一
  防護:守衛放在 `sign_logistics`(國內 form API 與瀏覽器表單的唯一簽署點),
  物流金鑰與 payment fallback 兩組皆空時拒絕
  (`tests/logistics_wire.rs::domestic_form_api_refuses_an_empty_key_client_before_sending`)。
- **`InvoiceMark` 帶發票欄位時不再靜默改成 `Y`**(程式碼審查 🟡):明確
  填了非 `Y` 的註記(小寫 `"n"` 拼錯也算)又帶 `InvoiceExtend`,過去會
  被靜默覆寫成 `InvoiceMark=Y` 送出——等於替呼叫端開出一張沒要求的
  電子發票(台灣的會計憑證,事後需要折讓/作廢流程)。現在直接回
  `Error::Validation`(與「差異 3」組別衝突同款大聲報錯;官方 SDK 原樣
  送出、由綠界拒收,列為 README 第五點刻意差異)。`None`/空字串自動補
  `Y`、明確 `"Y"`、無發票欄位時 `"N"` 原樣送出等既有行為不變(既有
  測試釘住)。
- **`Error::TransCode` 的 Display 跳脫並截斷伺服器訊息**(程式碼審查 🟡):
  API 路徑的 `TransMsg` 原樣進入錯誤欄位,Display 過去也原樣、無界輸出
  ——與 `HttpStatus` 已有的防護(`truncate_for_display`:控制字元跳脫 +
  512 字元上限)不一致;被注入的 HTTP client 或被擊穿的傳輸可用 raw 換行
  偽造 log 行。現在渲染與 `HttpStatus` 同款(可印字元維持原樣);`msg`
  欄位仍保留完整原文供程式化取用。回呼路徑本就先經 `body_excerpt`
  (Debug 跳脫、有界)預先處理,渲染不受影響。
- **新增 `ecpay::parse_form()`;`examples/callback_verify` 修正**(程式碼
  審查 🟡):範例過去把 stdin 的 key=value 行**原樣(未 percent-decode)**
  餵給 `verify_check_mac_value`——真實回呼 body 是 urlencoded(`TradeDate`
  的 `/` 與空白必編碼),未解碼的值在 MAC preimage 二次編碼,每一條真實
  回呼都會驗證失敗(fail-closed,但會誤導商戶以為金鑰設定錯誤)。新增
  公開 `ecpay::parse_form(body) -> HashMap<String, String>`(Python
  `parse_qsl(keep_blank_values=True)` 語意:`+`→空格、%XX 解碼、跨
  triplet 的多位元組 UTF-8 round-trip、空值保留、重複鍵後值勝),範例改
  吃整個 raw POST body 並經它解碼;已用官方 Python SDK 簽名的真實
  urlencoded body(含中文 `ItemName`)實測 `1|OK`、竄改 body `0|ERR`。
- **CI 補上 doctest 與 MSRV**(程式碼審查 🟡):`cargo test --all-targets`
  完全不執行 Doc-tests 階段——四個 compile_fail 釘子(deprecated 欄位 ×3、
  `EmptyCiphertext`)與所有 rustdoc 範例在 CI 從未跑過(本地裸
  `cargo test` 會跑)。新增 `cargo test --doc` 步驟;另新增 `msrv` job 以
  `dtolnay/rust-toolchain@1.89` + `cargo check --all-targets` 實測
  `rust-version = "1.89"`(CHANGELOG 0.4.0 記載過 1.82「從未能編譯」的同
  類事故;本地 `cargo +1.89 check --all-targets` 已先驗證通過)。
- **base URL 少了結尾 `/` 不再簽出不存在路徑**(程式碼審查 🟢):所有
  端點以 `{base}{action}` 拼接,base 少 `/` 過去直接產生
  `.../CashierAioCheckOut/V5` 這類簽好名的錯誤路徑(遠端 404,本地看不到
  配置錯誤)。新增 `join_url` 統一在 44 個拼接點自動補 `/`(空 base 照舊
  由各 family 換成正式環境預設),`Ecpay` struct 文件新增「Base-URL
  trailing slash」一節說明。
- **測試基礎設施與文件清理**(程式碼審查 🟢,行為不變):`urlencode`
  在 `e2e_flows`/`full_flow`/`logistics_wire` 的三份本地副本(已有漂流)
  合併回 `tests/common/mod.rs` 的 `sandbox::urlencode`,`full_flow` 併入
  `mod common`;`taipei_now`/`taipei_today` 重複的 civil-from-days 轉換
  抽成共用 `taipei_ymd`;`gen_vectors.py` 移除死占位行、兩份位元組等價的
  .NET 編碼器合併為一份(六組快照逐位元組驗證等價);`parse_encrypt_type`
  的 rustdoc 與測試註解不再把「garbage 也預設 SHA-256」說成官方 SDK 行為
  (官方 `int()` 對不可解析值是 raise——缺值才預設);
  `verify_logistics_check_mac_value` 文件加註金鑰 fallback 的安全邊界;
  範例 `chrono_now` 更名為 `unix_seconds`(名實相符,並註明
  `merchant_trade_date` 是占位)。
- **文件補強**(程式碼審查 🟡/🟢):https/loopback base-URL 規則寫進
  `Ecpay` 的 struct 文件與 README(中/英),不再是只有 `pub(crate)` 函式
  文件看得到的行為;回呼處理清單新增第 0 條——**註冊給綠界的回呼網址
  本身也應使用 https**(本函式庫不檢查回呼 scheme,`http://` 回呼會以
  明文收付款結果);`Error::Validation` 的文件範圍更新(現已涵蓋各家族
  請求防護與 URL scheme 規則,不再只講 AioCheckOutParams);
  `InvoiceExtend::carruer_num` 的文件改為如實描述「僅檢查長度,必填性
  由綠界裁定」;`payment::Donation` 文件錯字修正。
- **新增 `payment::decode_big5_with_status()`**(程式碼審查 🟢):回傳
  `(String, bool)`,字串半邊與 `download_merchant_balance` /
  `download_disbursement_balance` 的 Big5 解碼規則完全一致
  (U+FFFD 替換、不 BOM-sniff),布林半邊透出 encoding_rs 的
  `had_errors`——至少一個位元組是壞的 Big5。過去對帳檔裡的一個壞位元組
  會靜默變成 U+FFFD(如收款人名稱)流入對帳而無從察覺;兩個下載方法
  維持回傳 `String`(原始碼相容),在乎資料損壞的呼叫端改用本函式。
- **國內物流的協定錯誤判別不再依賴 `=` 啟發式**(程式碼審查 🟢):
  status 前綴(`0|`/`1|`)回應過去以「body 內沒有 `=`」判定為協定自身的
  錯誤訊息;帶 `=` 的錯誤訊息(如
  `0|The parameter [ReceiverStoreID]=required`)因此誤判成
  `Error::CheckMacValueMismatch`,把商戶導向金鑰/簽章排查。改以精確
  判別:解析後**沒有非空 `CheckMacValue` 且沒有 `RtnCode` 鍵**才是協定
  訊息;查詢形狀的 body(帶 `RtnCode` 而 MAC 缺漏/空值)維持
  `CheckMacValueMismatch`(完整性失敗),帶有效 MAC 的簽章查詢照舊驗證。
  已知行為放寬:status 前綴、含 `=` 但兩者皆無的 body,由
  `CheckMacValueMismatch`(2xx)/`HttpStatus`(非 2xx)改為協定訊息——
  該形狀從未在 live 觀察過,新映射更誠實(本來就沒驗過任何 MAC)。
- **`Error::HttpStatus` 的 Display 跳脫控制字元**(程式碼審查 🟢):節錄
  渲染(`truncate_for_display`)過去對控制字元原樣輸出,依據是「body 來自
  商戶自己的 TLS 連線」——該假設可被注入的 HTTP client 或被擊穿的傳輸
  打破,raw 換行即可偽造 log 行。現在可印字元維持 Go 對照的 `body=%s`
  原樣形狀,控制字元在**渲染**中以 `escape_debug` 跳脫(`\n`、`\u{7}`…),
  `body` 欄位仍保留完整原文供程式化取用;512 字元上限不變。
- **`finite_f64` 拒絕指數記法量級**(程式碼審查 🟡):AES-JSON 金額欄位
  (`ItemCount`/`ItemPrice`/`ItemAmount`/`GoodsWeight`)的 wire 形式過去
  完全交給 serde_json 的預設浮點渲染——其十進位/指數切換窗口是實作細節
  且已隨版本漂移(zmij 後 `1e+21`、前 ryu `1e21`,舊測試自己就載明了這個
  耦合),而指數形式的 wire 值從未對綠界驗證過。現在 `serialize` 檢查
  **實際渲染結果**,凡含指數記法(serde_json 1.0.151 實測:小於 1e-5 或
  1e16 以上,如 `0.000001` → `1e-6`)一律在本機以 serialization error
  拒絕——規格合法但離譜的量級(七位小數的 `0.000001` 元單價)從「悄悄
  送出未驗證的 wire 形狀」變成「本機大聲失敗」。原 `1e21`/`1e-7` 等指數
  釘子改為錯誤斷言;`1e15`/`1e-5` 的 plain 釘子保留(僅記錄現行窗口,
  不作保證)。**範圍補充**:帶此 helper 的欄位也出現在 `Serialize` 的
  **回應**型別上(`AllowanceItem`/`AllowanceInfoItem`)——把查回的回應
  原樣再序列化(存檔/轉發/log)時,若值落在指數窗口同樣會在此失敗;此前
  會原樣寫出。
- **`ensure_https` 不再對畸形 URL panic;裸 scheme 一律拒絕**(程式碼
  審查最終回歸審查 🟢):scheme 判別改為比對字面前綴——過去
  `split("://")` 取頭,base URL 只填 `"http"`(無 `://`)會在守衛內切過
  字串結尾直接 **panic**(所有請求路徑可觸發);`"https"` 則被誤當成
  https 而放行。兩者現在都是 schemeless 字串,回
  `Error::Validation`(與文件契約一致)。
- **`ensure_https` 修補 userinfo 繞道**(程式碼審查 🔴):守衛以手寫字串
  切割取 host(`rsplit_once(':')`),`http://127.0.0.1:80@evil.com/x` 這類
  「userinfo 長得像 loopback」的 URL 會被誤判為 host `127.0.0.1` 而放行,
  但 reqwest 背後的 url crate 取**最後一個 `@` 之後**的部分當 host——
  實際會以明文 http 把簽章表單/AES 信封 POST 到 `evil.com`(以 url 2.5.8
  實測釘死;六個呼叫點全受影響,含瀏覽器表單 action,瀏覽器同樣以
  `@` 解析 userinfo)。現在凡是 authority 帶 `@` 一律拒絕(ECPay 端點
  從不帶 userinfo);測試釘住三種繞道形狀,以及 `%40`、反斜線等編碼
  花招的 fail-closed 行為。
- **新增 `Ecpay::zeroize_signing_keys()`**:就地清零六組簽章金鑰緩衝區
  (bytes 歸零、字串截斷),供嵌入端在程序結束前主動清除記憶體中的金鑰
  材料。刻意做成**顯式**方法而非 `Drop`:對 `Ecpay` 實作 `Drop` 會禁止
  從結構體搬出欄位(E0509),破壞全庫與 README 的
  `Ecpay { .., ..Default::default() }` 慣用法。文件如實記載其「盡力而為」
  邊界(僅清當前緩衝區;clone 各自保有一份;曾重新配置的字串可能有清不到
  的殘留副本),以及清零後的 client 並未設防(logistics 金鑰會 fallback 到
  空的 payment 組)。
- **staging 測試覆蓋補全**:`tests/sandbox_payment.rs`(唯讀的 Big5 對帳
  下載往返,CI 每次 push 都會重釘「空報表 = `Ok("")`」契約)、B2C 發票
  三支無狀態查詢(統編/政府字軌/自有字軌)、國內物流 C2C 取消與更新門市
  (未確認訂單的 judged-rejection 形狀)、物流 v2 取消/更新門市/逆物流的
  in-band 錯誤形狀;既有 sandbox 測試同步加強斷言(查詢回應須回
  `AllPayLogisticsID` 與 `LogisticsStatus`、門市清單不得為空、
  `CreateTestData` 須鑄出 `LogisticsID`、條碼 well-formed 探測不得落入
  格式錯誤臂、B2B lifecycle 單次取日防跨日、ECPG 成功路徑 print 遮蔽
  Token/ConsumerInfo)。
- **CI:新增 `sandbox_payment` 至 sandbox 步驟;`stage_smoke` 改為每月
  排程自動執行**(不建物流訂單、不消耗字軌,但會在 stage 註冊待付款的
  checkout 交易——與 `sandbox_ecpg` 同類的殘留),`stage_probes` 因會建立
  真實 stage 紀錄、消耗字軌,維持僅手動 `workflow_dispatch` 觸發。
- **回呼解碼器的 `TransCode != 1` 錯誤不再原樣攜帶伺服器回傳的
  `TransMsg`**：`decrypt_ecpg_callback` / `decrypt_logistics_callback` /
  `decrypt_temp_trade_established` 的 TransCode 閘門只需要一個 `TransCode`
  鍵、先於任何解密就會觸發,`TransMsg` 因此是攻擊者可任填的位元組,先前
  卻原樣放進 `Error::TransCode.msg` 並由 `Display` 無界輸出(原始換行可
  偽造 log 行、單一未認證請求可灌入大訊息),與同一函式對非信封 body 的
  「永不無界原樣回顯」契約不一致。現在 callback 路徑的 `msg` 與該契約
  同款:有界、Debug 跳脫的節錄;API 呼叫路徑(自家 TLS 上的伺服器回應)
  維持原樣。
- **`decode_big5` 不再 BOM-sniff**:對帳檔下載(`download_merchant_balance`
  / `download_disbursement_balance`)改用 `decode_without_bom_handling`,
  貼齊文件所載 Python `big5` codec 契約——`Encoding::decode` 遇 `FF FE`
  開頭會把整個 body 改成 UTF-16LE 解碼,靜默產生亂碼;現在 BOM 位元組
  依 Big5 規則成為 U+FFFD,其餘內容照常以 Big5 解出。
- **`Error::EmptyCiphertext` 標記 `#[deprecated]`**（審查後續）：該變體
  自 0.4 起就沒有任何生產路徑——`decrypt` 的長度閘門把空密文回報為
  `InvalidCiphertextLength(0)`（舊 unpad 路徑到不了；改用 cbc crate 後
  連路徑本身都沒了）。0.5 先以 deprecation 警告使用者並以 `compile_fail`
  doctest 釘住（與三個 deprecated client 欄位同一套釘法），未來 breaking
  release 再移除變體。
- **AES-CBC/PKCS7 改用 RustCrypto 的 `cbc` crate**（全庫審查後的密碼學
  衛生）：`crypto.rs` 刪除手寫的 CBC 串接迴圈與 PKCS7 pad/unpad，改用
  RustCrypto 官方 mode crate `cbc 0.2`（與 `aes 0.9` 同為 cipher 0.5
  世代）。公開 API（`encrypt`/`decrypt`/`encrypt_data`/`decrypt_data`）
  簽名與行為不變：錯誤順序（`encrypt` 與 `decrypt` 一致為金鑰長度 → IV
  長度，即 Go `aes.NewCipher` 的順序——舊 `encrypt` 是 IV 先查，雙重錯誤
  設定下回報的錯誤類別因此改變，單一錯誤情境不受影響）、密文長度閘門與
  `Error::Padding` 的不透明性（CBC padding oracle 防護）皆
  保持——`block_padding::Error` 本身即不透明單元結構，直接映射。官方
  AES 測試向量（`tests/aes_vectors.rs`）與 Go-port crypto 測試逐位元組
  釘死，重構全程綠。padding 分支測試由公開 `decrypt` API 驅動
  （`tests/crypto.rs` 既有 raw-CBC helper）；原先直測內部 `unpad_pkcs7`
  的單元測試隨之移除（其契約已由公開 API 測試覆蓋）。
- **`logistics_notify_reply` 的 ack 型別改從接收端規格：字串 `"1"` →
  整數 `1`**（程式碼審查 🟢，推翻全庫審查 2026-09 的字串選擇）：兩個
  官方來源對全方位物流 v2 狀態通知應答體的 `TransCode`/`RtnCode` 型別
  **互相矛盾**——官方 PHP SDK 的出貨範例
  (`LogisticsStatusNotify.php`)送字串 `"1"`，官方 AI-skill 指南片段送
  整數 `1`。程式碼審查補抓**接收端自己的規格頁**
  (developers.ecpay.com.tw/10127.md，物流狀態(貨態)通知，
  特店Response參數說明，2026-09)：`TransCode` 與 Data 內 `RtnCode`
  皆型別為 **Int**（「1 代表 API 傳輸資料接收成功」），範例 body 即
  `"TransCode": 1`——規格壓過 SDK 範例。**注意 wire bytes 因此改變**
  （`"TransCode":"1"` → `"TransCode":1`、Data 內 `"RtnCode":"1"` →
  `1`）：自行比較/快取應答體序列化形式的整合端請同步。同頁規格的
  Response 信封寫 `RpHeader`，SDK 範例與本函式送 `RqHeader`，鍵名矛盾
  維持 SDK 形式並記錄於 docstring（上線觀察到 ack 被重送時連同鍵名
  一併以 stage 探測）。
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
