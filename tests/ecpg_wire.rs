//! The ECPG 站內付 2.0 wire contract against a hermetic local mock: the
//! Timestamp-only RqHeader (no Revision/RqID — the load-bearing difference
//! from the invoice/logistics envelopes), the dual-domain endpoint paths
//! (ecpg `Merchant/*` vs ecpayment `1.0.0/*`), omission of unset optional
//! pieces, the typed GetTokenbyTrade decode, and the TransCode gate.
//!
//! Nothing here touches the network; the one live stage probe at the bottom
//! is `#[ignore]`d like `tests/stage_probes.rs`.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use ecpay::ecpg::{
    AtmInfo, CardInfo, ConsumerInfo, CreateBindCardInput, CreatePaymentInput,
    CreatePaymentWithCardIdInput, DeleteMemberBindCardInput, EcpgCreditAction, EcpgDoActionInput,
    EcpgPeriodActionInput, EcpgTradeRefInput, GetMemberBindCardInput, GetTokenbyBindingCardInput,
    GetTokenbyTradeInput, GetTokenbyUserInput, OrderInfo, QueryTradeMediaInput,
};
use ecpay::{decrypt_data, encrypt_data, BaseUrl, Ecpay, Env, Error, Keys, Urls};

mod common;
use common::spawn_http_server;

/// Official public stage ECPG account (same as tests/stage_probes.rs): ECPG
/// signs with the PAYMENT HashKey/HashIV.
const MERCHANT: &str = "3002607";
const KEY: &[u8] = b"pwFHCqoQZGmho4w6";
const IV: &[u8] = b"EkRm7iFT261dpevs";

fn client(ecpg_api_url: String, ecpayment_api_url: String) -> Ecpay {
    Ecpay::new(
        MERCHANT,
        Env::Custom(Urls {
            ecpg: Some(BaseUrl::new(ecpg_api_url).unwrap()),
            ecpayment: Some(BaseUrl::new(ecpayment_api_url).unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs").unwrap())
}

/// The GetTokenbyTrade body the round-trip tests send: OrderInfo + a
/// ConsumerInfo (required by stage with RememberCard=1), everything else
/// left unset.
fn token_input() -> GetTokenbyTradeInput {
    GetTokenbyTradeInput {
        merchant_id: MERCHANT.to_owned(),
        remember_card: Some(1),
        payment_ui_type: Some(2),
        choose_payment_list: "0".to_owned(),
        order_info: Some(OrderInfo {
            merchant_trade_date: "2026/09/11 06:57:06".to_owned(),
            merchant_trade_no: "order1234567890".to_owned(),
            total_amount: 100,
            return_url: "https://example.com/return".to_owned(),
            trade_desc: "ecpay-rs wire test".to_owned(),
            item_name: "商品 x1".to_owned(),
        }),
        consumer_info: Some(ConsumerInfo {
            merchant_member_id: Some("member000001".to_owned()),
            email: "customer@email.com".to_owned(),
            phone: "0912345678".to_owned(),
            name: Some("王小美".to_owned()),
            country_code: Some("158".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A TransCode=1 response envelope whose Data is `data` encrypted with the
/// payment keys — the reply every mock hands back.
fn envelope_reply(data: Value) -> (u16, String, Vec<u8>) {
    let res = json!({
        "TransCode": 1,
        "TransMsg": "",
        "Data": encrypt_data(&data, KEY, IV).unwrap(),
    });
    (
        200,
        "application/json".to_owned(),
        serde_json::to_vec(&res).unwrap(),
    )
}

/// Asserts the outer envelope shape EVERY ECPG request must have and returns
/// the decrypted Data payload:
///
/// * top-level keys are exactly `{MerchantID, RqHeader, Data}` — no
///   PlatformID (unlike the B2C invoice envelope);
/// * RqHeader keys are exactly `{Timestamp}` — **NO Revision, NO RqID**.
///   This is the load-bearing wire detail: ECPG's RqHeader carries only the
///   Unix-seconds timestamp, unlike invoice/logistics/B2B. Set equality
///   proves both the absence of Revision/RqID AND the presence of
///   Timestamp; the value must be a real Unix-seconds integer.
fn assert_envelope_and_decrypt(body: &[u8]) -> Value {
    let req: Value = serde_json::from_slice(body).expect("envelope is JSON");
    let obj = req.as_object().expect("envelope is an object");
    let top: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        top,
        BTreeSet::from(["Data", "MerchantID", "RqHeader"]),
        "envelope carries exactly MerchantID/RqHeader/Data (no PlatformID)"
    );
    assert_eq!(obj["MerchantID"], MERCHANT, "envelope MerchantID");
    let rqh = obj["RqHeader"].as_object().unwrap();
    let rq_keys: BTreeSet<&str> = rqh.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        rq_keys,
        BTreeSet::from(["Timestamp"]),
        "ECPG RqHeader is Timestamp-only: no Revision, no RqID"
    );
    assert!(
        !rq_keys.contains("Revision") && !rq_keys.contains("RqID"),
        "spelled out: Revision/RqID must be absent"
    );
    let ts = rqh["Timestamp"].as_i64().expect("Timestamp is an integer");
    assert!(
        ts > 1_700_000_000,
        "Timestamp is a current Unix-seconds value, got {ts}"
    );
    let data = obj["Data"].as_str().expect("Data is an AES string");
    decrypt_data(data, KEY, IV).expect("Data decrypts with the payment keys")
}

/// The typed happy path: the mock verifies the exact wire shape (path,
/// envelope key sets, decrypted OrderInfo/ConsumerInfo) and answers with the
/// stage-proven response shape; the typed output must decode it.
#[tokio::test]
async fn get_token_by_trade_round_trips_the_proven_envelope() {
    let seen_path: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let path = seen_path.clone();
    let srv = spawn_http_server(move |p, body| {
        *path.lock().unwrap_or_else(|e| e.into_inner()) = p.to_owned();
        let data = assert_envelope_and_decrypt(body);
        assert_eq!(
            data["MerchantID"], MERCHANT,
            "ECPay wants MerchantID inside Data as well as the envelope"
        );
        assert_eq!(data["RememberCard"], 1);
        assert_eq!(data["ChoosePaymentList"], "0");
        assert_eq!(data["OrderInfo"]["MerchantTradeNo"], "order1234567890");
        assert_eq!(
            data["OrderInfo"]["MerchantTradeDate"],
            "2026/09/11 06:57:06"
        );
        assert_eq!(
            data["OrderInfo"]["TotalAmount"], 100,
            "TotalAmount rides the wire as a JSON number (i64)"
        );
        assert_eq!(data["ConsumerInfo"]["Email"], "customer@email.com");
        assert_eq!(data["ConsumerInfo"]["Phone"], "0912345678");
        assert_eq!(data["ConsumerInfo"]["CountryCode"], "158");
        // Nested objects carry exactly their specified keys (Address unset →
        // omitted from ConsumerInfo; CardInfo unset → whole object absent).
        let order = data["OrderInfo"].as_object().unwrap();
        assert_eq!(
            order.keys().map(|k| k.as_str()).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "MerchantTradeDate",
                "MerchantTradeNo",
                "TotalAmount",
                "ReturnURL",
                "TradeDesc",
                "ItemName",
            ]),
            "OrderInfo key set"
        );
        let consumer = data["ConsumerInfo"].as_object().unwrap();
        assert_eq!(
            consumer.keys().map(|k| k.as_str()).collect::<BTreeSet<_>>(),
            BTreeSet::from(["MerchantMemberID", "Email", "Phone", "Name", "CountryCode",]),
            "ConsumerInfo key set"
        );
        // The exact response shape proven live on stage (2026-09).
        envelope_reply(json!({
            "MerchantID": "3002607",
            "RtnCode": 1,
            "RtnMsg": "",
            "Token": "37c33c79195f40339279dae54a96e39c",
            "TokenExpireDate": "2026/09/11 06:57:06",
        }))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));

    let out = ec.get_token_by_trade(&token_input()).await.unwrap();
    assert_eq!(out.merchant_id, "3002607");
    assert_eq!(out.rtn_code, 1);
    assert_eq!(out.rtn_msg, "");
    assert_eq!(out.token, "37c33c79195f40339279dae54a96e39c");
    assert_eq!(out.token_expire_date, "2026/09/11 06:57:06");
    assert_eq!(
        *seen_path.lock().unwrap_or_else(|e| e.into_inner()),
        "/Merchant/GetTokenbyTrade"
    );
}

/// The encrypted `Data` plaintext must keep the STRUCT's field-declaration
/// order (the Go/PHP reference wire), not a `serde_json::Value`'s
/// alphabetical BTreeMap order: the envelope helper's MerchantID guard must
/// never reorder the JSON it encrypts. The Value-based assertions above
/// cannot see key order at all — this pins the exact plaintext text, so a
/// serialize-via-Value refactor fails here instead of on the stage server.
#[tokio::test]
async fn data_plaintext_keeps_the_struct_field_order() {
    let srv = spawn_http_server(|_p, body| {
        let req: Value = serde_json::from_slice(body).expect("envelope is JSON");
        // AES-decrypt Data, then undo aesURLEncode (%XX decode, `+` -> space)
        // to recover the exact compact JSON text that was encrypted. The
        // encoded form is pure ASCII, so byte-wise decoding is safe; the
        // decoded bytes are valid UTF-8 (they were a JSON string).
        let encoded = ecpay::decrypt(req["Data"].as_str().unwrap(), KEY, IV).unwrap();
        let b = encoded.as_bytes();
        let mut plain: Vec<u8> = Vec::with_capacity(b.len());
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => {
                    plain.push(b' ');
                    i += 1;
                }
                b'%' => {
                    // Unlike the sibling mocks (which resync), this decoder
                    // VERIFIES the crate's encoder, so malformed input must
                    // fail loudly — but with a bounds assert, not a cryptic
                    // index panic.
                    assert!(
                        i + 2 < b.len(),
                        "aesURLEncode never emits a truncated escape"
                    );
                    let hi = hex(b[i + 1]).expect("encoder always writes 2 hex digits");
                    let lo = hex(b[i + 2]).expect("encoder always writes 2 hex digits");
                    plain.push(hi * 16 + lo);
                    i += 3;
                }
                c => {
                    plain.push(c);
                    i += 1;
                }
            }
        }
        let plaintext = String::from_utf8(plain).expect("decoded Data is UTF-8 JSON");
        assert_eq!(
            plaintext,
            serde_json::to_string(&token_input()).unwrap(),
            "Data plaintext must be the struct serialized in field-declaration order"
        );
        envelope_reply(json!({"RtnCode": 1, "RtnMsg": "", "Token": "t", "TokenExpireDate": "e"}))
    });
    let out = client(srv, "http://127.0.0.1:1/".into())
        .get_token_by_trade(&token_input())
        .await
        .expect("call succeeds");
    assert_eq!(out.rtn_code, 1);
}

/// Optional sub-objects and fields ride `Option` and must be OMITTED from
/// the decrypted Data when unset (the PHP examples omit them — sending an
/// empty object or null is a deviation), and a present sub-object omits its
/// own unset fields too.
#[tokio::test]
async fn unset_optional_pieces_are_omitted_from_the_wire() {
    let datas: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = datas.clone();
    let srv = spawn_http_server(move |_p, body| {
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(assert_envelope_and_decrypt(body));
        envelope_reply(json!({
            "MerchantID": "3002607", "RtnCode": 1, "RtnMsg": "",
            "Token": "t", "TokenExpireDate": "x",
        }))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));

    // Call 1: CardInfo/ATMInfo (and every other optional piece) unset.
    ec.get_token_by_trade(&token_input()).await.unwrap();

    // Call 2: CardInfo + ATMInfo set, but only ONE field inside each.
    let mut with_pieces = token_input();
    with_pieces.card_info = Some(CardInfo {
        credit_installment: Some("3,6".to_owned()),
        ..Default::default()
    });
    with_pieces.atm_info = Some(AtmInfo {
        expire_date: Some(3),
    });
    ec.get_token_by_trade(&with_pieces).await.unwrap();

    let d = datas.lock().unwrap_or_else(|e| e.into_inner());
    let minimal = d[0].as_object().unwrap();
    for absent in [
        "CardInfo",
        "ATMInfo",
        "UnionPayInfo",
        "CVSInfo",
        "BarcodeInfo",
    ] {
        assert!(
            !minimal.contains_key(absent),
            "{absent} must be absent from Data when None, got {minimal:?}"
        );
    }

    let full = d[1].as_object().unwrap();
    assert!(full.contains_key("CardInfo"), "{full:?}");
    assert!(full.contains_key("ATMInfo"), "{full:?}");
    let card = full["CardInfo"].as_object().unwrap();
    assert_eq!(
        card.keys().collect::<Vec<_>>(),
        ["CreditInstallment"],
        "unset fields inside a present sub-object are omitted too"
    );
    assert_eq!(full["ATMInfo"]["ExpireDate"], 3);
}

/// Boxed future alias so three different query methods can share one loop.
type BoxFut<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = ecpay::Result<serde_json::Value>> + 'a>>;

/// The query family needs its Data MerchantID too: live-captured 2026-09
/// (tests/stage_probes.rs, ecpg_data_merchant_id_omitted_or_mismatched_is_named_by_stage),
/// QueryTrade / QueryPaymentInfo / CreditDetail-QueryTrade ALL answer the
/// in-band `5000220 "The parameter [MerchantID] is required."` when it is
/// omitted (the old "the envelope MerchantID stands in" assumption is
/// falsified). Like DoAction/CreditCardPeriodAction, the methods refuse an
/// empty value locally before any bytes go out.
#[tokio::test]
async fn query_family_refuses_an_omitted_data_merchant_id() {
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit = sent.clone();
    let srv = spawn_http_server(move |_p, _body| {
        hit.store(true, std::sync::atomic::Ordering::SeqCst);
        envelope_reply(json!({"RtnCode": 1, "RtnMsg": ""}))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let input = EcpgTradeRefInput {
        merchant_trade_no: "no".to_owned(),
        ..Default::default()
    };
    let calls: [(&str, BoxFut<'_>); 3] = [
        ("QueryTrade", Box::pin(ec.ecpg_query_trade(&input))),
        (
            "QueryPaymentInfo",
            Box::pin(ec.ecpg_query_payment_info(&input)),
        ),
        (
            "CreditDetail/QueryTrade",
            Box::pin(ec.ecpg_query_credit_trade(&input)),
        ),
    ];
    for (label, call) in calls {
        let err = call
            .await
            .expect_err(&format!("{label}: omit must be refused"));
        let msg = err.to_string();
        assert!(
            msg.contains("Data MerchantID must be set") && msg.contains("5000220"),
            "{label}: {msg}"
        );
    }
    assert!(
        !sent.load(std::sync::atomic::Ordering::SeqCst),
        "no bytes may reach the wire without a Data MerchantID"
    );
}

/// TransCode != 1 (the envelope gate) surfaces as `Error::TransCode`
/// before any Data decoding is attempted.
#[tokio::test]
async fn transcode_rejection_surfaces_as_a_transcode_error() {
    let srv = spawn_http_server(|_p, _body| {
        let res = json!({"TransCode": 110, "TransMsg": "Data decrypt failed", "Data": ""});
        (
            200,
            "application/json".to_owned(),
            serde_json::to_vec(&res).unwrap(),
        )
    });
    let ec = client(srv.clone(), srv);
    let err = ec
        .get_token_by_trade(&token_input())
        .await
        .expect_err("TransCode != 1 must be an error");
    match err {
        Error::TransCode { code, msg } => {
            assert_eq!(code, 110);
            assert_eq!(msg, "Data decrypt failed");
        }
        other => panic!("expected Error::TransCode, got {other:?}"),
    }
}

/// The MerchantID duplicated inside Data must equal the client's: ECPay
/// rejects a mismatch server-side (5000261 / 5100074, live 2026-09), so the client
/// refuses locally before any request leaves — as the `Error::Validation`
/// doc promises for every per-family request guard.
#[tokio::test]
async fn data_merchant_id_must_match_the_client_merchant() {
    // Port 1: nothing listens there — the guard must fire BEFORE the request.
    let ec = client(
        "http://127.0.0.1:1/Merchant/".to_owned(),
        "http://127.0.0.1:1/1.0.0/".to_owned(),
    );
    let mut input = token_input();
    input.merchant_id = "someone-else".to_owned();
    let err = ec
        .get_token_by_trade(&input)
        .await
        .expect_err("mismatched Data MerchantID must be refused locally");
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("MerchantID"), "{err}");

    let mut empty = token_input();
    empty.merchant_id = String::new();
    let err = ec
        .get_token_by_trade(&empty)
        .await
        .expect_err("empty Data MerchantID must be refused locally");
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
}

/// Every one of the 14 methods posts to its exact dual-domain path — the
/// 8 creation/bindcard endpoints under `/Merchant/`, the 6 query/action
/// endpoints under `/1.0.0/` (their paths carry the Cashier/Credit/
/// CreditDetail prefix) — AND its decrypted Data carries exactly the
/// specified wire keys, which pins every serde rename (including the
/// otherwise-uncovered PayToken/BindCardID/BindCardPayToken/DateType/…
/// names) hermetically: a rename typo anywhere fails here.
#[tokio::test]
async fn every_method_hits_its_exact_dual_domain_path() {
    let seen: Arc<Mutex<Vec<(String, Value)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let srv = spawn_http_server(move |p, body| {
        let data = assert_envelope_and_decrypt(body);
        recorded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((p.to_owned(), data));
        envelope_reply(json!({
            "MerchantID": "3002607", "RtnCode": 1, "RtnMsg": "",
            "Token": "t", "TokenExpireDate": "x",
        }))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));

    ec.get_token_by_trade(&token_input()).await.unwrap();
    ec.create_payment(&CreatePaymentInput {
        merchant_id: MERCHANT.to_owned(),
        pay_token: "pay-token".to_owned(),
        merchant_trade_no: "order1234567890".to_owned(),
    })
    .await
    .unwrap();
    ec.create_payment_with_card_id(&CreatePaymentWithCardIdInput {
        merchant_id: MERCHANT.to_owned(),
        bind_card_id: "bind-card-id".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    ec.create_bind_card(&CreateBindCardInput {
        merchant_id: MERCHANT.to_owned(),
        bind_card_pay_token: "bind-token".to_owned(),
        merchant_member_id: "member000001".to_owned(),
    })
    .await
    .unwrap();
    ec.get_token_by_binding_card(&GetTokenbyBindingCardInput {
        merchant_id: MERCHANT.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    ec.get_token_by_user(&GetTokenbyUserInput {
        merchant_id: MERCHANT.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    ec.get_member_bind_card(&GetMemberBindCardInput {
        merchant_id: MERCHANT.to_owned(),
        merchant_member_id: "member000001".to_owned(),
        merchant_trade_no: "order1234567890".to_owned(),
    })
    .await
    .unwrap();
    ec.delete_member_bind_card(&DeleteMemberBindCardInput {
        merchant_id: MERCHANT.to_owned(),
        bind_card_id: "bind-card-id".to_owned(),
    })
    .await
    .unwrap();

    for out in [
        ec.ecpg_query_trade(&EcpgTradeRefInput {
            merchant_id: MERCHANT.to_owned(),
            merchant_trade_no: "order1234567890".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap(),
        ec.ecpg_query_payment_info(&EcpgTradeRefInput {
            merchant_id: MERCHANT.to_owned(),
            merchant_trade_no: "order1234567890".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap(),
        ec.ecpg_query_trade_media(&QueryTradeMediaInput {
            merchant_id: MERCHANT.to_owned(),
            date_type: "1".to_owned(),
            begin_date: "2026-09-01".to_owned(),
            end_date: "2026-09-11".to_owned(),
            payment_type: Some("01".to_owned()),
        })
        .await
        .unwrap(),
        ec.ecpg_credit_card_period_action(&EcpgPeriodActionInput {
            merchant_id: MERCHANT.to_owned(), // Data MerchantID required (stage 5000220 otherwise)
            merchant_trade_no: "order1234567890".to_owned(),
            action: "ReAuth".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap(),
        ec.ecpg_do_action(&EcpgDoActionInput {
            merchant_id: MERCHANT.to_owned(), // Data MerchantID required (stage 5000220 otherwise)
            merchant_trade_no: "order1234567890".to_owned(),
            trade_no: "ecpay-trade-no".to_owned(),
            action: EcpgCreditAction::Refund,
            total_amount: 100,
            ..Default::default()
        })
        .await
        .unwrap(),
        ec.ecpg_query_credit_trade(&EcpgTradeRefInput {
            merchant_id: MERCHANT.to_owned(),
            merchant_trade_no: "order1234567890".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap(),
    ] {
        assert_eq!(
            out["RtnCode"], 1,
            "the Value output is the decrypted reply, not a pass-through"
        );
    }

    let calls = seen.lock().unwrap_or_else(|e| e.into_inner());
    let got_paths: Vec<&str> = calls.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        got_paths,
        vec![
            // ecpg domain — creation/bindcard family.
            "/Merchant/GetTokenbyTrade",
            "/Merchant/CreatePayment",
            "/Merchant/CreatePaymentWithCardID",
            "/Merchant/CreateBindCard",
            "/Merchant/GetTokenbyBindingCard",
            "/Merchant/GetTokenbyUser",
            "/Merchant/GetMemberBindCard",
            "/Merchant/DeleteMemberBindCard",
            // ecpayment domain — query/action family.
            "/1.0.0/Cashier/QueryTrade",
            "/1.0.0/Cashier/QueryPaymentInfo",
            "/1.0.0/Cashier/QueryTradeMedia",
            "/1.0.0/Cashier/CreditCardPeriodAction",
            "/1.0.0/Credit/DoAction",
            "/1.0.0/CreditDetail/QueryTrade",
        ],
        "each method must hit its exact dual-domain path"
    );
    // The exact key set of every decrypted Data payload: unset Option fields
    // are ABSENT (not null, not ""), present ones carry their verbatim ECPay
    // wire names.
    let expected_keys: Vec<BTreeSet<&str>> = vec![
        // GetTokenbyTrade (only the set pieces of token_input()).
        BTreeSet::from([
            "MerchantID",
            "RememberCard",
            "PaymentUIType",
            "ChoosePaymentList",
            "OrderInfo",
            "ConsumerInfo",
        ]),
        // CreatePayment.
        BTreeSet::from(["MerchantID", "PayToken", "MerchantTradeNo"]),
        // CreatePaymentWithCardID (OrderInfo/ConsumerInfo/CustomField unset).
        BTreeSet::from(["MerchantID", "BindCardID"]),
        // CreateBindCard.
        BTreeSet::from(["MerchantID", "BindCardPayToken", "MerchantMemberID"]),
        // GetTokenbyBindingCard.
        BTreeSet::from(["MerchantID"]),
        // GetTokenbyUser.
        BTreeSet::from(["MerchantID"]),
        // GetMemberBindCard.
        BTreeSet::from(["MerchantID", "MerchantMemberID", "MerchantTradeNo"]),
        // DeleteMemberBindCard.
        BTreeSet::from(["MerchantID", "BindCardID"]),
        // QueryTrade / QueryPaymentInfo (PlatformID unset → omitted;
        // MerchantID required — stage 5000220 otherwise).
        BTreeSet::from(["MerchantID", "MerchantTradeNo"]),
        BTreeSet::from(["MerchantID", "MerchantTradeNo"]),
        // QueryTradeMedia.
        BTreeSet::from([
            "MerchantID",
            "DateType",
            "BeginDate",
            "EndDate",
            "PaymentType",
        ]),
        // CreditCardPeriodAction (Data MerchantID is REQUIRED on stage —
        // 5000220 "[MerchantID] is required" otherwise, live-captured 2026-09).
        BTreeSet::from(["MerchantID", "MerchantTradeNo", "Action"]),
        // DoAction (Data MerchantID required, same reason).
        BTreeSet::from([
            "MerchantID",
            "MerchantTradeNo",
            "TradeNo",
            "Action",
            "TotalAmount",
        ]),
        // QueryCreditTrade.
        BTreeSet::from(["MerchantID", "MerchantTradeNo"]),
    ];
    assert_eq!(calls.len(), expected_keys.len(), "every method sent once");
    for (i, (_, data)) in calls.iter().enumerate() {
        let keys: BTreeSet<&str> = data
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(keys, expected_keys[i], "call {i} Data key set: {data}");
    }
}

/// Query-family inputs: an EMPTY Data MerchantID is refused locally (stage
/// answers 5000220 — see query_family_refuses_an_omitted_data_merchant_id);
/// a set one rides the Data, and `PlatformID` is omitted when `None`.
/// DoAction carries its required fields verbatim. A set-but-mismatched Data
/// MerchantID is rejected locally instead of round-tripping to ECPay's
/// `5000261 "The parameter [MerchantID] does not match."`.
#[tokio::test]
async fn query_inputs_omit_unset_platform_id_and_require_merchant_id() {
    let datas: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = datas.clone();
    let srv = spawn_http_server(move |_p, body| {
        // into_inner, not unwrap: an earlier request's wire-assert panic
        // poisons the mutex, and the poisoned lock must not mask the later
        // requests' own assertions with a PoisonError.
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(assert_envelope_and_decrypt(body));
        envelope_reply(json!({"RtnCode": 1, "RtnMsg": ""}))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));

    // 1) MerchantID empty → refused locally (stage: 5000220 "The parameter
    //    [MerchantID] is required."; nothing may reach the wire).
    let err = ec
        .ecpg_query_trade(&EcpgTradeRefInput {
            merchant_trade_no: "no-1".to_owned(),
            ..Default::default()
        })
        .await
        .expect_err("omit must be refused");
    assert!(err.to_string().contains("5000220"), "{err}");

    // 1b) MerchantID set, PlatformID unset → Data omits PlatformID only.
    ec.ecpg_query_trade(&EcpgTradeRefInput {
        merchant_id: MERCHANT.to_owned(),
        merchant_trade_no: "no-1b".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    // 2) Both ids set → they ride the Data (MerchantID = the client's own).
    ec.ecpg_query_trade(&EcpgTradeRefInput {
        platform_id: Some("platform-id".to_owned()),
        merchant_id: MERCHANT.to_owned(),
        merchant_trade_no: "no-2".to_owned(),
    })
    .await
    .unwrap();

    // 3) DoAction required fields ride verbatim.
    ec.ecpg_do_action(&EcpgDoActionInput {
        merchant_id: MERCHANT.to_owned(),
        merchant_trade_no: "no-3".to_owned(),
        trade_no: "ecpay-trade-no".to_owned(),
        action: EcpgCreditAction::Refund,
        total_amount: 100,
        ..Default::default()
    })
    .await
    .unwrap();

    {
        let d = datas.lock().unwrap_or_else(|e| e.into_inner());
        // Only the request that PASSED the local guard reaches the wire:
        // 1b (MerchantID set, PlatformID unset), 2 (both set), 3 (DoAction).
        assert_eq!(d.len(), 3, "the refused call sent nothing: {d:?}");
        let keys: Vec<&str> = d[0]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            keys,
            ["MerchantID", "MerchantTradeNo"],
            "unset PlatformID must be omitted, got {keys:?}"
        );
        assert_eq!(d[0]["MerchantTradeNo"], "no-1b");
        assert_eq!(d[0]["MerchantID"], MERCHANT);
        assert_eq!(d[1]["PlatformID"], "platform-id");
        assert_eq!(d[1]["MerchantID"], MERCHANT);
        assert_eq!(d[2]["TradeNo"], "ecpay-trade-no");
        assert_eq!(d[2]["Action"], "R");
        assert_eq!(d[2]["TotalAmount"], 100);
    }

    // 4) A set-but-mismatched Data MerchantID never leaves the process:
    // port 1 is reserved, so an outbound request would fail with
    // Error::Http — Error::Validation proves the local guard fired.
    let offline = client(
        "http://127.0.0.1:1/Merchant/".to_owned(),
        "http://127.0.0.1:1/1.0.0/".to_owned(),
    );
    let err = offline
        .ecpg_query_trade(&EcpgTradeRefInput {
            platform_id: None,
            merchant_id: "sub-merchant".to_owned(),
            merchant_trade_no: "no-4".to_owned(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("Data MerchantID"), "{err}");
}

/// Live stage probe: the TYPED `get_token_by_trade` wire bytes against the
/// real stage server — the same shape `tests/stage_probes.rs` proved with
/// hand-built JSON, now re-proven through this module's structs and the
/// post_aes_json helper. Never runs under plain `cargo test` (offline suite);
/// run explicitly with:
///
/// ```bash
/// cargo test --test ecpg_wire -- --ignored --nocapture stage_probe
/// ```
#[tokio::test]
#[ignore = "hits the real stage server; the hermetic suite must stay offline"]
async fn stage_probe_get_token_by_trade_with_the_typed_method() {
    let ec = client(
        "https://ecpg-stage.ecpay.com.tw/Merchant/".to_owned(),
        "https://ecpayment-stage.ecpay.com.tw/1.0.0/".to_owned(),
    );
    let mut input = token_input();
    // Unique per run so stage never sees a duplicate MerchantTradeNo.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    input.order_info.as_mut().unwrap().merchant_trade_no = format!("WIRE{stamp}");
    // Mirror the stage-proven payload (tests/stage_probes.rs): RememberCard=1
    // without CardInfo.OrderResultURL is rejected with RtnCode 5100010
    // "[OrderResultURL] cannot be empty" (live-learned 2026-09).
    input.card_info = Some(CardInfo {
        redeem: Some(0),
        order_result_url: Some("https://www.ecpay.com.tw/example/receive".to_owned()),
        credit_installment: Some("3,6,12".to_owned()),
        flexible_installment: Some(30),
    });
    // The proven payload carries the three non-card payment sub-objects too;
    // stage rejects their absence one by one (5100010 "[ATMInfo] cannot be
    // empty" live-learned right after the OrderResultURL one).
    input.atm_info = Some(AtmInfo {
        expire_date: Some(3),
    });
    input.cvs_info = Some(ecpay::ecpg::CvsInfo {
        store_expire_date: Some(10080),
    });
    input.barcode_info = Some(ecpay::ecpg::BarcodeInfo {
        store_expire_date: Some(7),
    });

    let out = ec
        .get_token_by_trade(&input)
        .await
        .expect("envelope: TransCode==1 and Data decrypts");
    println!(
        "stage GetTokenbyTrade: RtnCode={} RtnMsg={:?} Token={} TokenExpireDate={}",
        out.rtn_code, out.rtn_msg, out.token, out.token_expire_date
    );
    assert_eq!(
        out.rtn_code, 1,
        "the typed structs must speak ECPG verbatim (RtnMsg={:?})",
        out.rtn_msg
    );
    assert!(
        !out.token.is_empty(),
        "a token was issued through the typed path"
    );
}

// --- The token/browser-flow endpoints that only had live/e2e coverage:
// each now pins the ecpg-domain path, the decrypted Data key set, and the
// omission of unset Option pieces. ---

/// Asserts the request path hit the ecpg domain with the expected action,
/// on top of the shared envelope checks.
fn assert_ecpg_path_and_decrypt(p: &str, body: &[u8], expected: &str) -> Value {
    assert_eq!(p, expected, "ecpg-domain path");
    assert_envelope_and_decrypt(body)
}

#[tokio::test]
async fn create_payment_posts_the_token_field_set() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/CreatePayment");
        let keys: BTreeSet<&str> = data
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["MerchantID", "MerchantTradeNo", "PayToken"]),
            "exact Data key set"
        );
        assert_eq!(data["MerchantID"], MERCHANT);
        assert_eq!(data["PayToken"], "tok-1234");
        envelope_reply(json!({"MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": ""}))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .create_payment(&CreatePaymentInput {
            merchant_id: MERCHANT.into(),
            pay_token: "tok-1234".into(),
            merchant_trade_no: "order1234567890".into(),
        })
        .await
        .expect("create_payment");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn create_payment_with_card_id_omits_unset_pieces() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/CreatePaymentWithCardID");
        assert_eq!(
            data.as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["BindCardID", "MerchantID"]),
            "OrderInfo/ConsumerInfo/CustomField absent when None"
        );
        assert_eq!(data["BindCardID"], "bc-777");
        envelope_reply(json!({"MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": ""}))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .create_payment_with_card_id(&CreatePaymentWithCardIdInput {
            merchant_id: MERCHANT.into(),
            bind_card_id: "bc-777".into(),
            ..Default::default()
        })
        .await
        .expect("create_payment_with_card_id");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn create_bind_card_posts_the_member_field_set() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/CreateBindCard");
        assert_eq!(
            data.as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["BindCardPayToken", "MerchantID", "MerchantMemberID"]),
        );
        assert_eq!(data["MerchantMemberID"], "member000001");
        envelope_reply(json!({"MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": ""}))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .create_bind_card(&CreateBindCardInput {
            merchant_id: MERCHANT.into(),
            bind_card_pay_token: "bcpt-1".into(),
            merchant_member_id: "member000001".into(),
        })
        .await
        .expect("create_bind_card");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn get_token_by_user_carries_only_consumer_info() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/GetTokenbyUser");
        assert_eq!(
            data.as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["ConsumerInfo", "MerchantID"]),
        );
        assert_eq!(data["ConsumerInfo"]["MerchantMemberID"], "member000001");
        envelope_reply(json!({
            "MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": "",
            "Token": "user-token", "TokenExpireDate": "2026/09/12 00:00:00",
        }))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .get_token_by_user(&GetTokenbyUserInput {
            merchant_id: MERCHANT.into(),
            consumer_info: Some(ConsumerInfo {
                merchant_member_id: Some("member000001".into()),
                email: "customer@email.com".into(),
                phone: "0912345678".into(),
                ..Default::default()
            }),
        })
        .await
        .expect("get_token_by_user");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn get_token_by_binding_card_posts_the_binding_field_set() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/GetTokenbyBindingCard");
        assert_eq!(
            data.as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["ConsumerInfo", "MerchantID", "OrderInfo"]),
            "OrderResultURL/CustomField absent when None"
        );
        assert_eq!(data["OrderInfo"]["MerchantTradeNo"], "order1234567890");
        envelope_reply(json!({
            "MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": "",
            "Token": "bind-token", "TokenExpireDate": "2026/09/12 00:00:00",
        }))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .get_token_by_binding_card(&GetTokenbyBindingCardInput {
            merchant_id: MERCHANT.into(),
            consumer_info: Some(ConsumerInfo {
                merchant_member_id: Some("member000001".into()),
                email: "customer@email.com".into(),
                phone: "0912345678".into(),
                ..Default::default()
            }),
            order_info: Some(OrderInfo {
                merchant_trade_date: "2026/09/12 06:57:06".into(),
                merchant_trade_no: "order1234567890".into(),
                total_amount: 100,
                return_url: "https://example.com/return".into(),
                trade_desc: "wire test".into(),
                item_name: "商品 x1".into(),
            }),
            ..Default::default()
        })
        .await
        .expect("get_token_by_binding_card");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn get_member_bind_card_posts_the_query_field_set() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/GetMemberBindCard");
        assert_eq!(
            data.as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["MerchantID", "MerchantMemberID", "MerchantTradeNo"]),
        );
        envelope_reply(json!({
            "MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": "",
            "BindCards": [],
        }))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .get_member_bind_card(&GetMemberBindCardInput {
            merchant_id: MERCHANT.into(),
            merchant_member_id: "member000001".into(),
            merchant_trade_no: "order1234567890".into(),
        })
        .await
        .expect("get_member_bind_card");
    assert_eq!(out["RtnCode"], 1);
}

#[tokio::test]
async fn delete_member_bind_card_posts_the_bind_card_id() {
    let srv = spawn_http_server(move |p, body| {
        let data = assert_ecpg_path_and_decrypt(p, body, "/Merchant/DeleteMemberBindCard");
        assert_eq!(
            data.as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["BindCardID", "MerchantID"]),
        );
        assert_eq!(data["BindCardID"], "bc-777");
        envelope_reply(json!({"MerchantID": MERCHANT, "RtnCode": 1, "RtnMsg": ""}))
    });
    let ec = client(format!("{srv}Merchant/"), format!("{srv}1.0.0/"));
    let out = ec
        .delete_member_bind_card(&DeleteMemberBindCardInput {
            merchant_id: MERCHANT.into(),
            bind_card_id: "bc-777".into(),
        })
        .await
        .expect("delete_member_bind_card");
    assert_eq!(out["RtnCode"], 1);
}

/// Negative money never rides the encrypted request: the same local
/// refusal `aio_check_out` and the payment family make for TWD amounts
/// (a sign typo on a refund would otherwise ride the AES envelope and come
/// back as an opaque server error).
#[tokio::test]
async fn ecpg_do_action_rejects_a_negative_total_amount() {
    // Port 1: nothing listens there — the guard must fire BEFORE the request.
    let ec = client(
        "http://127.0.0.1:1/Merchant/".to_owned(),
        "http://127.0.0.1:1/1.0.0/".to_owned(),
    );
    let err = ec
        .ecpg_do_action(&EcpgDoActionInput {
            merchant_id: MERCHANT.to_owned(),
            merchant_trade_no: "no".to_owned(),
            trade_no: "ecpay-trade-no".to_owned(),
            action: EcpgCreditAction::Refund,
            total_amount: -1,
            ..Default::default()
        })
        .await
        .expect_err("a negative TotalAmount must be refused locally");
    assert!(
        matches!(&err, Error::Validation(m) if m == "TotalAmount cannot be negative."),
        "{err:?}"
    );
}
