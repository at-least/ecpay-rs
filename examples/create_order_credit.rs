//! Port of sample_create_order_Credit.py: build a Credit-card All-in-One
//! checkout form (offline — the browser does the POST).

use ecpay::payment::{need_extra_paid_info, union_pay, AioCheckOutParams, ChoosePayment};
use ecpay::Ecpay;

fn main() {
    let client = Ecpay {
        // 測試環境的帳號(官方 sample 使用);正式環境請換成你的金鑰。
        merchant_id: "3002607".into(),
        hash_key: "pwFHCqoQZGmho4w6".into(),
        hash_iv: "EkRm7iFT261dpevs".into(),
        // 測試環境:https://payment-stage.ecpay.com.tw/Cashier/
        payment_api_url: "https://payment-stage.ecpay.com.tw/Cashier/".into(),
        ..Default::default()
    };

    let checkout = client
        .aio_check_out(&AioCheckOutParams {
            merchant_trade_no: format!("NO{}", unix_seconds()),
            merchant_trade_date: "2024/01/01 12:00:00".into(),
            total_amount: 2000,
            trade_desc: "訂單測試".into(),
            item_name: "商品1#商品2".into(),
            return_url: "https://www.ecpay.com.tw/return_url.php".into(),
            choose_payment: ChoosePayment::Credit,
            client_back_url: Some("https://www.ecpay.com.tw/client_back_url.php".into()),
            need_extra_paid_info: Some(need_extra_paid_info::YES.into()),
            // 一次付清:紅利不折抵、銀聯可選
            redeem: Some("N".into()),
            union_pay: Some(union_pay::SELECT),
            ..Default::default()
        })
        .expect("create_order");

    println!("{}", checkout.html_form());
}

fn unix_seconds() -> String {
    // A timestamp suffix keeps the trade number unique for the demo; in
    // real code prefer a proper id, and note `merchant_trade_date` here is
    // a hardcoded placeholder — production needs the current time in
    // ECPay's yyyy/MM/dd HH:mm:ss format (e.g. via chrono::Utc::now with
    // UTC+8, see the MERCHANT_TRADE_DATE_FORMAT contract in the crate
    // docs).
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}
