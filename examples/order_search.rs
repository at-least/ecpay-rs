//! Port of sample_order_search.py: query a trade (QueryTradeInfo/V5).
//! Requires network access and real stage credentials via env vars:
//!
//! ```text
//! ECPAY_MERCHANT_ID=3002607 \
//! ECPAY_HASH_KEY=pwFHCqoQZGmho4w6 \
//! ECPAY_HASH_IV=EkRm7iFT261dpevs \
//! cargo run --example order_search -- <MerchantTradeNo>
//! ```

use ecpay::payment::OrderSearchParams;
use ecpay::Ecpay;

#[tokio::main]
async fn main() {
    let merchant_trade_no = std::env::args()
        .nth(1)
        .expect("usage: order_search <MerchantTradeNo>");
    let client = Ecpay {
        merchant_id: std::env::var("ECPAY_MERCHANT_ID").expect("ECPAY_MERCHANT_ID"),
        hash_key: std::env::var("ECPAY_HASH_KEY").expect("ECPAY_HASH_KEY"),
        hash_iv: std::env::var("ECPAY_HASH_IV").expect("ECPAY_HASH_IV"),
        // 測試環境(預設為正式環境):
        payment_api_url: std::env::var("ECPAY_PAYMENT_API_URL")
            .unwrap_or_else(|_| "https://payment-stage.ecpay.com.tw/Cashier/".into()),
        ..Default::default()
    };

    let result = client
        .order_search(&OrderSearchParams {
            merchant_trade_no,
            time_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            platform_id: None,
        })
        .await
        .expect("order_search");

    for (k, v) in &result {
        println!("{k} = {v}");
    }
}
