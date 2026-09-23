//! Verify an inbound payment-result callback's CheckMacValue (ReturnURL) —
//! the required check for every ECPay notification. Feed it the raw POSTed
//! form body (`a=1&b=%E5%95%86...`) on stdin; `ecpay::parse_form`
//! percent-decodes it into the map `verify_check_mac_value` takes (the MAC
//! is computed over DECODED values — feeding still-encoded values never
//! verifies).
//!
//! ⚠ MAC verification alone is NOT "paid": before fulfilling an order you
//! must also deduplicate the notification, bind `TradeAmt`/`MerchantID` to
//! YOUR order record, and (high-value orders) confirm via `order_search` —
//! see the 回呼處理清單 / callback checklist in README.md, items 2–4.

use std::collections::HashMap;
use std::io::Read;

use ecpay::{Ecpay, Env, Keys};

fn main() {
    let client = Ecpay::new(
        std::env::var("ECPAY_MERCHANT_ID").unwrap_or_default(),
        Env::Production,
    )
    .unwrap()
    .with_payment_keys(
        Keys::new(
            std::env::var("ECPAY_HASH_KEY").expect("ECPAY_HASH_KEY"),
            std::env::var("ECPAY_HASH_IV").expect("ECPAY_HASH_IV"),
        )
        .unwrap(),
    );

    let mut body = String::new();
    std::io::stdin()
        .read_to_string(&mut body)
        .expect("read stdin");
    let params: HashMap<String, String> = ecpay::parse_form(body.trim());

    if client.verify_check_mac_value(&params) {
        println!("1|OK — CheckMacValue verified");
        match params.get("RtnCode").map(String::as_str) {
            Some("1") => println!(
                "paid: {}",
                params.get("MerchantTradeNo").cloned().unwrap_or_default()
            ),
            Some(code) => println!("payment not complete (RtnCode={code})"),
            None => println!("no RtnCode in the callback"),
        }
    } else {
        println!("0|ERR — CheckMacValue mismatch");
        std::process::exit(1);
    }
}
