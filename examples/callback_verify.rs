//! Verify an inbound payment-result callback's CheckMacValue (ReturnURL) —
//! the required check for every ECPay notification. Feed it the raw POSTed
//! form as key=value lines on stdin, e.g. from a webhook handler's params.
//!
//! ⚠ MAC verification alone is NOT "paid": before fulfilling an order you
//! must also deduplicate the notification, bind `TradeAmt`/`MerchantID` to
//! YOUR order record, and (high-value orders) confirm via `order_search` —
//! see the 回呼處理清單 / callback checklist in README.md, items 2–4.

use std::collections::HashMap;
use std::io::BufRead;

use ecpay::Ecpay;

fn main() {
    let client = Ecpay {
        merchant_id: std::env::var("ECPAY_MERCHANT_ID").unwrap_or_default(),
        hash_key: std::env::var("ECPAY_HASH_KEY").expect("ECPAY_HASH_KEY"),
        hash_iv: std::env::var("ECPAY_HASH_IV").expect("ECPAY_HASH_IV"),
        ..Default::default()
    };

    let stdin = std::io::stdin();
    let params: HashMap<String, String> = stdin
        .lock()
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| {
            line.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();

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
