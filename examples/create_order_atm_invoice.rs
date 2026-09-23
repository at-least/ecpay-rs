//! Port of sample_create_order_ATM.py: an ATM order with a 7-day expiry,
//! including an electronic invoice (發票), rendered as an auto-submitting
//! form (offline).

use ecpay::payment::{
    AioCheckOutParams, ChoosePayment, Donation, InvType, InvoiceExtend, PrintMark, TaxType,
};
use ecpay::{BaseUrl, Ecpay, Env, Keys, Urls};

fn main() {
    let client = Ecpay::new(
        "3002607",
        Env::Custom(Urls {
            payment: Some(BaseUrl::new("https://payment-stage.ecpay.com.tw/Cashier/").unwrap()),
            ..Default::default()
        }),
    )
    .unwrap()
    .with_payment_keys(Keys::new("pwFHCqoQZGmho4w6", "EkRm7iFT261dpevs").unwrap());

    let checkout = client
        .aio_check_out(&AioCheckOutParams {
            merchant_trade_no: "NO20240101120000".into(),
            merchant_trade_date: "2024/01/01 12:00:00".into(),
            total_amount: 2000,
            trade_desc: "訂單測試".into(),
            item_name: "商品1#商品2".into(),
            return_url: "https://www.ecpay.com.tw/return_url.php".into(),
            choose_payment: ChoosePayment::Atm,
            expire_date: Some(7),
            payment_info_url: Some("https://www.ecpay.com.tw/payment_info_url.php".into()),
            // InvoiceMark=Y is filled automatically when invoice is present.
            invoice: Some(InvoiceExtend {
                relate_number: "Tea0001".into(),
                customer_name: Some("客戶名稱".into()),
                customer_addr: Some("台北市中正區100號".into()),
                customer_phone: Some("0912345678".into()),
                tax_type: TaxType::Dutiable,
                donation: Donation::No,
                print: PrintMark::No,
                invoice_item_name: "測試商品1#測試商品2".into(),
                invoice_item_count: "2#3".into(),
                invoice_item_word: "個#包".into(),
                invoice_item_price: "350#100".into(),
                delay_day: 0,
                inv_type: InvType::General,
                ..Default::default()
            }),
            ..Default::default()
        })
        .expect("create_order");

    println!("{}", checkout.html_form());
}
