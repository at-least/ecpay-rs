# Generate conformance vectors from the REAL official ECPayAIO_Python SDK.
# `requests` is stubbed: the SDK only needs it for send_post, which no
# scenario here calls (create_order + generate_check_value are offline).
import json
import sys
import types

requests_stub = types.ModuleType("requests")
sys.modules["requests"] = requests_stub

import importlib.util
import os

SDK_PATH = os.environ.get(
    "ECPAY_PYTHON_SDK",
    os.path.join(os.path.dirname(__file__), "ECPayAIO_Python", "sdk", "ecpay_payment_sdk.py"),
)

spec = importlib.util.spec_from_file_location("ecpay_payment_sdk", SDK_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SDK = module.ECPayPaymentSdk

# The stage/test account the official samples use.
MERCHANT = dict(MerchantID="3002607", HashKey="pwFHCqoQZGmho4w6", HashIV="EkRm7iFT261dpevs")


def base_params(choose_payment):
    return {
        "MerchantTradeNo": "NO20240101120000",
        "StoreID": "",
        "MerchantTradeDate": "2024/01/01 12:00:00",
        "PaymentType": "aio",
        "TotalAmount": 2000,
        "TradeDesc": "訂單測試",
        "ItemName": "商品1#商品2",
        "ReturnURL": "https://www.ecpay.com.tw/return_url.php",
        "ChoosePayment": choose_payment,
        "ClientBackURL": "https://www.ecpay.com.tw/client_back_url.php",
        "ItemURL": "https://www.ecpay.com.tw/item_url.php",
        "Remark": "交易備註",
        "ChooseSubPayment": "",
        "OrderResultURL": "https://www.ecpay.com.tw/order_result_url.php",
        "NeedExtraPaidInfo": "Y",
        "DeviceSource": "",
        "IgnorePayment": "",
        "PlatformID": "",
        "InvoiceMark": "N",
        "CustomField1": "",
        "CustomField2": "",
        "CustomField3": "",
        "CustomField4": "",
        "EncryptType": 1,
    }


scenarios = {}

# --- create_order scenarios: (name, overrides) ---
create_cases = [
    ("credit_basic", {**base_params("Credit"), "BindingCard": 0, "MerchantMemberID": "", "Redeem": "N", "UnionPay": 0}),
    ("credit_installment", {**base_params("Credit"), "CreditInstallment": "3,6,12"}),
    ("credit_language", {**base_params("Credit"), "Language": "eng"}),
    ("credit_period", {**base_params("Credit"), "PeriodAmount": 1000, "PeriodType": "M", "Frequency": 1, "ExecTimes": 12, "PeriodReturnURL": "https://www.ecpay.com.tw/period_return_url.php"}),
    ("atm", {**base_params("ATM"), "ExpireDate": 7, "PaymentInfoURL": "https://www.ecpay.com.tw/payment_info_url.php", "ClientRedirectURL": ""}),
    ("cvs", {**base_params("CVS"), "StoreExpireDate": 10080, "Desc_1": "超商繳款說明1", "Desc_2": "", "Desc_3": "", "Desc_4": "", "PaymentInfoURL": "https://www.ecpay.com.tw/payment_info_url.php", "ClientRedirectURL": "https://www.ecpay.com.tw/client_redirect_url.php"}),
    ("barcode", {**base_params("BARCODE"), "StoreExpireDate": 120}),
    ("all", {**base_params("ALL"), "IgnorePayment": "WebATM#BARCODE"}),
    ("webatm", {**base_params("WebATM"), "ChooseSubPayment": "TAISHIN"}),
    ("bnpl", {**base_params("BNPL"), "ChooseSubPayment": "URICH"}),
    ("digital", {**base_params("DigitalPayment"), "ChooseSubPayment": "Jkopay"}),
    ("twqr", {**base_params("TWQR")}),
    ("weixin", {**base_params("WeiXin")}),
    ("googlepay", {**base_params("GooglePay")}),
    ("applepay", {**base_params("ApplePay")}),
    # Invoice scenarios: no uppercase ASCII in the six urlencoded free-text
    # fields, so the SDK's `.lower()` is a no-op and outputs must be equal.
    ("all_invoice", {**base_params("ALL"), "IgnorePayment": "WebATM#BARCODE", "InvoiceMark": "Y",
                     "RelateNumber": "Tea0001", "CustomerID": "", "CustomerIdentifier": "",
                     "CustomerName": "客戶名稱", "CustomerAddr": "台北市中正區100號", "CustomerPhone": "0912345678",
                     "CustomerEmail": "", "ClearanceMark": "", "TaxType": "1", "CarruerType": "",
                     "CarruerNum": "", "Donation": "2", "LoveCode": "", "Print": "0",
                     "InvoiceItemName": "測試商品1#測試商品2", "InvoiceItemCount": "2#3",
                     "InvoiceItemWord": "個#包", "InvoiceItemPrice": "350#100",
                     "InvoiceItemTaxType": "", "InvoiceRemark": "測試商品說明", "DelayDay": 0, "InvType": "07"}),
    ("credit_invoice_b2b", {**base_params("Credit"), "InvoiceMark": "Y",
                            "RelateNumber": "Tea0002", "CustomerID": "TEA_0000001", "CustomerIdentifier": "53348111",
                            "CustomerName": "客戶名稱", "CustomerAddr": "台北市中正區100號", "CustomerPhone": "",
                            "CustomerEmail": "abc@ecpay.com.tw", "ClearanceMark": "", "TaxType": "1",
                            "CarruerType": "", "CarruerNum": "", "Donation": "2", "LoveCode": "", "Print": "1",
                            "InvoiceItemName": "測試商品1", "InvoiceItemCount": "2", "InvoiceItemWord": "個",
                            "InvoiceItemPrice": "350", "InvoiceItemTaxType": "", "InvoiceRemark": "", "DelayDay": 0, "InvType": "07"}),
    ("atm_expire_zero", {**base_params("ATM"), "ExpireDate": 0}),  # 0 must be sent, -1 dropped
]

for name, params in create_cases:
    sdk = SDK(**MERCHANT)
    try:
        out = sdk.create_order(params)
        scenarios.setdefault("create_order", {})[name] = {"ok": sorted([str(k), str(v)] for k, v in out.items())}
    except Exception as error:  # noqa: BLE001
        scenarios.setdefault("create_order", {})[name] = {"error": str(error)}

# --- validation errors ---
error_cases = [
    ("missing_item_name", {**base_params("Credit"), "ItemName": ""}),
    ("too_long_trade_no", {**base_params("Credit"), "MerchantTradeNo": "A" * 21}),
    ("identifier_not_8", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerIdentifier": "123", "CustomerName": "客戶", "CustomerAddr": "地址", "CustomerPhone": "0912345678", "TaxType": "1", "Donation": "2", "Print": "0", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("identifier_with_carrier", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerIdentifier": "53348111", "CarruerType": "3", "CustomerName": "客戶", "CustomerAddr": "地址", "CustomerPhone": "0912345678", "TaxType": "1", "Donation": "2", "Print": "1", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("print_without_name", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerName": "", "CustomerAddr": "地址", "CustomerPhone": "0912345678", "TaxType": "1", "Donation": "2", "Print": "1", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("no_email_no_phone", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerName": "客戶", "CustomerAddr": "地址", "CustomerPhone": "", "CustomerEmail": "", "TaxType": "1", "Donation": "2", "Print": "0", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("donation_without_love_code", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerName": "客戶", "CustomerAddr": "地址", "CustomerPhone": "0912345678", "TaxType": "1", "Donation": "1", "Print": "0", "LoveCode": "", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("love_code_too_short", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerName": "客戶", "CustomerAddr": "地址", "CustomerPhone": "0912345678", "TaxType": "1", "Donation": "1", "Print": "0", "LoveCode": "1", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("donation_with_print", {**base_params("Credit"), "InvoiceMark": "Y", "RelateNumber": "T1", "CustomerName": "客戶", "CustomerAddr": "地址", "CustomerPhone": "0912345678", "TaxType": "1", "Donation": "1", "Print": "1", "LoveCode": "168001", "InvoiceItemName": "商品", "InvoiceItemCount": "1", "InvoiceItemWord": "個", "InvoiceItemPrice": "10", "DelayDay": 0, "InvType": "07"}),
    ("tachong_rejected", {**base_params("WebATM"), "ChooseSubPayment": "TACHONG"}),
    ("sinopac_rejected", {**base_params("WebATM"), "ChooseSubPayment": "SINOPAC"}),
]
for name, params in error_cases:
    sdk = SDK(**MERCHANT)
    try:
        sdk.create_order(params)
        scenarios.setdefault("errors", {})[name] = {"error": None}
    except Exception as error:  # noqa: BLE001
        scenarios.setdefault("errors", {})[name] = {"error": str(error)}

# --- generate_check_value vectors ---
check_cases = [
    # The Go-port's official SHA-256 vector params (no tilde): Python must
    # produce the same digest as ECPay's docs.
    ("official_sha256", {
        "MerchantID": "2000132", "MerchantTradeNo": "ecpay20130312153023",
        "MerchantTradeDate": "2013/03/12 15:30:23", "PaymentType": "aio",
        "TotalAmount": 1000, "TradeDesc": "促銷方案", "ItemName": "Apple iphone 7 手機殼",
        "ReturnURL": "https://www.ecpay.com.tw/receive.php", "ChoosePayment": "ALL",
        "EncryptType": 1,
    }),
    # Tilde: the Python SDK hashes the LITERAL ~ (quote_plus always-safe set)
    # while ECPay's .NET backend escapes it to %7e. This vector pins what the
    # SDK produces so the Rust side can assert the documented divergence.
    ("tilde_divergence", {
        "MerchantID": "2000132", "MerchantTradeNo": "tilde~case",
        "MerchantTradeDate": "2013/03/12 15:30:23", "PaymentType": "aio",
        "TotalAmount": 1000, "TradeDesc": "a~b", "ItemName": "x",
        "ReturnURL": "https://www.ecpay.com.tw/receive.php", "ChoosePayment": "ALL",
        "EncryptType": 1,
    }),
    # MD5 (EncryptType=0), retired by ECPay but supported by the SDK.
    ("md5_encrypt_type_0", {
        "MerchantID": "2000132", "MerchantTradeNo": "ecpay20130312153023",
        "MerchantTradeDate": "2013/03/12 15:30:23", "PaymentType": "aio",
        "TotalAmount": 1000, "TradeDesc": "促銷方案", "ItemName": "Apple iphone 7 手機殼",
        "ReturnURL": "https://www.ecpay.com.tw/receive.php", "ChoosePayment": "ALL",
        "EncryptType": 0,
    }),
]
sdk = SDK(**MERCHANT)
for name, params in check_cases:
    scenarios.setdefault("check_value", {})[name] = {
        "params": {k: str(v) for k, v in sorted(params.items())},
        "expected": sdk.generate_check_value(params),
    }

# A .NET-contract reference (HttpUtility.UrlEncode: unreserved alnum+-_.!*(),
# space->+, lowercase %xx) for the tilde case, so the Rust side can pin the
# ESCAPED digest it intends to produce instead of the SDK's.
def dot_net_url_encode(s):
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!*()")
    out = []
    for b in s.encode("utf-8"):
        c = chr(b)
        if c in safe:
            out.append(c)
        elif c == " ":
            out.append("+")
        else:
            out.append("%%%02x" % b)
    return "".join(out)


import hashlib  # noqa: E402

tilde = check_cases[1][1]
ordered = sorted(tilde.items(), key=lambda kv: kv[0].lower())
s = "HashKey=%s&" % MERCHANT["HashKey"] + "".join(f"{k}={v}&" for k, v in ordered) + "HashIV=%s" % MERCHANT["HashIV"]
scenarios.setdefault("check_value", {})["tilde_divergence"]["dot_net_escaped"] = hashlib.sha256(
    dot_net_url_encode(s).lower().encode("utf-8")
).hexdigest().upper()

# --- gen_html_post_form vector (no special chars) ---
final_order_params = SDK(**MERCHANT).create_order({**base_params("ATM"), "ExpireDate": 7, "PaymentInfoURL": "https://www.ecpay.com.tw/payment_info_url.php", "ClientRedirectURL": ""})
scenarios["html_form"] = {
    "action": "https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5",
    "params": sorted([str(k), str(v)] for k, v in final_order_params.items()),
    "html": SDK(**MERCHANT).gen_html_post_form(
        "https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5", final_order_params
    ),
}

# --- randomized differential corpus (seeded => reproducible) ---
# 150 random parameter maps signed by the REAL SDK; the Rust side must match
# every digest byte-for-byte (tilde-free inputs), and the 6 tilde-bearing
# cases pin the documented %7e divergence via dot_net_escaped.
import random  # noqa: E402

rng = random.Random(3002607)

# No two keys may collide under lowercasing: the SDK's stable sort breaks
# such ties by dict insertion order (unreproducible from a map API), while
# ecpay-rs tie-breaks on the original key (deterministic). Real ECPay keys
# are unique after lowercasing, so the corpus models that; the tie behavior
# is covered by a dedicated unit test.
alphabet = [
    "MerchantID", "MerchantTradeNo", "MerchantTradeDate", "PaymentType", "TotalAmount",
    "TradeDesc", "ItemName", "ReturnURL", "ChoosePayment", "EncryptType", "CustomField1",
    "CustomField2", "StoreID", "ChooseSubPayment", "RtnCode", "RtnMsg", "TradeNo",
    "PaymentDate", "a", "z", "_x", "Desc_1", "ItemURL", "lang",
]
value_parts = [
    "abc", "XYZ", "0123", "測試", "中文與English", "a b", "plus+", "eq=sign", "amp&ersand",
    "pct%25", "quote'q", "star*s", "paren(1)", "dash-d", "dot.d", "under_d",
    "emoji😀", "逗號,寫", "slash/ok", "colon:time", "at@site", "hash#tag", "q?", "semi;", "brack[]",
]

diff_cases = {}
for i in range(150):
    n = rng.randint(1, 10)
    # EncryptType is excluded: the SDK crashes on a non-numeric EncryptType
    # (int() ValueError) — real traffic always carries 0/1, and the Rust side
    # deliberately falls back to 1 on garbage (a documented robustness
    # difference, covered by the unit tests instead).
    keys = rng.sample([k for k in alphabet if k != "EncryptType"], n)
    params = {}
    for k in keys:
        v = "".join(rng.choice(value_parts) for _ in range(rng.randint(1, 3)))
        params[k] = v
    params.setdefault("MerchantID", "3002607")
    params["EncryptType"] = rng.choice(["0", "1"])
    sdk2 = SDK(**MERCHANT)
    diff_cases[f"rand_{i:03d}"] = {
        "params": {k: str(v) for k, v in sorted(params.items())},
        "expected": sdk2.generate_check_value(params),
    }
# Tilde-bearing divergence cases (Rust side must produce dot_net_escaped, not expected);
# the .NET-contract encoder is dot_net_url_encode above (byte-identical to the
# local copy this used to duplicate).
for i in range(6):
    params = {"MerchantID": "3002607", "MerchantTradeNo": f"tilde{i}", "TradeDesc": f"a~b~{i}", "ItemName": "x~y", "TotalAmount": str(100 + i), "EncryptType": "1"}
    ordered = sorted(params.items(), key=lambda kv: kv[0].lower())
    pre = "HashKey=%s&" % MERCHANT["HashKey"] + "".join(f"{k}={v}&" for k, v in ordered) + "HashIV=%s" % MERCHANT["HashIV"]
    diff_cases[f"tilde_{i:03d}"] = {
        "params": {k: str(v) for k, v in sorted(params.items())},
        "expected": SDK(**MERCHANT).generate_check_value(params),
        "dot_net_escaped": hashlib.sha256(dot_net_url_encode(pre).lower().encode("utf-8")).hexdigest().upper(),
    }

scenarios["differential"] = diff_cases

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "python_sdk_vectors.json")
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(scenarios, f, ensure_ascii=False, indent=1, sort_keys=True)
print(f"wrote {OUT}")
