from urllib.parse import urljoin
import requests

REQUEST_TIMEOUT = 30

def scan_xss(form_details, url, payloads):
    """
    Bir formda XSS zafiyeti olup olmadığını test eder.

    Args:
        form_details: Form bilgileri (action, method, inputs)
        url: Formun bulunduğu sayfa URL'i
        payloads: Test edilecek XSS payload'ları

    Returns:
        list: Başarılı olan payload'lar
    """
    action = form_details["action"]
    method = form_details["method"]
    inputs = form_details["inputs"]

    # Form action'ı relatif olabilir, absolute yap
    target_url = urljoin(url, action)

    found_payloads = []

    print(f"  [*] Form test ediliyor: {target_url} ({method.upper()})")

    for payload in payloads:
        # Tüm input'lara aynı payload'ı yaz
        data = {name: payload for name in inputs}

        try:
            # Form methoduna göre istek at
            if method == "post":
                res = requests.post(target_url, data=data, timeout=REQUEST_TIMEOUT)
            else:
                res = requests.get(target_url, params=data, timeout=REQUEST_TIMEOUT)

            # Payload yanıtta görünüyor mu?
            # Eğer görünüyorsa XSS var demektir!
            if payload in res.text:
                print(f"    [!!!] XSS BULUNDU! Payload: {payload[:50]}")
                found_payloads.append(payload)

        except Exception as e:
            print(f"    [-] Hata: {e}")

    return found_payloads