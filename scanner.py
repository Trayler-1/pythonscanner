import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from xss_payloads import XSS_PAYLOADS
from crawler import crawl_site
from sqli_scanner import scan_sqli

REQUEST_TIMEOUT = 10


def get_forms(url):
    """URL içindeki tüm form etiketlerini döndürür."""
    try:
        res = requests.get(url, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[-] Form taramada hata: {e}")
        return []


def get_form_details(form):
    """Formun action, method ve input isimlerini döndürür."""
    details = {}

    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()

    inputs = []
    for inp in form.find_all("input"):
        name = inp.attrs.get("name")
        if name:
            inputs.append(name)

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details


def scan_xss(form_details, url):
    """Form XSS taraması yapar. Tüm çalışan payloadları döndürür."""
    action = form_details["action"]
    method = form_details["method"]
    inputs = form_details["inputs"]

    target_url = urljoin(url, action)

    found_payloads = []   # ► çalışacak payloadlar buraya eklenecek

    for payload in XSS_PAYLOADS:
        data = {}

        # tüm inputlara payload bas
        for name in inputs:
            data[name] = payload

        try:
            if method == "post":
                res = requests.post(target_url, data=data, timeout=REQUEST_TIMEOUT)
            else:
                res = requests.get(target_url, params=data, timeout=REQUEST_TIMEOUT)

            if payload in res.text:
                found_payloads.append(payload)

        except Exception as e:
            print(f"[-] XSS sırasında hata: {e}")

    # ► Tüm payloadlar denendi, şimdi sonucu döndür
    return found_payloads


def main_scanner():
    target_url = input("Hedef site URL: ")

    print("\n--- SITE CRAWLER BAŞLIYOR ---")
    urls = crawl_site(target_url)
    print(f"[+] Bulunan toplam URL: {len(urls)}")

    xss_count = 0
    sqli_count = 0

    for url in urls:
        print(f"\n=== Taranıyor: {url} ===")

        # FORM TARAMASI
        forms = get_forms(url)
        for form in forms:
            details = get_form_details(form)
            payloads = scan_xss(details, url)

            if payloads:
                xss_count += 1
                print("\n[!!!] XSS Açığı Bulundu!")
                print(f"  URL: {url}")
                print(f"  Form Inputları: {details['inputs']}")
                print("  Çalışan Payloadlar:")

                for p in payloads:
                    print("   -", p)

        # SQL TARAYICI
        if scan_sqli(url):
            sqli_count += 1

    print("\n--- TARAMA BİTTİ ---")
    print(f"XSS Açığı Bulunan Form: {xss_count}")
    print(f"SQL Injection Açığı Bulunan URL: {sqli_count}")


if __name__ == "__main__":
    main_scanner()
