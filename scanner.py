# scanner.py

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Yeni payload listemizi içe aktar
from xss_payloads import XSS_PAYLOADS

# SQLi modülünü entegre etmeye hazır olmak için varsayılan bir fonksiyon ekleyelim
# NOT: Eğer SQLi modülünü (sqli_scanner.py) henüz entegre etmediyseniz, bu kısmı görmezden gelin.
# from sqli_scanner import scan_sqli

REQUEST_TIMEOUT = 10

def get_forms(url):
    """Verilen URL'deki tüm form etiketlerini (form) ayrıştırır."""
    try:
        res = requests.get(url, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[-] Hata: URL'ye erişilemiyor veya formlar bulunamıyor: {e}")
        return []

def get_form_details(form):
    """Bir form etiketinden aksiyon, metot ve input isimlerini çıkarır."""
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        if input_name:
            inputs.append(input_name)

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def scan_xss(form_details, url):
    """Form detaylarını kullanarak XSS payload'larını dener ve yansıma kontrolü yapar."""

    action = form_details.get('action', "")
    target_url = urljoin(url, action)
    method = form_details['method']

    xss_found = False

    # Tüm payload'lar üzerinde döngü
    for payload in XSS_PAYLOADS:
        data = {}

        # Formdaki tüm input'lara aynı payload'ı ata
        for input_name in form_details['inputs']:
            if input_name:
                # Payload'ı, input adı olarak ata (payload, input adına basılmıyorsa bu gerekli)
                data[input_name] = payload

        # İsteği gönder
        try:
            if method == "post":
                res = requests.post(target_url, data=data, timeout=REQUEST_TIMEOUT)
            else: # GET metodu veya varsayılan
                res = requests.get(target_url, params=data, timeout=REQUEST_TIMEOUT)

            # Cevapta payload'ın yansımasını kontrol et
            if payload in res.text:
                print(f"[!!!] XSS Açığı Bulundu! URL: {target_url}")
                print(f"      Zafiyetli Form Alanı: {form_details['inputs']}")
                print(f"      Başarılı Payload: '{payload}'")
                xss_found = True
                # Bir açık bulununca bu form için diğer payload'ları denemeyi bırak


        except Exception as e:
            print(f"[-] XSS tarama sırasında hata: {e}")
            continue

    return xss_found

def main_scanner():
    target_url = input("Site URL'sini gir (Örn: http://127.0.0.1:5000): ")

    print("\n--- FORM BULMA ---")
    forms = get_forms(target_url)
    if not forms:
        print("[!] Hedefte taranacak form bulunamadı.")
        return

    print(f"[+] Toplam {len(forms)} form bulundu.")

    print("\n--- XSS TARAMASI BAŞLIYOR ---")
    xss_found_count = 0

    for form in forms:
        form_details = get_form_details(form)
        print(f"[i] XSS: {form_details.get('action', 'N/A')} form taranıyor...")

        if scan_xss(form_details, target_url):
            xss_found_count += 1

    # SQLi Tarama Bölümünü ekleyebiliriz (SQLi modülünü entegre edince)

    print("\n--- TARAMA SONUCU ---")
    if xss_found_count > 0:
        print(f"[!!!] Toplam {xss_found_count} XSS açığı bulundu.")
    else:
        print("[+] Tüm formlar taranmıştır. XSS açığı bulunamadı.")

if __name__ == "__main__":
    main_scanner()