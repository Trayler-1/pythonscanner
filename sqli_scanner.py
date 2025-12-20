import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from sqli_payload_loader import load_sqli_payloads

SQLI_PAYLOADS = load_sqli_payloads("payloads/sqli.txt")
REQUEST_TIMEOUT = 15  # 2-3 saniyelik SLEEP için yeterli

def detect_error_based(response_text):
    """SQL hata mesajı kontrolü"""
    error_signatures = [
        "sql syntax", "mysql", "warning", "database error",
        "pdoexception", "sqlite", "unclosed quotation mark",
        "you have an error in your sql syntax", "postgresql",
    ]
    text = response_text.lower()
    return any(err in text for err in error_signatures)

def detect_time_based(response_time, payload, baseline=0):
    """Time-based SQLi tespiti"""
    if "SLEEP(2)" in payload or "DELAY '0:0:2'" in payload:
        expected_delay = 2
    elif "SLEEP(3)" in payload or "DELAY '0:0:3'" in payload:
        expected_delay = 3
    elif "SLEEP(5)" in payload or "DELAY '0:0:5'" in payload:
        expected_delay = 5
    else:
        return False

    difference = response_time - baseline
    threshold = expected_delay * 0.7

    if difference >= threshold:
        print(f"      [!] Gecikme: {difference:.2f}s (Beklenen: {expected_delay}s)")
        return True

    return False

def scan_sqli(url):
    """SQL Injection tarama (DÜZELTİLDİ: Payloadları gruplayarak raporlar!)"""
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Parametreleri al
    params = parse_qs(parsed.query)

    # Parametre yoksa test parametresi ekle
    if not params:
        params = {"id": ["1"]}  # Liste olarak!

    # Yeni yapı: Tüm başarılı payloadları tipe göre gruplayacak sözlük
    found_payloads = {}

    print(f"  [*] SQLi test ediliyor: {url}")
    print(f"  [*] Parametreler: {list(params.keys())}")

    # Baseline ölçümü
    baseline = 0
    try:
        start = time.time()
        normal_res = requests.get(url, timeout=REQUEST_TIMEOUT)
        baseline = time.time() - start
        normal_text = normal_res.text
        normal_length = len(normal_text)
        print(f"  [*] Baseline yanıt süresi: {baseline:.2f}s")
    except Exception as e:
        print(f"  [-] Baseline hatası: {e}")
        return []

    # Her parametre için (Sadece ilk parametrede zafiyet arıyoruz varsayalım)
    for param in params:
        print(f"    [*] '{param}' parametresi test ediliyor...")

        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]

            try:
                query_string = urlencode(test_params, doseq=True)
                test_url = f"{base_url}?{query_string}"

                start = time.time()
                res = requests.get(test_url, timeout=REQUEST_TIMEOUT)
                elapsed = time.time() - start

                vuln_type = None

                # 1. ERROR-BASED
                if detect_error_based(res.text):
                    vuln_type = "Error-based SQLi"

                # 2. TIME-BASED
                elif detect_time_based(elapsed, payload, baseline):
                    vuln_type = "Time-based Blind SQLi"

                # 3. CONTENT-BASED (Boolean ve Union saldırıları burada yakalanabilir)
                elif abs(len(res.text) - normal_length) > 100:
                    vuln_type = "Content-based SQLi"

                # Payload başarılıysa, kaydet
                if vuln_type:
                    # Payload'ı, tipine göre gruplayarak kaydet
                    if vuln_type not in found_payloads:
                        found_payloads[vuln_type] = []

                    # Eğer payload bu tipe ait kanıt listesinde zaten yoksa ekle
                    if payload not in found_payloads[vuln_type]:
                        found_payloads[vuln_type].append(payload)

                    print(f"      [!!!] {vuln_type} Kanıtı Bulundu: {payload}")

            except Exception as e:
                continue

        # Eğer bu parametrede herhangi bir payload başarılı olduysa, sonuçları toparla
        if found_payloads:
            # Tek bir zafiyet nesnesi oluştur, tüm payload'ları payloads_by_type içine koy
            final_vuln_report = {
                "type": "SQL Injection",
                "url": base_url,
                "parameter": param,
                "payloads_by_type": found_payloads
            }
            return [final_vuln_report] # Tek bir liste döndür

    return [] # Zafiyet bulunamazsa boş liste döndür