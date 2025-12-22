import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from crawler import crawl_site
from xss_payload_loader import load_xss_payloads
from scanner import scan_xss
from sqli_scanner import scan_sqli
from report_generator import generate_html_report
from hassasbilgitarayıcı import hassas_bilgi_tara

MAX_WORKERS = 8
TIMEOUT = 30
RESULT_FILE = "reports/scan_results.json"

session = requests.Session()
session.headers.update({"User-Agent": "VulnScanner/3.0"})

def scan_url_for_forms(url, payloads):
    """Bir URL'deki formları bulur ve test eder."""
    try:
        res = session.get(url, timeout=TIMEOUT)
    except Exception as e:
        return {"url": url, "error": f"GET error: {e}", "xss": []}

    soup = BeautifulSoup(res.text, "html.parser")
    forms = soup.find_all("form")

    findings = []
    for form in forms:
        inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
        details = {
            "action": form.get("action") or url,
            "method": form.get("method", "get").lower(),
            "inputs": inputs
        }
        found = scan_xss(details, url, payloads)
        if found:
            findings.append({"form": details, "payloads": found})

    return {"url": url, "xss": findings}

def get_base_path(url):

    parsed = urlparse(url)

    # Pathi al ve son segmenti çıkar
    path = parsed.path.rstrip('/')

    # Eğer path varsa, son segmenti çıkar
    if '/' in path:
        base_path = path.rsplit('/', 1)[0]
    else:
        base_path = ''

    # Base URL oluştur
    base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/"

    return base_url

def extract_unique_paths(urls):
    """
    URL listesinden benzersiz base path'leri çıkarır

    Girdi:
      ['http://127.0.0.1:5000/',
       'http://127.0.0.1:5000/user?id=1',
       'http://127.0.0.1:5000/comment']

    Çıktı:
      {'http://127.0.0.1:5000/'}
    """
    unique_paths = set()

    for url in urls:
        base = get_base_path(url)
        unique_paths.add(base)

    return unique_paths

def worker_scan(url, payloads, scan_info_for_this_url=False):
    """
    URL için taramaları yapar:
    - XSS
    - SQLi
    - Hassas Bilgi (sadece işaretli URL'ler için)
    """

    # 1. XSS Taraması
    xss_res = scan_url_for_forms(url, payloads)

    # 2. SQLi Taraması
    try:
        sqli_res = scan_sqli(url)
    except Exception as e:
        sqli_res = []
        print(f"  [-] SQLi hatası: {e}")

    # 3. Hassas Bilgi Taraması (sadece işaretli URL'ler için)
    info_res = []
    if scan_info_for_this_url:
        try:
            info_res = hassas_bilgi_tara(url)
        except Exception as e:
            print(f"  [-] Hassas bilgi tarama hatası: {e}")


    combined = {
        "url": url,
        "xss": xss_res.get("xss", []),
        "sqli": sqli_res if sqli_res else [],
        "info_leak": info_res if info_res else []
    }

    return combined

def run(start_url):
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        🔍 GÜVENLİK TARAYICI v3.0                        ║
    ║                                                          ║
    ║  Tarama Kapsamı:                                        ║
    ║    ✓ XSS (Cross-Site Scripting)                        ║
    ║    ✓ SQL Injection                                      ║
    ║    ✓ Hassas Bilgi Sızıntısı                            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    print("[*] Crawler başlatılıyor...")
    urls = crawl_site(start_url)
    print(f"[+] {len(urls)} URL bulundu\n")

    # Payloadları yükle
    xss_payloads = load_xss_payloads("payloads/xss.txt")

    # Benzersiz path'leri çıkar
    unique_paths = extract_unique_paths(urls)
    print(f"[*] {len(unique_paths)} benzersiz path bulundu")
    print(f"[*] Hassas bilgi taraması sadece bu path'lerde yapılacak:")
    for path in unique_paths:
        print(f"    - {path}")
    print()

    # Her URL için, o URL'in path'i benzersiz mi kontrol et
    url_to_scan_info = {}
    for url in urls:
        base = get_base_path(url)
        # Bu path'i ilk kez mi görüyoruz?
        if base in unique_paths:
            url_to_scan_info[url] = True
            unique_paths.remove(base)  # İşaretle, bir daha tarama
        else:
            url_to_scan_info[url] = False

    print(f"[*] {len(urls)} URL için paralel tarama başlatılıyor...")
    print(f"[*] Worker sayısı: {MAX_WORKERS}\n")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        for u in urls:
            scan_info = url_to_scan_info[u]
            futures[ex.submit(worker_scan, u, xss_payloads, scan_info)] = u

        for idx, fut in enumerate(as_completed(futures), 1):
            u = futures[fut]
            try:
                r = fut.result()
                results.append(r)

            except Exception as e:
                print(f"[!] Hata {u}: {e}")

    # JSON rapor kaydet
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[+] JSON rapor kaydedildi: {RESULT_FILE}")

    # HTML rapor oluştur
    try:
        html_file = generate_html_report(results, start_url)
        print(f"[+] ✅ HTML raporu hazır: {html_file}")
        print(f"[+] 📂 Raporu açmak için: start {html_file}")
    except Exception as e:
        print(f"[!] HTML raporu oluşturulamadı: {e}")


    total_xss = sum(1 for r in results if r.get("xss"))
    total_sqli = sum(1 for r in results if r.get("sqli"))


# Hassas dosyaları benzersiz olarak say
    all_info_files = set()
    for r in results:
        if r.get("info_leak"):
            for leak in r["info_leak"]:
                all_info_files.add(leak['url'])

    total_info = len(all_info_files)

    print(f"   Taranan URL: {len(results)}")
    print(f"    XSS: {total_xss}")
    print(f"  ️  SQL Injection: {total_sqli}")
    print(f"  ️  Hassas Bilgi: {total_info} benzersiz dosya")
    print(f"   Toplam Zafiyet: {total_xss + total_sqli + total_info}")

if __name__ == "__main__":
    target = input("🎯 Hedef URL (örn http://127.0.0.1:5000): ").strip()

    if not target:
        print("[!] Hata: URL girilmedi!")
        exit(1)

    run(target)