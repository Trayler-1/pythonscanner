import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
from crawler import crawl_site
from xss_payload_loader import load_xss_payloads
from scanner import scan_xss
from sqli_scanner import scan_sqli
from sqli_payload_loader import load_sqli_payloads
from report_generator import generate_html_report  # ✅ Zaten var

# Ayarlar
MAX_WORKERS = 8
TIMEOUT = 30
RESULT_FILE = "reports/scan_results.json"

session = requests.Session()
session.headers.update({"User-Agent": "VulnScanner/2.0"})

def scan_url_for_forms(url, payloads):
    """Bir URL'deki formları bulur ve test eder."""
    try:
        res = session.get(url, timeout=TIMEOUT)
    except Exception as e:
        return {"url": url, "error": f"GET error: {e}"}

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

def scan_url_for_sqli(url):
    """SQLi için tarama yapar."""
    try:
        res = scan_sqli(url)
        return {"url": url, "sqli": res if res else False}
    except Exception as e:
        return {"url": url, "sqli_error": str(e)}

def worker_scan(url, payloads):
    """URL için hem XSS hem SQLi taraması yapar."""
    xss_res = scan_url_for_forms(url, payloads)
    sqli_res = scan_url_for_sqli(url)

    combined = {"url": url}
    combined.update(xss_res)
    combined.update(sqli_res)
    return combined

def run(start_url):
    print("[*] Başlatılıyor, crawler çalışıyor...")
    urls = crawl_site(start_url)

    # Payloadları yükle
    xss_payloads = load_xss_payloads("payloads/xss.txt")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(worker_scan, u, xss_payloads): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                r = fut.result()
                results.append(r)

                # Konsola özet yazdır
                print(f"\n--- {u} ---")
                if r.get("xss"):
                    print("[XSS] Forms with payloads:")
                    for f in r["xss"]:
                        print("  form:", f["form"])
                        for p in f["payloads"]:
                            print("    -", p)
                if r.get("sqli"):
                    print("[SQLi] Possible SQLi found")
            except Exception as e:
                print(f"[!] Hata {u}: {e}")
    # JSON rapor kaydet
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[+] Tarama bitti. Sonuçlar: {RESULT_FILE}")

    # HTML RAPOR OLUŞTUR (ÖNEMLİ!)
    print("\n[*] HTML raporu oluşturuluyor...")
    try:
        html_file = generate_html_report(results, start_url)
        print(f"[+] ✅ HTML raporu hazır: {html_file}")
        print(f"[+] 📂 Raporu açmak için: start {html_file}")
    except Exception as e:
        print(f"[!] HTML raporu oluşturulamadı: {e}")

if __name__ == "__main__":
    target = input("Hedef URL (örn http://127.0.0.1:5000): ").strip()
    run(target)