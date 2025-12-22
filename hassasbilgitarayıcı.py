import requests
from urllib.parse import urlparse, urljoin

REQUEST_TIMEOUT = 10

# ✅ GÜNCELLENDİ: Hem .env hem hassas.env arıyor
SENSITIVE_PATHS = [
    ".env",
    ".env.local",
    ".env.production",
    "config.php",
    "test.php",
    "phpinfo.php",
    "backup.sql",
    "database.sql",
    "config.json",
    "wp-config.php",
    ".git/config",
    "composer.json",
    "package.json",
]

# İÇERİK ANAHTAR KELİMELERİ
SENSITIVE_KEYWORDS = [
    "DB_PASSWORD",
    "API_KEY",
    "SECRET",
    "SECRET_KEY",
    "AWS_ACCESS_KEY",
    "PASSWORD=",
    "STRIPE",
    "SENDGRID",
    "JWT_SECRET",
]

def check_sensitive_file(base_url, file_path):
    """Tek bir hassas dosyayı kontrol eder"""
    test_url = urljoin(base_url, file_path)

    try:
        r = requests.get(test_url, timeout=REQUEST_TIMEOUT)

        if r.status_code == 200 and len(r.text) > 10:
            # İçerikte "not found" var mı kontrol et
            if 'not found' in r.text.lower() or '404' in r.text:
                return None

            # Anahtar kelime ara
            matched = [kw for kw in SENSITIVE_KEYWORDS if kw in r.text]

            if matched:
                return {
                    "file": file_path,
                    "url": test_url,
                    "status": r.status_code,
                    "size": len(r.text),
                    "keywords": matched
                }

        return None

    except Exception:
        return None

def hassas_bilgi_tara(url):
    """
    Hassas bilgi sızıntısı taraması (PATH + CONTENT ANALYSIS)
    """
    findings = []

    parsed = urlparse(url)

    # ✅ GÜNCELLENDİ: /static/ de kontrol ediliyor
    base_urls = [
        f"{parsed.scheme}://{parsed.netloc}/",
        f"{parsed.scheme}://{parsed.netloc}/static/",
    ]

    print("  [*] Hassas bilgi sızıntısı taraması başlatıldı")

    for base in base_urls:
        for path in SENSITIVE_PATHS:
            res = check_sensitive_file(base, path)
            if res:
                print(f"    [!!!] Hassas dosya bulundu: {res['file']} ({len(res['keywords'])} anahtar kelime)")
                findings.append(res)

    if not findings:
        print("  [✓] Hassas bilgi sızıntısı bulunamadı")

    return findings