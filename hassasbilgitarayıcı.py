import requests
from urllib.parse import urlparse, urljoin

REQUEST_TIMEOUT = 10

# Hassas dosyalar ve dizinler
SENSITIVE_FILES = [
    # Version control
    ".git/config",
    ".git/HEAD",
    ".svn/entries",
    ".hg/store",

    # Backup files
    "backup.zip",
    "backup.sql",
    "backup.tar.gz",
    "db_backup.sql",
    "database.sql",
    "dump.sql",
    "site_backup.zip",
    "www.zip",
    "web.zip",

    # Config files
    "config.php",
    "configuration.php",
    "settings.php",
    "database.php",
    "wp-config.php",
    ".env",
    ".env.local",
    ".env.production",
    "config.json",
    "config.yml",
    "app.json",

    # Log files
    "error.log",
    "access.log",
    "debug.log",
    "application.log",
    "app.log",

    # Admin panels
    "admin/",
    "admin.php",
    "administrator/",
    "phpmyadmin/",
    "wp-admin/",
    "cpanel/",
    "controlpanel/",

    # Info files
    "phpinfo.php",
    "info.php",
    "test.php",
    "README.md",
    "CHANGELOG.md",
    "TODO.txt",

    # Database
    "db.sql",
    "database.sqlite",
    "data.db",

    # Source code
    "index.php.bak",
    "index.php~",
    "index.php.old",
    ".htaccess",
    "web.config",

    # IDE files
    ".idea/",
    ".vscode/",
    ".project",
    ".classpath",

    # Package managers
    "composer.json",
    "package.json",
    "requirements.txt",
    "Gemfile",

    # API keys / credentials
    "credentials.txt",
    "api_keys.txt",
    "secrets.txt",
]

# Dizin listeleme URL'leri
DIRECTORY_LISTING_PATHS = [
    "uploads/",
    "images/",
    "files/",
    "backup/",
    "backups/",
    "logs/",
    "temp/",
    "tmp/",
    "cache/",
]

def check_sensitive_file(base_url, file_path):
    """
    Tek bir hassas dosyayı kontrol eder

    Returns:
        dict veya None
    """
    test_url = urljoin(base_url, file_path)

    try:
        response = requests.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)

        # 200 OK veya 403 Forbidden (dosya var ama erişim yok)
        if response.status_code in [200, 403]:
            # İçerik kontrolü
            content_length = len(response.content)

            # 200 ise içeriğe bak
            if response.status_code == 200:
                # Çok küçük dosyalar (404 sayfası olabilir)
                if content_length < 10:
                    return None

                # İçerikte "not found" var mı?
                if 'not found' in response.text.lower():
                    return None

                return {
                    'file': file_path,
                    'url': test_url,
                    'status': response.status_code,
                    'size': content_length,
                    'accessible': True,
                    'content_type': response.headers.get('Content-Type', 'unknown')
                }

            # 403 ise dosya var ama erişilemiyor
            elif response.status_code == 403:
                return {
                    'file': file_path,
                    'url': test_url,
                    'status': 403,
                    'accessible': False,
                    'note': 'Dosya mevcut ama erişim engelli'
                }

        return None

    except Exception as e:
        return None

def check_directory_listing(base_url, dir_path):
    """
    Dizin listeleme zafiyeti kontrolü

    Returns:
        dict veya None
    """
    test_url = urljoin(base_url, dir_path)

    try:
        response = requests.get(test_url, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            # Directory listing göstergeleri
            indicators = [
                'Index of /',
                'Directory listing',
                'Parent Directory',
                '<title>Index of',
                '[To Parent Directory]'
            ]

            if any(indicator in response.text for indicator in indicators):
                return {
                    'directory': dir_path,
                    'url': test_url,
                    'status': 'Directory listing enabled',
                    'severity': 'MEDIUM'
                }

        return None

    except Exception as e:
        return None

def hassas_bilgi_tara(url):
    """
    Hassas bilgi sızıntısı taraması yapar

    Args:
        url: Test edilecek base URL

    Returns:
        list: Bulunan zafiyetler
    """
    vulnerabilities = []

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}/"

    print(f"  [*] Hassas bilgi sızıntısı kontrolü: {base_url}")

    # 1. Hassas dosyaları kontrol et
    print(f"  [*] {len(SENSITIVE_FILES)} hassas dosya kontrol ediliyor...")

    found_files = []
    for file_path in SENSITIVE_FILES:
        result = check_sensitive_file(base_url, file_path)
        if result:
            found_files.append(result)
            if result['accessible']:
                print(f"    [!!!] Hassas dosya bulundu: {file_path} ({result['size']} bytes)")
            else:
                print(f"    [!] Dosya mevcut ama erişim engelli: {file_path}")

    if found_files:
        vulnerability = {
            'type': 'Sensitive Information Disclosure',
            'url': base_url,
            'files_found': found_files,
            'count': len(found_files),
            'severity': 'HIGH',
            'description': f'{len(found_files)} adet hassas dosya/dizin bulundu ve erişilebilir.'
        }
        vulnerabilities.append(vulnerability)

    # 2. Dizin listeleme kontrolü
    print(f"  [*] Dizin listeleme kontrolü yapılıyor...")

    found_dirs = []
    for dir_path in DIRECTORY_LISTING_PATHS:
        result = check_directory_listing(base_url, dir_path)
        if result:
            found_dirs.append(result)
            print(f"    [!!!] Dizin listeleme aktif: {dir_path}")

    if found_dirs:
        vulnerability = {
            'type': 'Directory Listing Enabled',
            'url': base_url,
            'directories': found_dirs,
            'count': len(found_dirs),
            'severity': 'MEDIUM',
            'description': f'{len(found_dirs)} dizinde directory listing aktif.'
        }
        vulnerabilities.append(vulnerability)

    if not vulnerabilities:
        print(f"  [✓] Hassas bilgi sızıntısı tespit edilmedi")

    return vulnerabilities