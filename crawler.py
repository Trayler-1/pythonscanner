import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_site(start_url, max_urls=50):
    """
    Bir sitedeki tüm URL'leri bulur.

    Args:
        start_url: Başlangıç URL'i (örn: http://example.com)
        max_urls: Maksimum kaç URL taransın

    Returns:
        list: Bulunan URL'lerin listesi
    """
    visited = set()  # Zaten ziyaret edilenler
    to_visit = [start_url]  # Ziyaret edilecekler

    print(f"[*] Crawler başladı: {start_url}")

    while to_visit and len(visited) < max_urls:
        url = to_visit.pop(0)  # İlk URL'i al

        # Zaten ziyaret edildiyse atla
        if url in visited:
            continue

        print(f"[+] Taranıyor: {url}")
        visited.add(url)

        try:
            res = requests.get(url, timeout=5)
        except:
            continue  # Hata varsa atla

        # HTML'i parse et
        soup = BeautifulSoup(res.text, "html.parser")

        # Tüm linkleri bul
        for link in soup.find_all("a", href=True):
            href = link["href"]

            # Relatif URL'leri absolute yap
            full_url = urljoin(url, href)

            # Sadece aynı sitedeki linkleri al
            if urlparse(full_url).netloc == urlparse(start_url).netloc:
                if full_url not in visited:
                    to_visit.append(full_url)

        # Form action'larını da bul (önemli!)
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                form_url = urljoin(url, action)
                if urlparse(form_url).netloc == urlparse(start_url).netloc:
                    if form_url not in visited:
                        to_visit.append(form_url)

    print(f"[+] Toplam {len(visited)} URL bulundu")
    return list(visited)