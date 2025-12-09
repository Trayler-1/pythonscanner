import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

REQUEST_TIMEOUT = 10


def crawl_site(start_url, max_depth=2):
    visited = set()
    to_visit = [(start_url, 0)]
    found_urls = []

    while to_visit:
        url, depth = to_visit.pop(0)

        if depth > max_depth or url in visited:
            continue

        visited.add(url)
        found_urls.append(url)

        try:
            res = requests.get(url, timeout=REQUEST_TIMEOUT)
        except:
            continue

        soup = BeautifulSoup(res.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")
            if not href:
                continue

            absolute = urljoin(url, href)

            if urlparse(absolute).netloc == urlparse(start_url).netloc:
                to_visit.append((absolute, depth + 1))

    return found_urls
