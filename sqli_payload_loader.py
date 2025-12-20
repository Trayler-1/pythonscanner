def load_sqli_payloads(file_path="payloads/sqli.txt"):
    """
    SQL Injection payload dosyasını okur ve listeye döndürür.

    Args:
        file_path: Payload dosyasının yolu

    Returns:
        list: Payload'ların listesi
    """
    payloads = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()  # Baştaki/sondaki boşlukları temizle

                # Boş satır veya yorum satırını atla
                if line and not line.startswith("#"):
                    payloads.append(line)

        print(f"[+] {len(payloads)} SQLi payload yüklendi: {file_path}")

    except FileNotFoundError:
        print(f"[!] HATA: Dosya bulunamadı: {file_path}")
        print("[!] 'payloads/sqli.txt' dosyasını oluşturun!")

    return payloads