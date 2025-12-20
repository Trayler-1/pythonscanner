def load_xss_payloads(file_path="payloads/xss.txt"):
    """
    XSS payload dosyasını okur ve listeye döndürür.

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

        print(f"[+] {len(payloads)} payload yüklendi: {file_path}")

    except FileNotFoundError:
        print(f"[!] HATA: Dosya bulunamadı: {file_path}")
        print("[!] 'payloads/xss.txt' dosyasını oluşturun!")

    return payloads