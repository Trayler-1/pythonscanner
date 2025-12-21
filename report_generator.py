from datetime import datetime

def generate_html_report(results, target_url):
    """
    Tarama sonuçlarından profesyonel HTML raporu oluşturur.
    """

    # İstatistikler
    total_urls = len(results)
    total_xss = sum(1 for r in results if r.get("xss"))
    total_sqli = sum(1 for r in results if r.get("sqli"))
    total_info = sum(1 for r in results if r.get("info_leak"))

    html = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>Güvenlik Tarama Raporu</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f6f8;
                padding: 20px;
            }}
            .container {{
                max-width: 1200px;
                margin: auto;
            }}
            .header {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
                gap: 15px;
                margin-bottom: 30px;
            }}
            .stat {{
                background: white;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                border-top: 5px solid #3498db;
            }}
            .stat.red {{ border-top-color: #e74c3c; }}
            .stat.orange {{ border-top-color: #e67e22; }}
            .stat.purple {{ border-top-color: #8e44ad; }}
            .vuln {{
                background: white;
                padding: 25px;
                border-radius: 10px;
                margin-bottom: 15px;
                border-left: 5px solid #e74c3c;
            }}
            .severity {{
                font-weight: bold;
                color: white;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 12px;
            }}
            .high {{ background: #e74c3c; }}
            .medium {{ background: #f39c12; }}
            .critical {{ background: #c0392b; }}
            footer {{
                text-align: center;
                margin-top: 40px;
                color: #777;
            }}
        </style>
    </head>
    <body>
    <div class="container">

        <div class="header">
            <h1>🔐 Güvenlik Tarama Raporu</h1>
            <p><strong>Hedef:</strong> {target_url}</p>
            <p><strong>Tarih:</strong> {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>
        </div>

        <div class="stats">
            <div class="stat"><h2>{total_urls}</h2><p>Taranan URL</p></div>
            <div class="stat red"><h2>{total_xss}</h2><p>XSS</p></div>
            <div class="stat orange"><h2>{total_sqli}</h2><p>SQLi</p></div>
            <div class="stat purple"><h2>{total_info}</h2><p>Hassas Bilgi</p></div>
        </div>

        <h2>🚨 Bulunan Zafiyetler</h2>
    """

    has_vulns = False

    for result in results:

        # XSS
        if result.get("xss"):
            has_vulns = True
            for xss in result["xss"]:
                html += f"""
                <div class="vuln">
                    <h3>XSS Zafiyeti <span class="severity high">HIGH</span></h3>
                    <p><strong>URL:</strong> {result['url']}</p>
                    <p><strong>Form Action:</strong> {xss['form']['action']}</p>
                </div>
                """

        # SQLi
        if result.get("sqli"):
            has_vulns = True
            for sqli in result["sqli"]:
                html += f"""
                <div class="vuln">
                    <h3>SQL Injection <span class="severity critical">CRITICAL</span></h3>
                    <p><strong>URL:</strong> {sqli.get('url', result['url'])}</p>
                    <p><strong>Parametre:</strong> {sqli.get('parameter')}</p>
                </div>
                """

        # HASSAS BİLGİ SIZINTISI
        if result.get("info_leak"):
            has_vulns = True
            for leak in result["info_leak"]:
                html += f"""
                <div class="vuln">
                    <h3>Hassas Bilgi Sızıntısı 
                        <span class="severity {'high' if leak.get('severity') == 'HIGH' else 'medium'}">
                            {leak.get('severity', 'HIGH')}
                        </span>
                    </h3>
                    <p><strong>URL:</strong> {leak.get('url')}</p>
                    <p><strong>Açıklama:</strong> {leak.get('description')}</p>
                </div>
                """

    if not has_vulns:
        html += "<p>✅ Herhangi bir zafiyet bulunamadı.</p>"

    html += """
        <footer>
            <p>Vulnerability Scanner v2.0 – Eğitim Amaçlı</p>
        </footer>

    </div>
    </body>
    </html>
    """

    filename = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename
