from datetime import datetime

def generate_html_report(results, target_url):
    """
    Tarama sonuçlarından profesyonel HTML raporu oluşturur.

    Args:
        results: Tarama sonuçları (list of dict)
        target_url: Hedef URL

    Returns:
        str: Oluşturulan dosya adı
    """

    # İstatistikleri hesapla
    total_urls = len(results)
    total_xss = sum(1 for r in results if r.get("xss") and r["xss"])
    total_sqli = sum(1 for r in results if r.get("sqli") and r["sqli"])

    # HTML şablonu
    html = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Güvenlik Tarama Raporu</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px;
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            
            .header {{
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                margin-bottom: 30px;
            }}
            
            .header h1 {{
                color: #2c3e50;
                font-size: 36px;
                margin-bottom: 20px;
            }}
            
            .header-info {{
                color: #7f8c8d;
                font-size: 14px;
            }}
            
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                text-align: center;
                transition: transform 0.3s;
            }}
            
            .stat-card:hover {{
                transform: translateY(-5px);
            }}
            
            .stat-card.total {{
                border-top: 5px solid #3498db;
            }}
            
            .stat-card.xss {{
                border-top: 5px solid #e74c3c;
            }}
            
            .stat-card.sqli {{
                border-top: 5px solid #e67e22;
            }}
            
            .stat-number {{
                font-size: 48px;
                font-weight: bold;
                color: #2c3e50;
                margin: 10px 0;
            }}
            
            .stat-label {{
                color: #7f8c8d;
                font-size: 16px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            
            .vulnerabilities {{
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }}
            
            .vuln-title {{
                color: #2c3e50;
                font-size: 28px;
                margin-bottom: 30px;
                padding-bottom: 15px;
                border-bottom: 3px solid #3498db;
            }}
            
            .vuln-item {{
                background: #f8f9fa;
                padding: 25px;
                border-radius: 10px;
                margin-bottom: 20px;
                border-left: 5px solid #e74c3c;
            }}
            
            .vuln-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
            }}
            
            .vuln-type {{
                font-size: 20px;
                font-weight: bold;
                color: #e74c3c;
            }}
            
            .severity {{
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
            }}
            
            .severity-high {{
                background: #e74c3c;
                color: white;
            }}
            
            .severity-critical {{
                background: #c0392b;
                color: white;
            }}
            
            .vuln-detail {{
                color: #555;
                margin: 10px 0;
                line-height: 1.6;
            }}
            
            .vuln-detail strong {{
                color: #2c3e50;
            }}
            
            .code-block {{
                background: #2c3e50;
                color: #ecf0f1;
                padding: 15px;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 13px;
                overflow-x: auto;
                margin: 10px 0;
            }}
            
            .recommendation {{
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
                padding: 15px;
                border-radius: 8px;
                margin-top: 15px;
            }}
            
            .recommendation strong {{
                display: block;
                margin-bottom: 5px;
            }}
            
            .no-vulns {{
                text-align: center;
                padding: 60px 20px;
                color: #27ae60;
            }}
            
            .no-vulns i {{
                font-size: 64px;
                margin-bottom: 20px;
            }}
            
            footer {{
                text-align: center;
                color: white;
                margin-top: 40px;
                padding: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Güvenlik Tarama Raporu</h1>
                <div class="header-info">
                    <p><strong>Hedef:</strong> {target_url}</p>
                    <p><strong>Tarih:</strong> {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>
                    <p><strong>Tarayıcı:</strong> Vulnerability Scanner v2.0</p>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-card total">
                    <div class="stat-label">Taranan URL</div>
                    <div class="stat-number">{total_urls}</div>
                </div>
                <div class="stat-card xss">
                    <div class="stat-label">XSS Zafiyeti</div>
                    <div class="stat-number">{total_xss}</div>
                </div>
                <div class="stat-card sqli">
                    <div class="stat-label">SQLi Zafiyeti</div>
                    <div class="stat-number">{total_sqli}</div>
                </div>
            </div>
            
            <div class="vulnerabilities">
                <h2 class="vuln-title">🚨 Bulunan Zafiyetler</h2>
    """

    has_vulns = False

    # XSS zafiyetlerini ekle (Aynı kalıyor, çünkü zaten payloadları listeliyor)
    for result in results:
        if result.get("xss"):
            has_vulns = True
            for xss in result["xss"]:
                html += f"""
                <div class="vuln-item">
                    <div class="vuln-header">
                        <div class="vuln-type">⚠️ Cross-Site Scripting (XSS)</div>
                        <span class="severity severity-high">Yüksek</span>
                    </div>
                    <div class="vuln-detail">
                        <strong>URL:</strong> {result['url']}
                    </div>
                    <div class="vuln-detail">
                        <strong>Form Action:</strong> {xss['form']['action']}
                    </div>
                    <div class="vuln-detail">
                        <strong>Method:</strong> {xss['form']['method'].upper()}
                    </div>
                    <div class="vuln-detail">
                        <strong>Başarılı Payloadlar:</strong>
                    </div>
                    <div class="code-block">
                """
                for payload in xss['payloads']:
                    safe_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                    html += f"{safe_payload}<br>"

                html += """
                    </div>
                    <div class="recommendation">
                        <strong>💡 Çözüm Önerisi:</strong>
                        Kullanıcı girdilerini HTML encode edin, Content Security Policy (CSP) kullanın, 
                        ve input validasyonu yapın.
                    </div>
                </div>
                """

        # SQLi zafiyetlerini ekle (DEĞİŞTİRİLEN KISIM!)
        if result.get("sqli") and result["sqli"]:
            has_vulns = True
            sqli_list = result["sqli"] # sqli_scanner'dan gelen zafiyet listesi

            for sqli in sqli_list:
                if isinstance(sqli, dict):
                    # SQLi başlığı (Tüm payloadları tek bir blokta toplayacak)
                    html += f"""
                    <div class="vuln-item">
                        <div class="vuln-header">
                            <div class="vuln-type">⚠️ SQL Injection ({sqli.get('parameter', 'Bilinmiyor')} Parametresi)</div>
                            <span class="severity severity-critical">Kritik</span>
                        </div>
                        <div class="vuln-detail">
                            <strong>URL:</strong> {sqli.get('url', result['url'])}
                        </div>
                        <div class="vuln-detail">
                            <strong>Tip:</strong> {sqli.get('type', 'SQL Injection')}
                        </div>
                        <div class="vuln-detail">
                            <strong>Kanıtlanan Payloadlar:</strong>
                        </div>
                        <div class="code-block">
                    """

                    # Yeni kod: Payload tipleri (Error, Time, Content) üzerinde döngü kur
                    payloads_by_type = sqli.get("payloads_by_type", {})

                    if payloads_by_type:
                        for vuln_type, payload_list in payloads_by_type.items():
                            html += f"<strong>--- {vuln_type.upper()} ---</strong><br>"

                            for payload in payload_list:
                                # Payload'ı HTML kaçış karakterleriyle güvenli göster
                                safe_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                                html += f"{safe_payload}<br>"

                            html += "<br>" # Tipler arasına boşluk koy
                    else:
                        html += "N/A" # Payloadlar yoksa

                    html += """
                        </div>
                        <div class="recommendation">
                            <strong>💡 Çözüm Önerisi:</strong>
                            Prepared statements (parametreli sorgular) kullanın, ORM kullanın, 
                            input validasyonu ve sanitization yapın.
                        </div>
                    </div>
                    """

    if not has_vulns:
        html += """
            <div class="no-vulns">
                <div style="font-size: 64px;">✅</div>
                <h2>Harika Haber!</h2>
                <p>Taramada herhangi bir zafiyet bulunamadı.</p>
                <p style="margin-top: 10px; color: #7f8c8d;">
                    (Bu, sistemin tamamen güvenli olduğu anlamına gelmez. 
                    Daha kapsamlı testler yapılması önerilir.)
                </p>
            </div>
        """

    html += """
            </div>
            
            <footer>
                <p>Bu rapor otomatik olarak oluşturulmuştur.</p>
                <p>Vulnerability Scanner v2.0 - Eğitim Amaçlı</p>
            </footer>
        </div>
    </body>
    </html>
    """

    # Dosyaya kaydet
    filename = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML raporu oluşturuldu: {filename}")
    return filename