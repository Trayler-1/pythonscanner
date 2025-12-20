from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

def init_db():
    """
    Test için basit bir veritabanı oluştur.

    NEDEN BÖYLE?
    SQLi zafiyetini göstermek için kasıtlı olarak
    zafiyetli bir veritabanı sorgusu yazacağız.
    """
    conn = sqlite3.connect("test.db")
    c = conn.cursor()

    # Tablo oluştur
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, 
            name TEXT,
            email TEXT
        )
    """)

    # Örnek veriler
    c.execute("INSERT OR IGNORE INTO users (id, name, email) VALUES (1, 'Ali Veli', 'ali@test.com')")
    c.execute("INSERT OR IGNORE INTO users (id, name, email) VALUES (2, 'Ayşe Yılmaz', 'ayse@test.com')")
    c.execute("INSERT OR IGNORE INTO users (id, name, email) VALUES (3, 'Mehmet Kaya', 'mehmet@test.com')")

    conn.commit()
    conn.close()
    print("[+] Veritabanı hazırlandı!")

# Ana sayfa (XSS zafiyetli)
@app.route("/")
def index():
    """
    KASITLI XSS ZAFİYETİ!

    Kullanıcı 'search' parametresi ile ne yazarsa
    direkt olarak sayfaya yazdırılıyor.
    """
    search_query = request.args.get("search", "")

    # KASITLI HATA: Kullanıcı girdisini escape etmiyoruz!
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Zafiyetli Test Sitesi</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            .search-box {{ padding: 20px; background: #f0f0f0; }}
            input {{ padding: 10px; width: 300px; }}
            button {{ padding: 10px 20px; background: #007bff; color: white; border: none; }}
        </style>
    </head>
    <body>
        <h1>🔍 Arama Motoru (XSS Zafiyetli)</h1>
        <div class="search-box">
            <form method="GET">
                <input type="text" name="search" placeholder="Ara...">
                <button type="submit">Ara</button>
            </form>
        </div>
        
        <h2>Arama Sonuçları:</h2>
        <p>Aradığınız: {search_query}</p>
        
        <hr>
        <p><a href="/user?id=1">Kullanıcı Profili (SQLi Zafiyetli)</a></p>
        <p><a href="/comment">Yorum Formu (XSS Zafiyetli)</a></p>
    </body>
    </html>
    """
    return html

# Kullanıcı profili (SQLi zafiyetli)
@app.route("/user")
def user():
    """
    KASITLI SQLi ZAFİYETİ!

    Kullanıcı 'id' parametresini direkt SQL sorgusuna
    ekliyoruz. Bu çok tehlikeli!
    """
    user_id = request.args.get("id", "1")

    conn = sqlite3.connect("test.db")
    c = conn.cursor()

    # KASITLI HATA: f-string ile SQL yazmak!
    # Doğrusu: c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    query = f"SELECT * FROM users WHERE id = '{user_id}'"

    print(f"[SQL] Çalıştırılan sorgu: {query}")

    try:
        c.execute(query)
        result = c.fetchall()
        conn.close()

        html = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <h1>👤 Kullanıcı Bilgileri</h1>
            <p><strong>SQL Sorgusu:</strong> {query}</p>
            <p><strong>Sonuç:</strong> {result}</p>
            <hr>
            <a href="/">Ana Sayfa</a>
        </body>
        </html>
        """
        return html

    except Exception as e:
        conn.close()
        # Hata mesajını göstermek de zafiyet!
        return f"""
        <h1>SQL HATASI!</h1>
        <p style="color: red;">{str(e)}</p>
        <p>Sorgu: {query}</p>
        <a href="/">Ana Sayfa</a>
        """

# Yorum formu (XSS zafiyetli)
@app.route("/comment", methods=["GET", "POST"])
def comment():
    """
    KASITLI XSS ZAFİYETİ!

    POST ile gelen yorumları direkt gösteriyoruz.
    """
    if request.method == "POST":
        name = request.form.get("name", "")
        comment_text = request.form.get("comment", "")

        html = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <h1>💬 Yorum Gönderildi</h1>
            <div style="background: #f0f0f0; padding: 20px; margin: 20px 0;">
                <strong>{name}</strong> dedi ki:
                <p>{comment_text}</p>
            </div>
            <a href="/comment">Yeni Yorum</a>
        </body>
        </html>
        """
        return html

    # GET isteği - Form göster
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>💬 Yorum Formu (XSS Zafiyetli)</h1>
        <form method="POST">
            <p><input type="text" name="name" placeholder="Adınız" required></p>
            <p><textarea name="comment" placeholder="Yorumunuz" required></textarea></p>
            <button type="submit">Gönder</button>
        </form>
        <hr>
        <a href="/">Ana Sayfa</a>
    </body>
    </html>
    """

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        ⚠️  ZAFİYETLİ TEST SUNUCUSU                       ║
    ║        Bu sunucu KASITLI olarak zafiyetlidir!            ║
    ║        Sadece test amaçlı kullanın!                      ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    init_db()

    print("\n[*] Sunucu başlatılıyor...")
    print("[*] Adres: http://127.0.0.1:5000")
    print("[*] Durdurmak için: CTRL+C\n")

    app.run(debug=True, port=5000, use_reloader=False)