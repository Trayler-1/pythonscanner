from flask import Flask, request, render_template_string

app = Flask(__name__)

# XSS açığı olan basit bir arama sayfası
VULNERABLE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Zafiyetli Test Sayfası</title></head>
<body>
    <h1>Arama Sonuçları</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Arama yap...">
        <button type="submit">Ara</button>
    </form>
    
    {% if query %}
        <h2>Sonucunuz: {{ query }}</h2>
        <p>Girdiğiniz metin yansıtılıyor: <span>{{ query | safe}}</span></p>
    {% endif %}
    
    <p>Scanner'ınızın buradaki input'u bulup payload göndermesi gerekiyor.</p>
</body>
</html>
"""

@app.route('/')
@app.route('/search')
def search():
    # URL'den 'q' parametresini alır. Hiçbir filtreleme yapmaz.
    query = request.args.get('q', '')

    # HTML şablonuna, kullanıcıdan gelen sorguyu direkt yerleştirir.
    # Eğer sorgu bir <script>alert(1)</script> ise, XSS gerçekleşir.
    return render_template_string(VULNERABLE_HTML, query=query)

if __name__ == '__main__':
    # Sunucuyu varsayılan portta çalıştır (Örn: http://127.0.0.1:5000)
    app.run(debug=True)