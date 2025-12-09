from flask import Flask, request, render_template_string

app = Flask(__name__)

VULNERABLE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Zafiyet Testi</title></head>
<body>
    <h1>Test Arama</h1>
    <form method="GET" action="/search">
        <input type="text" name="q">
        <button type="submit">Ara</button>
    </form>

    {% if query %}
        <h2>Veri: {{ query }}</h2>
        <p>Yansıyan Input: <span>{{ query | safe }}</span></p>
    {% endif %}
</body>
</html>
"""

@app.route("/")
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(VULNERABLE_HTML, query=q)


if __name__ == "__main__":
    app.run(debug=True)
