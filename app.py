import os
import io
import csv
import hmac
import secrets
import sqlite3

from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, session, redirect,
    url_for, render_template_string,
    Response, abort, jsonify
)

from werkzeug.middleware.proxy_fix import ProxyFix


# ==================================================
# MGS TRACK ANALYTICS
# MG SHANKAR TECH
# ==================================================

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable missing.")

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "VINAY PRATAP"
)

DATA_DIR = os.environ.get("DATA_DIR", ".")

os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "mgs_tracker.db")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=3600
)


# ==================================================
# DATABASE
# ==================================================

def get_db():

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    return con


def setup_database():

    con = get_db()

    con.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            created TEXT NOT NULL
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            ip TEXT,
            browser TEXT,
            device TEXT,
            language TEXT,
            consent_time TEXT,
            gps_lat TEXT DEFAULT '',
            gps_lon TEXT DEFAULT ''
        )
    """)

    con.commit()
    con.close()


setup_database()


# ==================================================
# SECURITY
# ==================================================

def get_csrf():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


def verify_csrf():

    submitted = request.form.get(
        "csrf_token",
        request.headers.get("X-CSRF-Token", "")
    )

    saved = session.get("csrf_token", "")

    if not saved or not hmac.compare_digest(submitted, saved):
        abort(400, "Security token invalid")


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def clean(value):

    return str(value or "").strip()[:500]


# ==================================================
# DEVICE INFORMATION
# ==================================================

def get_device_info(user_agent):

    ua = user_agent.lower()

    if "edg/" in ua:
        browser = "Microsoft Edge"

    elif "chrome/" in ua:
        browser = "Google Chrome"

    elif "firefox/" in ua:
        browser = "Firefox"

    elif "safari/" in ua:
        browser = "Safari"

    else:
        browser = "Unknown"

    if "android" in ua:
        device = "Android"

    elif "iphone" in ua:
        device = "iPhone"

    elif "ipad" in ua:
        device = "iPad"

    elif "windows" in ua:
        device = "Windows"

    elif "macintosh" in ua:
        device = "Mac"

    elif "linux" in ua:
        device = "Linux"

    else:
        device = "Unknown"

    return browser, device


# ==================================================
# HTML DESIGN
# ==================================================

STYLE = """
<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #080e1d;
    color: white;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1100px;
    width: 94%;
    margin: 25px auto;
}

.header {
    background: linear-gradient(120deg,#17386c,#142044);
    padding: 25px;
    border-radius: 18px;
    margin-bottom: 20px;
}

.card {
    background: #121e35;
    border: 1px solid #293c60;
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 18px;
}

input {
    width: 100%;
    padding: 14px;
    margin: 8px 0;
    border-radius: 9px;
    border: 1px solid #354c72;
    background: #09152b;
    color: white;
    font-size: 16px;
}

button {
    width: 100%;
    padding: 14px;
    margin: 8px 0;
    border-radius: 9px;
    background: #3478f6;
    color: white;
    border: none;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
}

a {
    color: #83b5ff;
    overflow-wrap: anywhere;
}

.small {
    color: #aebbd2;
    font-size: 13px;
    line-height: 1.7;
}

.stat {
    background: #0b1830;
    padding: 15px;
    margin: 10px 0;
    border-radius: 10px;
}

.tablewrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 700px;
}

td, th {
    padding: 12px;
    border-bottom: 1px solid #293b5b;
    text-align: left;
    font-size: 13px;
}

th {
    color: #8cb9ff;
}

.footer {
    text-align: center;
    color: #7889a7;
    padding: 20px;
}

</style>
"""


def render_page(title, template, **data):

    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="hi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">

            <title>{{ title }}</title>

            """ + STYLE + """

        </head>

        <body>

            <div class="container">

                """ + template + """

                <div class="footer">
                    MGS Track Analytics | MG Shankar Tech
                </div>

            </div>

        </body>
        </html>
        """,
        title=title,
        **data
    )


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if session.get("admin"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        verify_csrf()

        password = request.form.get("password", "")

        if hmac.compare_digest(password, ADMIN_PASSWORD):

            session.clear()

            session["admin"] = True
            session.permanent = True

            get_csrf()

            return redirect(url_for("dashboard"))

        return render_page(
            "Login Failed",
            """
            <div class="card">
                <h2>गलत पासवर्ड</h2>
                <a href="/login">दोबारा प्रयास करें</a>
            </div>
            """
        ), 401

    return render_page(
        "Admin Login",
        """
        <div class="header">
            <h1>MGS Track Analytics</h1>
            <p>Administrator Login</p>
        </div>

        <div class="card">

            <h2>Admin Login</h2>

            <form method="POST">

                <input type="hidden"
                       name="csrf_token"
                       value="{{ csrf }}">

                <input type="password"
                       name="password"
                       placeholder="Admin Password"
                       required>

                <button type="submit">
                    Login
                </button>

            </form>

        </div>
        """,
        csrf=get_csrf()
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
@admin_required
def dashboard():

    con = get_db()

    links = con.execute(
        "SELECT * FROM links ORDER BY id DESC"
    ).fetchall()

    visitors = con.execute(
        "SELECT * FROM visitors ORDER BY id DESC"
    ).fetchall()

    con.close()

    return render_page(
        "MGS Dashboard",
        """
        <div class="header">

            <h1>MGS Track Analytics</h1>

            <p>MG Shankar Tech</p>

            <a href="/logout">Logout</a>

        </div>


        <div class="card">

            <h2>Create New Link</h2>

            <form method="POST" action="/create">

                <input type="hidden"
                       name="csrf_token"
                       value="{{ csrf }}">

                <input name="title"
                       placeholder="Enter Link Title"
                       maxlength="100"
                       required>

                <button type="submit">
                    Create Link
                </button>

            </form>

        </div>


        <div class="card">

            <h2>Generated Links ({{ links|length }})</h2>

            {% for link in links %}

                <div class="stat">

                    <b>{{ link["title"] }}</b>

                    <p>
                        <a href="{{ url_for(
                            'visitor',
                            code=link['code'],
                            _external=True
                        ) }}">
                            {{ url_for(
                                'visitor',
                                code=link['code'],
                                _external=True
                            ) }}
                        </a>
                    </p>

                    <button type="button"
                            class="copy-button"
                            data-link="{{ url_for(
                                'visitor',
                                code=link['code'],
                                _external=True
                            ) }}">
                        Copy Link
                    </button>

                </div>

            {% else %}

                <p class="small">अभी कोई लिंक नहीं बनी है।</p>

            {% endfor %}

        </div>


        <div class="card">

            <h2>
                Visitor Records ({{ visitors|length }})
            </h2>

            <p>
                <a href="/export">Download CSV</a>
            </p>

            <div class="tablewrap">

                <table>

                    <tr>
                        <th>ID</th>
                        <th>Link Code</th>
                        <th>IP</th>
                        <th>Browser</th>
                        <th>Device</th>
                        <th>GPS</th>
                        <th>Time</th>
                    </tr>

                    {% for v in visitors %}

                    <tr>

                        <td>{{ v["id"] }}</td>
                        <td>{{ v["code"] }}</td>
                        <td>{{ v["ip"] }}</td>
                        <td>{{ v["browser"] }}</td>
                        <td>{{ v["device"] }}</td>

                        <td>
                            {% if v["gps_lat"] and v["gps_lon"] %}
                                {{ v["gps_lat"] }}, {{ v["gps_lon"] }}
                            {% else %}
                                Not provided
                            {% endif %}
                        </td>

                        <td>{{ v["consent_time"] }}</td>

                    </tr>

                    {% endfor %}

                </table>

            </div>

        </div>


        <script>

        document.querySelectorAll(".copy-button").forEach(
            function(button) {

                button.addEventListener("click", function() {

                    const link = this.dataset.link;

                    if (navigator.clipboard) {

                        navigator.clipboard.writeText(link)
                        .then(function() {
                            alert("Link copied successfully!");
                        })
                        .catch(function() {
                            prompt("Copy this link:", link);
                        });

                    } else {

                        prompt("Copy this link:", link);

                    }

                });

            }
        );

        </script>
        """,
        links=links,
        visitors=visitors,
        csrf=get_csrf()
    )


# ==================================================
# CREATE LINK
# ==================================================

@app.route("/create", methods=["POST"])
@admin_required
def create_link():

    verify_csrf()

    title = clean(request.form.get("title", ""))[:100]

    if not title:
        abort(400)

    code = secrets.token_urlsafe(18)

    con = get_db()

    con.execute(
        """
        INSERT INTO links(code,title,created)
        VALUES(?,?,?)
        """,
        (
            code,
            title,
            datetime.now().isoformat()
        )
    )

    con.commit()
    con.close()

    return redirect(url_for("dashboard"))


# ==================================================
# VISITOR PAGE
# ==================================================

@app.route("/v/<code>")
def visitor(code):

    con = get_db()

    link = con.execute(
        "SELECT * FROM links WHERE code=?",
        (code,)
    ).fetchone()

    con.close()

    if not link:
        abort(404)

    session["visitor_code"] = code
    session["visitor_nonce"] = secrets.token_urlsafe(32)

    return render_page(
        "Visitor Consent",
        """
        <div class="header">

            <h1>Welcome</h1>

            <p>{{ title }}</p>

        </div>


        <div class="card">

            <h2>Privacy & Consent</h2>

            <p class="small">

                इस लिंक के संचालक को आपकी सहमति के बाद
                आपका IP पता, ब्राउज़र, डिवाइस का प्रकार
                और भाषा जैसी तकनीकी जानकारी सेव की जाएगी।

            </p>

            <p class="small">

                GPS लोकेशन के लिए अलग से ब्राउज़र अनुमति
                माँगी जाएगी। GPS अनुमति देना वैकल्पिक है।

            </p>

            <form method="POST"
                  action="{{ url_for('consent', code=code) }}">

                <input type="hidden"
                       name="csrf_token"
                       value="{{ csrf }}">

                <label>

                    <input type="checkbox"
                           name="agree"
                           value="yes"
                           required
                           style="width:auto">

                    मैं जानकारी पढ़कर सहमति देता/देती हूँ।

                </label>

                <button type="submit">
                    Agree & Continue
                </button>

            </form>

        </div>
        """,
        title=link["title"],
        code=code,
        csrf=get_csrf()
    )


# ==================================================
# CONSENT
# ==================================================

@app.route("/consent/<code>", methods=["POST"])
def consent(code):

    verify_csrf()

    if request.form.get("agree") != "yes":
        abort(400)

    if session.get("visitor_code") != code:
        abort(400)

    nonce = session.get("visitor_nonce")

    if not nonce:
        abort(400)

    con = get_db()

    link = con.execute(
        "SELECT code FROM links WHERE code=?",
        (code,)
    ).fetchone()

    if not link:
        con.close()
        abort(404)

    user_agent = request.headers.get(
        "User-Agent", ""
    )[:500]

    browser, device = get_device_info(user_agent)

    ip = request.remote_addr or "Unknown"

    language = request.headers.get(
        "Accept-Language", ""
    )[:100]

    cur = con.execute(
        """
        INSERT INTO visitors(
            code,ip,browser,device,language,consent_time
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            code,
            ip,
            browser,
            device,
            language,
            datetime.now().isoformat()
        )
    )

    visitor_id = cur.lastrowid

    con.commit()
    con.close()

    session["gps_visitor_id"] = visitor_id
    session["gps_nonce"] = nonce
    session["gps_allowed"] = True

    return render_page(
        "Thank You",
        """
        <div class="header">

            <h1>Thank You!</h1>

            <p>आपकी सहमति दर्ज हो गई है।</p>

        </div>


        <div class="card">

            <h2>Optional GPS Permission</h2>

            <p class="small">

                GPS लोकेशन साझा करना वैकल्पिक है।
                नीचे बटन दबाने पर ब्राउज़र अलग से अनुमति माँगेगा।

            </p>

            <button type="button" id="gpsButton">
                Allow GPS Location
            </button>

            <p id="status" class="small" aria-live="polite"></p>

        </div>


        <script>

        const button = document.getElementById("gpsButton");
        const status = document.getElementById("status");

        button.addEventListener("click", function() {

            if (!navigator.geolocation) {

                status.textContent = "GPS उपलब्ध नहीं है।";
                return;

            }

            status.textContent = "ब्राउज़र अनुमति की प्रतीक्षा है...";

            navigator.geolocation.getCurrentPosition(

                async function(position) {

                    const data = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude
                    };

                    try {

                        const response = await fetch("/gps", {

                            method: "POST",

                            headers: {
                                "Content-Type": "application/json",
                                "X-CSRF-Token": "{{ csrf }}"
                            },

                            body: JSON.stringify(data)

                        });

                        if (response.ok) {

                            status.textContent =
                                "GPS स्थान अपडेट हो गया।";

                        } else {

                            status.textContent =
                                "GPS अपडेट नहीं हो सका।";

                        }

                    } catch (error) {

                        status.textContent =
                            "नेटवर्क समस्या हुई।";

                    }

                },

                function(error) {

                    status.textContent =
                        "GPS अनुमति नहीं मिली या उपलब्ध नहीं है।";

                },

                {
                    enableHighAccuracy: true,
                    timeout: 15000,
                    maximumAge: 0
                }

            );

        });

        </script>
        """,
        csrf=get_csrf()
    )


# ==================================================
# GPS UPDATE
# ==================================================

@app.route("/gps", methods=["POST"])
def gps():

    if not session.get("gps_allowed"):
        abort(403)

    visitor_id = session.get("gps_visitor_id")
    nonce = session.get("gps_nonce")

    if not visitor_id or not nonce:
        abort(403)

    submitted = request.headers.get("X-CSRF-Token", "")
    saved = session.get("csrf_token", "")

    if not saved or not hmac.compare_digest(submitted, saved):
        abort(403)

    data = request.get_json(silent=True) or {}

    try:

        latitude = float(data.get("latitude"))
        longitude = float(data.get("longitude"))

        if not -90 <= latitude <= 90:
            abort(400)

        if not -180 <= longitude <= 180:
            abort(400)

    except (ValueError, TypeError):
        abort(400)

    con = get_db()

    result = con.execute(
        """
        UPDATE visitors
        SET gps_lat=?, gps_lon=?
        WHERE id=?
        """,
        (
            str(latitude),
            str(longitude),
            visitor_id
        )
    )

    con.commit()
    updated = result.rowcount
    con.close()

    if updated != 1:
        abort(403)

    return jsonify({"success": True})


# ==================================================
# CSV EXPORT
# ==================================================

@app.route("/export")
@admin_required
def export():

    con = get_db()

    rows = con.execute(
        """
        SELECT id,code,ip,browser,device,
               language,gps_lat,gps_lon,consent_time
        FROM visitors
        ORDER BY id DESC
        """
    ).fetchall()

    con.close()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Link Code",
        "IP",
        "Browser",
        "Device",
        "Language",
        "GPS Latitude",
        "GPS Longitude",
        "Consent Time"
    ])

    for row in rows:

        writer.writerow(list(row))

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=mgs_visitors.csv"
        }
    )


# ==================================================
# HEALTH CHECK
# ==================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "running",
        "application": "MGS Track Analytics"
    })


# ==================================================
# ERROR PAGES
# ==================================================

@app.errorhandler(404)
def not_found(error):

    return render_page(
        "404",
        """
        <div class="card">
            <h2>404 - Link नहीं मिला</h2>
            <p>यह लिंक मौजूद नहीं है या हटाया जा चुका है।</p>
        </div>
        """
    ), 404


@app.errorhandler(400)
def bad_request(error):

    return render_page(
        "Request Error",
        """
        <div class="card">
            <h2>Request Error</h2>
            <p>अनुरोध सही नहीं है। पेज दोबारा खोलें।</p>
        </div>
        """
    ), 400


# ==================================================
# LOCAL START
# ==================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
