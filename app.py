import os
import sqlite3
import secrets
import hmac
import csv
import io
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, session, redirect,
    url_for, render_template_string,
    Response, abort
)
from werkzeug.middleware.proxy_fix import ProxyFix

# =====================================
# MGS TRACK ANALYTICS
# MG SHANKAR TECH
# =====================================

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-before-deployment"
)

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

# =====================================
# DATABASE
# =====================================

def connect_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def setup_db():
    con = connect_db()

    con.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            title TEXT,
            created TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT,
            ip TEXT,
            browser TEXT,
            device TEXT,
            language TEXT,
            consent_token TEXT,
            gps_lat TEXT DEFAULT '',
            gps_lon TEXT DEFAULT '',
            created TEXT
        )
    """)

    con.commit()
    con.close()


setup_db()

# =====================================
# BASIC SECURITY
# =====================================

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    saved = session.get("csrf", "")

    if not saved or not hmac.compare_digest(sent, saved):
        abort(400, "Invalid security token")


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def escape(value):
    from markupsafe import escape as e
    return e(value)


def browser_info(ua):
    ua = ua.lower()

    if "edg/" in ua:
        browser = "Edge"
    elif "chrome/" in ua:
        browser = "Chrome"
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
    else:
        device = "Unknown"

    return browser, device


# =====================================
# DESIGN
# =====================================

STYLE = """
<style>
*{box-sizing:border-box}
body{
    margin:0;
    background:#080e1d;
    color:white;
    font-family:Arial,sans-serif
}
.container{
    max-width:1100px;
    width:94%;
    margin:25px auto
}
.header{
    background:linear-gradient(120deg,#17386c,#142044);
    padding:25px;
    border-radius:18px;
    margin-bottom:20px
}
.card{
    background:#121e35;
    border:1px solid #293c60;
    padding:20px;
    border-radius:15px;
    margin-bottom:18px
}
input,button{
    width:100%;
    padding:13px;
    margin:7px 0;
    border-radius:9px;
    font-size:15px
}
input{
    background:#09152b;
    color:white;
    border:1px solid #354c72
}
button{
    background:#3478f6;
    color:white;
    border:0;
    font-weight:bold
}
a{color:#83b5ff;overflow-wrap:anywhere}
.small{color:#aebbd2;font-size:13px;line-height:1.6}
.stat{
    background:#0b1830;
    padding:15px;
    margin:10px 0;
    border-radius:10px
}
.tablewrap{overflow-x:auto}
table{
    width:100%;
    border-collapse:collapse;
    min-width:650px
}
td,th{
    padding:12px;
    border-bottom:1px solid #293b5b;
    text-align:left;
    font-size:13px
}
th{color:#8cb9ff}
.footer{text-align:center;color:#7889a7;padding:20px}
</style>
"""


def page(title, body):
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="hi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">
        <title>{{ title }}</title>
        """ + STYLE + """
    </head>
    <body>
        <div class="container">
            {{ body|safe }}
            <div class="footer">
                MGS Track Analytics | MG Shankar Tech
            </div>
        </div>
    </body>
    </html>
    """, title=title, body=body)


# =====================================
# HOME / LOGIN
# =====================================

@app.route("/")
def home():
    if session.get("admin"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        check_csrf()

        password = request.form.get("password", "")

        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            session.permanent = True
            csrf_token()
            return redirect(url_for("dashboard"))

        return page(
            "Login",
            "<div class='card'><h2>गलत पासवर्ड</h2>"
            "<a href='/login'>दोबारा प्रयास करें</a></div>"
        ), 401

    body = """
    <div class="header">
        <h1>MGS Track Analytics</h1>
        <p>Administrator Login</p>
    </div>

    <div class="card">
        <h2>Admin Login</h2>
        <form method="POST">
            <input type="hidden" name="csrf"
                   value="{{ token }}">
            <input type="password" name="password"
                   placeholder="Admin Password" required>
            <button>Login</button>
        </form>
    </div>
    """

    return page(
        "Admin Login",
        render_template_string(body, token=csrf_token())
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================
# DASHBOARD
# =====================================

@app.route("/dashboard")
@admin_required
def dashboard():

    con = connect_db()

    links = con.execute(
        "SELECT * FROM links ORDER BY id DESC"
    ).fetchall()

    visitors = con.execute(
        "SELECT * FROM visitors ORDER BY id DESC"
    ).fetchall()

    con.close()

    link_html = ""

    for link in links:
        public_url = url_for(
            "visitor",
            code=link["code"],
            _external=True
        )

        link_html += f"""
        <div class="stat">
            <b>{escape(link['title'])}</b>
            <p><a href="{escape(public_url)}">
                {escape(public_url)}
            </a></p>
            <button onclick="copyText('{escape(public_url)}')">
                Copy Link
            </button>
        </div>
        """

    visitor_html = ""

    for v in visitors:
        gps = "Not provided"

        if v["gps_lat"] and v["gps_lon"]:
            gps = (
                str(v["gps_lat"]) + ", " +
                str(v["gps_lon"])
            )

        visitor_html += f"""
        <tr>
            <td>{v['id']}</td>
            <td>{escape(v['code'])}</td>
            <td>{escape(v['ip'])}</td>
            <td>{escape(v['browser'])}</td>
            <td>{escape(v['device'])}</td>
            <td>{escape(gps)}</td>
            <td>{escape(v['created'])}</td>
        </tr>
        """

    body = f"""
    <div class="header">
        <h1>MGS Analytics Dashboard</h1>
        <p>MG Shankar Tech</p>
        <a href="/logout">Logout</a>
    </div>

    <div class="card">
        <h2>Create New Link</h2>

        <form method="POST" action="/create">
            <input type="hidden" name="csrf"
                   value="{csrf_token()}">
            <input name="title"
                   placeholder="Link Title" required>
            <button>Create Link</button>
        </form>
    </div>

    <div class="card">
        <h2>Generated Links ({len(links)})</h2>
        {link_html or '<p>No links created yet.</p>'}
    </div>

    <div class="card">
        <h2>Consented Visitor Records ({len(visitors)})</h2>

        <p><a href="/export">Download CSV</a></p>

        <div class="tablewrap">
        <table>
            <tr>
                <th>ID</th>
                <th>Link</th>
                <th>IP</th>
                <th>Browser</th>
                <th>Device</th>
                <th>GPS</th>
                <th>Time</th>
            </tr>
            {visitor_html}
        </table>
        </div>
    </div>

    <script>
    function copyText(text){
        navigator.clipboard.writeText(text)
        .then(()=>alert("Link copied!"))
        .catch(()=>alert("Copy failed. Long-press the link."));
    }
    </script>
    """

    return page("Dashboard", body)


# =====================================
# CREATE LINK
# =====================================

@app.route("/create", methods=["POST"])
@admin_required
def create_link():

    check_csrf()

    title = request.form.get("title", "").strip()[:100]

    if not title:
        return redirect(url_for("dashboard"))

    code = secrets.token_urlsafe(16)

    con = connect_db()

    con.execute("""
        INSERT INTO links(code,title,created)
        VALUES(?,?,?)
    """, (
        code,
        title,
        datetime.now().isoformat()
    ))

    con.commit()
    con.close()

    return redirect(url_for("dashboard"))


# =====================================
# VISITOR CONSENT PAGE
# =====================================

@app.route("/v/<code>", methods=["GET"])
def visitor(code):

    con = connect_db()

    link = con.execute(
        "SELECT * FROM links WHERE code=?",
        (code,)
    ).fetchone()

    con.close()

    if not link:
        abort(404)

    token = secrets.token_urlsafe(32)
    session["visitor_token"] = token
    session["visitor_code"] = code

    body = f"""
    <div class="header">
        <h1>Welcome</h1>
        <p>{escape(link['title'])}</p>
    </div>

    <div class="card">
        <h2>Privacy & Consent</h2>

        <p class="small">
            इस वेबसाइट के संचालक को आपकी सहमति के बाद
            आपका IP पता, ब्राउज़र, डिवाइस का प्रकार और
            भाषा जैसी तकनीकी जानकारी दी जाएगी।
        </p>

        <p class="small">
            GPS लोकेशन के लिए अलग से ब्राउज़र अनुमति
            माँगी जाएगी। GPS अनुमति देना वैकल्पिक है।
            आप सहमति न देने पर पेज बंद कर सकते हैं।
        </p>

        <form method="POST"
              action="/consent/{escape(code)}">

            <input type="hidden" name="csrf"
                   value="{csrf_token()}">

            <label>
                <input type="checkbox" required
                       style="width:auto">
                मैं जानकारी पढ़कर सहमति देता/देती हूँ।
            </label>

            <button type="submit">Agree & Continue</button>
        </form>
    </div>
    """

    return page("Privacy Consent", body)


# =====================================
# CONSENT ACCEPTED
# =====================================

@app.route("/consent/<code>", methods=["POST"])
def consent(code):

    check_csrf()

    if session.get("visitor_code") != code:
        abort(400)

    token = session.get("visitor_token")

    if not token:
        abort(400)

    con = connect_db()

    link = con.execute(
        "SELECT code FROM links WHERE code=?",
        (code,)
    ).fetchone()

    if not link:
        con.close()
        abort(404)

    ua = request.headers.get("User-Agent", "")[:500]
    browser, device = browser_info(ua)

    ip = request.remote_addr or "Unknown"
    language = request.headers.get(
        "Accept-Language", ""
    )[:100]

    con.execute("""
        INSERT INTO visitors(
            code,ip,browser,device,language,
            consent_token,created
        )
        VALUES(?,?,?,?,?,?,?)
    """, (
        code,
        ip,
        browser,
        device,
        language,
        token,
        datetime.now().isoformat()
    ))

    con.commit()
    con.close()

    session["gps_allowed"] = True

    body = """
    <div class="header">
        <h1>Thank You!</h1>
        <p>आपकी सहमति दर्ज हो गई है।</p>
    </div>

    <div class="card">
        <h2>Optional GPS Permission</h2>

        <p class="small">
            यदि आप चाहें तो नीचे बटन दबाकर
            अपने ब्राउज़र में GPS अनुमति दे सकते हैं।
        </p>

        <button onclick="getGPS()">Allow GPS</button>
        <p id="status" class="small"></p>
    </div>

    <script>
    async function getGPS(){

        const status = document.getElementById("status");

        if(!navigator.geolocation){
            status.innerText = "GPS उपलब्ध नहीं है।";
            return;
        }

        status.innerText = "Permission का इंतजार है...";

        navigator.geolocation.getCurrentPosition(
            async function(pos){

                const data = {
                    latitude: pos.coords.latitude,
                    longitude: pos.coords.longitude
                };

                const response = await fetch("/gps",{
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify(data)
                });

                status.innerText = response.ok
                    ? "GPS अनुमति के साथ स्थान अपडेट हो गया।"
                    : "स्थान अपडेट नहीं हो सका।";
            },

            function(){
                status.innerText =
                    "GPS अनुमति नहीं मिली या उपलब्ध नहीं है।";
            }
        );
    }
    </script>
    """

    return page("Thank You", body)


# =====================================
# GPS UPDATE
# =====================================

@app.route("/gps", methods=["POST"])
def gps():

    if not session.get("gps_allowed"):
        abort(403)

    token = session.get("visitor_token")

    if not token:
        abort(403)

    data = request.get_json(silent=True) or {}

    lat = str(data.get("latitude", ""))[:40]
    lon = str(data.get("longitude", ""))[:40]

    try:
        latitude = float(lat)
        longitude = float(lon)

        if not (-90 <= latitude <= 90):
            abort(400)

        if not (-180 <= longitude <= 180):
            abort(400)

    except (ValueError, TypeError):
        abort(400)

    con = connect_db()

    result = con.execute("""
        UPDATE visitors
        SET gps_lat=?, gps_lon=?
        WHERE consent_token=?
    """, (
        lat,
        lon,
        token
    ))

    con.commit()
    updated = result.rowcount
    con.close()

    if updated != 1:
        abort(403)

    return {"success": True}


# =====================================
# CSV EXPORT
# =====================================

@app.route("/export")
@admin_required
def export():

    con = connect_db()

    rows = con.execute("""
        SELECT id,code,ip,browser,device,
               language,gps_lat,gps_lon,created
        FROM visitors ORDER BY id DESC
    """).fetchall()

    con.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Link Code", "IP",
        "Browser", "Device", "Language",
        "GPS Latitude", "GPS Longitude", "Time"
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


# =====================================
# HEALTH CHECK
# =====================================

@app.route("/health")
def health():
    return {"status": "running"}


# =====================================
# START
# =====================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
