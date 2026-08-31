"""
Fake HTTP admin login page - a second, independent honeypot service
alongside Cowrie (SSH/Telnet). Matches the persona already baited into
Cowrie's fake filesystem (honeypot/honeyfs-overlay/var/www/html/) - an
attacker who reads Cowrie's `admin/login.php` bait and then port-scans the
same IP finds a REAL page answering at that exact path, not a dead end.

Every request (any method, any path) is logged to the same MongoDB
`attacks` collection the SSH/Telnet side writes to - most of the internet's
scanner traffic never even tries a login, it just walks a fixed list of
common paths (/wp-login.php, /.env, /phpmyadmin, ...), and that alone is
worth capturing. A POST with recognizable username/password-shaped form
fields to any path is treated as a login attempt and always rejected -
this never authenticates anyone, it only watches.

Runs on its own internal port (default 8899), meant to be NAT'd from
public port 80 the same way deploy/expose_cowrie_port22.sh redirects 22 ->
2222 - see deploy/expose_webtrap_port80.sh.
"""

import os
import time
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from prometheus_client import start_http_server
from pymongo import MongoClient

import metrics
from severity import classify_severity

INTERNAL_PORT = int(os.getenv("HTTP_HONEYPOT_PORT", "8899"))
METRICS_PORT = int(os.getenv("HTTP_HONEYPOT_METRICS_PORT", "9108"))

# Paths that get the fake login page instead of a generic 404 - matches
# both the specific bait path already planted in Cowrie's fake filesystem
# and a few of the most commonly bot-scanned admin panel paths, so a
# generic scanner's fixed wordlist has something to "find" too.
LOGIN_PAGE_PATHS = {"admin/login.php", "admin", "admin/", "login", "wp-login.php"}


def _read_secret(env_name: str):
    """Reads a secret from <env_name>_FILE (a file path) if set - the
    Docker Compose `secrets:` convention (see docker-compose.yml) - else
    falls back to the plain env var, which is what the native venv
    workflow uses. Duplicated per-file rather than shared, same as the
    other `_read_secret()`s in this project (see CLAUDE.md)."""
    file_path = os.getenv(f"{env_name}_FILE")
    if file_path:
        with open(file_path) as f:
            return f.read().strip()
    return os.getenv(env_name)


def _mongo_auth_kwargs() -> dict:
    """Adds MongoDB username/password auth if MONGO_USERNAME is set - the
    native venv workflow (mongod with no --auth) never sets it, so this
    returns {} and pymongo connects exactly as before."""
    username = _read_secret("MONGO_USERNAME")
    if not username:
        return {}
    return {
        "username": username,
        "password": _read_secret("MONGO_PASSWORD"),
        "authSource": os.getenv("MONGO_AUTH_SOURCE", "admin"),
    }


client     = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), **_mongo_auth_kwargs())
db         = client[os.getenv("DB_NAME", "honeypot")]
collection = db["attacks"]


def get_geo(ip: str) -> dict:
    """Duplicated from notifier/realtime_alert.py's copy rather than
    shared - same reasoning as parser/log_watcher.py vs
    notifier/realtime_alert.py's own parse_event (see CLAUDE.md)."""
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return {"country": "Local", "country_code": "LO", "city": "localhost", "latitude": 0.0, "longitude": 0.0}
    try:
        import geoip2.database
        db_path = os.getenv(
            "GEOIP_DB_PATH",
            os.path.expanduser("~/Honeypot-Monitor/parser/geoip/GeoLite2-City.mmdb"),
        )
        with geoip2.database.Reader(db_path) as reader:
            r = reader.city(ip)
            return {
                "country":      r.country.name or "Unknown",
                "country_code": r.country.iso_code or "??",
                "city":         r.city.name or "Unknown",
                "latitude":     float(r.location.latitude or 0),
                "longitude":    float(r.location.longitude or 0),
            }
    except Exception:
        return {"country": "Unknown", "country_code": "??", "city": "Unknown", "latitude": 0.0, "longitude": 0.0}


LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>PaymentCo Admin Panel</title>
<style>
body{{font-family:Arial,sans-serif;background:#f1f1f1;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#fff;padding:40px;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.15);width:320px}}
h1{{font-size:18px;margin:0 0 20px;color:#333}}
input{{width:100%;padding:9px;margin-bottom:12px;box-sizing:border-box;border:1px solid #ccc;border-radius:3px}}
button{{width:100%;padding:10px;background:#2563eb;color:#fff;border:none;border-radius:3px;cursor:pointer}}
.error{{color:#c0392b;font-size:13px;margin-bottom:12px}}
</style></head>
<body><div class="box">
<h1>PaymentCo &mdash; Admin Login</h1>
{error}
<form method="POST">
<input type="text" name="username" placeholder="Username" autocomplete="username"/>
<input type="password" name="password" placeholder="Password" autocomplete="current-password"/>
<button type="submit">Sign in</button>
</form>
</div></body></html>"""

ROBOTS_TXT = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /api/\n"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _log_event(request: Request, event: str, username: str = None, password: str = None):
    ip = request.client.host if request.client else "unknown"
    geo = get_geo(ip)
    # Any credential submission gets the same T1110 (Brute Force) tag
    # SSH/Telnet login attempts use - it's the same ATT&CK technique
    # regardless of protocol - so it maps to the same severity too.
    mitre_techniques = ["T1110"] if event == "http.login.attempt" else []
    doc = {
        "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "src_ip":     ip,
        "src_port":   request.client.port if request.client else None,
        "dst_port":   80,
        "event":      event,
        "username":   username,
        "password":   password,
        "command":    None,
        "session":    None,
        "method":     request.method,
        "path":       "/" + str(request.url.path).lstrip("/"),
        "user_agent": request.headers.get("user-agent"),
        "mitre_techniques": mitre_techniques,
        "severity":   classify_severity(mitre_techniques),
        "sensor":     os.getenv("HTTP_HONEYPOT_SENSOR", "honeypot-01"),
        "country":    geo["country"],
        "country_code": geo["country_code"],
        "city":       geo["city"],
        "latitude":   geo["latitude"],
        "longitude":  geo["longitude"],
        "alerted":    False,
        "created_at": datetime.now(timezone.utc),
    }
    try:
        collection.insert_one(doc)
    except Exception:
        metrics.HTTP_HONEYPOT_INSERT_ERRORS.inc()
        return  # best-effort logging - never let a Mongo hiccup break the response
    metrics.HTTP_HONEYPOT_EVENTS_PROCESSED.labels(event).inc()
    metrics.HTTP_HONEYPOT_LAST_EVENT_TIMESTAMP.set(time.time())


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse(ROBOTS_TXT)


@app.get("/{full_path:path}")
async def catch_all_get(full_path: str, request: Request):
    _log_event(request, "http.request")
    if full_path.rstrip("/") in {p.rstrip("/") for p in LOGIN_PAGE_PATHS}:
        return HTMLResponse(LOGIN_PAGE_HTML.format(error=""))
    return PlainTextResponse("Not Found", status_code=404)


@app.post("/{full_path:path}")
async def catch_all_post(full_path: str, request: Request):
    form = await request.form()
    username = form.get("username") or form.get("user") or form.get("email")
    password = form.get("password") or form.get("pass") or form.get("passwd")

    if username or password:
        _log_event(
            request, "http.login.attempt",
            username=str(username) if username else None,
            password=str(password) if password else None,
        )
        return HTMLResponse(
            LOGIN_PAGE_HTML.format(error='<div class="error">Invalid username or password.</div>'),
            status_code=401,
        )

    _log_event(request, "http.request")
    return PlainTextResponse("Not Found", status_code=404)


if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    uvicorn.run(app, host="0.0.0.0", port=INTERNAL_PORT, log_level="warning")
