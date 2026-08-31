import os
import re
import struct
import time
from datetime import datetime

from fastapi import APIRouter, Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector
from pymongo import MongoClient
from typing import Optional
import io, csv

import auth
import metrics
from log_setup import get_logger
from mitre_mapping import TECHNIQUES as MITRE_TECHNIQUE_NAMES

logger = get_logger(__name__)

app = FastAPI(
    title="Honeypot API - Version 2 (Pro)",
    description="Hệ thống phân tích và thống kê log tấn công từ Cowrie",
    version="2.0.0"
)

# Every /api/* route below is registered on this router instead of directly
# on `app` so auth.check_api_rate_limit runs once per request for all of
# them (a generic per-IP cap, on top of whatever per-route auth dependency
# it also has) without repeating `Depends(...)` on every single endpoint -
# a new /api/* endpoint added later gets rate-limited automatically.
api_router = APIRouter(prefix="/api", dependencies=[Depends(auth.check_api_rate_limit)])

# Dashboard is a separate static origin (live-server on :8080). Cookies are
# httpOnly, so the browser must be told the API trusts that exact origin
# with credentials - `allow_origins=["*"]` cannot be combined with
# `allow_credentials=True` (browsers reject the combination outright).
DASHBOARD_ORIGIN = os.getenv("DASHBOARD_ORIGIN", "http://localhost:8080")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[DASHBOARD_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "honeypot")
# auth.py already defines _mongo_auth_kwargs() (and this file already does
# `import auth`) - reused here rather than duplicated, since these two
# files are already tightly coupled siblings within parser/, unlike the
# parser/notifier boundary where duplication is deliberate (sys.path
# collision risk, see CLAUDE.md).
client     = MongoClient(MONGO_URL, **auth._mongo_auth_kwargs())
db         = client[DB_NAME]
collection = db["attacks"]

collection.create_index([("timestamp", -1)])
collection.create_index([("src_ip", 1)])

logger.info(
    "API starting up, connected to database %s",
    DB_NAME,
)  # deliberately not logging MONGO_URL - it may embed credentials (mongodb://user:pass@host)

COOKIE_KWARGS = {"httponly": True, "samesite": "lax", "secure": False, "path": "/"}

# Cowrie renames a TTY log to its sha256 content hash on close (see
# cowrie/core/ttylog.py's ttylog_inputhash()) and that's the only form
# parser.py/log_watcher.py ever store in the "ttylog" field - anything else
# in that field would mean a corrupted/tampered DB row, and letting it
# through to os.path.join() below would be a path-traversal read of
# arbitrary files inside the container.
_TTYLOG_HASH_RE = re.compile(r"^[0-9a-f]{16,64}$")

# A pathological/hostile session (e.g. `cat` on a huge file, or a flood
# script) can make a TTY log arbitrarily large - this caps how much of it
# a single replay request will parse and return, so one such session can't
# turn a replay request into a multi-hundred-MB JSON response.
_TTYLOG_MAX_BYTES = 2 * 1024 * 1024

# Struct layout Cowrie's own ttylog writer uses (cowrie/core/ttylog.py):
# (op, tty[unused], length, direction, sec, usec).
_TTYLOG_STRUCT = "<iLiiLL"
_TTYLOG_OP_WRITE, _TTYLOG_OP_CLOSE = 3, 2
_TTYLOG_TYPE_OUTPUT, _TTYLOG_TYPE_INTERACT = 2, 3


def _ttylog_to_frames(raw: bytes) -> tuple[list[dict], float, bool]:
    """Ports the direction-selection logic from Cowrie's own
    scripts/asciinema.py and scripts/playlog.py (the tools Cowrie ships to
    replay these binary logs) rather than re-deriving it: the first
    OP_WRITE direction seen (other than TYPE_INTERACT, which is exec-mode
    command echo and always shown) is treated as "the output stream" a
    viewer would want replayed - a raw ttylog also contains the attacker's
    own keystrokes (TYPE_INPUT), which would otherwise double up with the
    shell's echo of them.

    Returns (frames, duration_seconds, truncated) where each frame is
    {"t": seconds-since-first-frame, "data": str}.
    """
    ssize = struct.calcsize(_TTYLOG_STRUCT)
    offset = 0
    currtty = None
    prefdir = 0
    start_time: float | None = None
    frames: list[dict] = []
    total_bytes = 0
    truncated = False

    while offset + ssize <= len(raw):
        op, tty, length, direction, sec, usec = struct.unpack(
            _TTYLOG_STRUCT, raw[offset : offset + ssize]
        )
        offset += ssize
        data = raw[offset : offset + length]
        offset += length

        if currtty is None:
            currtty = tty
        if tty != currtty:
            continue

        if op == _TTYLOG_OP_CLOSE:
            break
        if op != _TTYLOG_OP_WRITE:
            continue

        if prefdir == 0 and direction != _TTYLOG_TYPE_INTERACT:
            prefdir = direction
        if direction != prefdir and direction != _TTYLOG_TYPE_INTERACT:
            continue

        total_bytes += length
        if total_bytes > _TTYLOG_MAX_BYTES:
            truncated = True
            break

        t = sec + usec / 1_000_000
        if start_time is None:
            start_time = t
        # errors="replace": attacker-controlled bytes can be arbitrary
        # binary/invalid UTF-8, and a multi-byte sequence can legitimately
        # straddle two separate ttylog writes - this trades perfect
        # fidelity on those rare boundary bytes for never raising here.
        frames.append({"t": round(t - start_time, 3), "data": data.decode("utf-8", errors="replace")})

    duration = frames[-1]["t"] if frames else 0.0
    return frames, duration, truncated


# --- Prometheus metrics -----------------------------------------------------
# Hand-rolled rather than using prometheus-fastapi-instrumentator: that
# library's current release requires a newer starlette than the version
# fastapi==0.115.0 (pinned above) needs, and pulling it in broke that pin -
# a plain ASGI middleware + prometheus_client is little enough code that
# it's not worth the dependency conflict.
@app.middleware("http")
async def _prometheus_metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start
    # request.url.path is safe to use as a label as-is (not a template like
    # "/api/search/{id}") - every route in this API takes query params, not
    # path params, so there's no per-ID cardinality explosion risk here.
    path = request.url.path
    metrics.HTTP_REQUESTS.labels(request.method, path, response.status_code).inc()
    metrics.HTTP_REQUEST_DURATION_SECONDS.labels(request.method, path).observe(duration)
    return response


class _MongoStatsCollector(Collector):
    """Queries MongoDB live on every Prometheus scrape rather than caching
    a value - scrapes are infrequent (Prometheus' default is every 15s) and
    these are simple indexed count_documents() calls, cheap enough to run
    on demand instead of adding a background refresh loop."""

    def collect(self):
        total = GaugeMetricFamily(
            "honeypot_attacks_total", "Total attack documents in MongoDB"
        )
        total.add_metric([], collection.count_documents({}))
        yield total

        by_event = GaugeMetricFamily(
            "honeypot_attacks_by_event_total",
            "Attack documents by Cowrie event type",
            labels=["event"],
        )
        for event in ("cowrie.login.failed", "cowrie.login.success", "cowrie.command.input"):
            by_event.add_metric([event], collection.count_documents({"event": event}))
        yield by_event

        pending = GaugeMetricFamily(
            "honeypot_pending_alerts",
            "Attack documents not yet marked alerted=True (queue depth for /api/alerts/pending)",
        )
        pending.add_metric([], collection.count_documents({"alerted": False}))
        yield pending


metrics.register_mongo_stats_collector(_MongoStatsCollector())


@app.get("/metrics", include_in_schema=False)
def metrics_endpoint():
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


class LoginRequest(BaseModel):
    username: str
    password: str


class TotpCodeRequest(BaseModel):
    code: str


class DisableTotpRequest(BaseModel):
    password: str


def _issue_session(response: Response, username: str) -> dict:
    """Shared by the direct-login path (2FA disabled) and POST
    /auth/2fa/verify (2FA enabled, code just checked out) - both end the
    same way: real access/refresh/csrf cookies, and any leftover
    pending_2fa_token cookie cleared."""
    role = auth.get_user_role(username)
    access_token = auth.create_access_token(username, role)
    refresh_token = auth.create_refresh_token(username)
    csrf_token = auth.new_csrf_token()

    response.set_cookie(
        "access_token", access_token,
        max_age=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60, **COOKIE_KWARGS,
    )
    response.set_cookie(
        "refresh_token", refresh_token,
        max_age=auth.REFRESH_TOKEN_EXPIRE_DAYS * 86400, **COOKIE_KWARGS,
    )
    # Not httpOnly - the frontend JS must be able to read this one and echo
    # it back as a header for the double-submit CSRF check to work.
    response.set_cookie(
        "csrf_token", csrf_token,
        max_age=auth.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        httponly=False, samesite="lax", secure=False, path="/",
    )
    response.delete_cookie("pending_2fa_token", path="/")
    return {"status": "ok", "username": username, "role": role, "csrf_token": csrf_token}


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    ip = auth.client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    auth.check_rate_limit(ip, payload.username)

    if not auth.authenticate_user(payload.username, payload.password):
        auth.record_failed_attempt(ip, payload.username)
        auth.log_auth_event(ip, payload.username, success=False, user_agent=user_agent)
        metrics.LOGIN_ATTEMPTS.labels("failed").inc()
        logger.warning(
            "Failed login attempt for user '%s'", payload.username,
            extra={"ip": ip, "username": payload.username, "endpoint": "/auth/login"},
        )
        # Deliberately generic - never say which of username/password was wrong.
        raise HTTPException(status_code=401, detail="Sai thông tin đăng nhập")

    auth.reset_attempts(ip, payload.username)

    user_doc = auth.users_col.find_one({"username": payload.username})
    if user_doc and user_doc.get("totp_enabled"):
        # Password correct, but the login isn't complete until POST
        # /auth/2fa/verify also succeeds - no real session cookies yet, and
        # no auth_log/audit entry until then either (a password-only login
        # isn't actually "in").
        pending_token = auth.create_pending_2fa_token(payload.username)
        response.set_cookie(
            "pending_2fa_token", pending_token,
            max_age=auth.PENDING_2FA_TOKEN_EXPIRE_MINUTES * 60, **COOKIE_KWARGS,
        )
        logger.info(
            "Password OK, 2FA code required for user '%s'", payload.username,
            extra={"ip": ip, "username": payload.username, "endpoint": "/auth/login"},
        )
        return {"status": "2fa_required"}

    auth.log_auth_event(ip, payload.username, success=True, user_agent=user_agent)
    metrics.LOGIN_ATTEMPTS.labels("success").inc()
    logger.info(
        "Successful login for user '%s'", payload.username,
        extra={"ip": ip, "username": payload.username, "endpoint": "/auth/login"},
    )
    return _issue_session(response, payload.username)


@app.post("/auth/2fa/verify")
def verify_2fa(
    payload: TotpCodeRequest,
    request: Request,
    response: Response,
    pending_payload: dict = Depends(auth.get_pending_2fa_payload),
):
    username = pending_payload["sub"]
    ip = auth.client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    user_doc = auth.users_col.find_one({"username": username})
    secret = user_doc.get("totp_secret") if user_doc else None

    if not auth.verify_totp_code(secret, payload.code):
        logger.warning(
            "Failed 2FA code for user '%s'", username,
            extra={"ip": ip, "username": username, "endpoint": "/auth/2fa/verify"},
        )
        raise HTTPException(status_code=401, detail="Mã xác thực không đúng")

    auth.log_auth_event(ip, username, success=True, user_agent=user_agent)
    metrics.LOGIN_ATTEMPTS.labels("success").inc()
    logger.info(
        "2FA verified, login complete for user '%s'", username,
        extra={"ip": ip, "username": username, "endpoint": "/auth/2fa/verify"},
    )
    return _issue_session(response, username)


@app.post("/auth/2fa/setup")
def setup_2fa(user: str = Depends(auth.get_current_user), _csrf: None = Depends(auth.verify_csrf)):
    """Generates a fresh TOTP secret and stores it as NOT-yet-enabled -
    POST /auth/2fa/confirm with a valid current code is what actually
    turns 2FA on, so a secret that was generated but never confirmed
    (e.g. the user closed the tab) can't silently lock them out."""
    secret = auth.generate_totp_secret()
    auth.users_col.update_one(
        {"username": user}, {"$set": {"totp_secret": secret, "totp_enabled": False}}
    )
    return {"secret": secret, "otpauth_uri": auth.get_totp_uri(user, secret)}


@app.post("/auth/2fa/confirm")
def confirm_2fa(
    payload: TotpCodeRequest,
    user: str = Depends(auth.get_current_user),
    _csrf: None = Depends(auth.verify_csrf),
):
    user_doc = auth.users_col.find_one({"username": user})
    secret = user_doc.get("totp_secret") if user_doc else None
    if not auth.verify_totp_code(secret, payload.code):
        raise HTTPException(status_code=401, detail="Mã xác thực không đúng")
    auth.users_col.update_one({"username": user}, {"$set": {"totp_enabled": True}})
    return {"status": "ok", "totp_enabled": True}


@app.post("/auth/2fa/disable")
def disable_2fa(
    payload: DisableTotpRequest,
    user: str = Depends(auth.get_current_user),
    _csrf: None = Depends(auth.verify_csrf),
):
    """Requires the current password again (not just an active session) -
    an attacker who stole a logged-in browser's cookies but not the
    password shouldn't be able to turn off the second factor."""
    if not auth.authenticate_user(user, payload.password):
        raise HTTPException(status_code=401, detail="Sai mật khẩu")
    auth.users_col.update_one(
        {"username": user}, {"$unset": {"totp_secret": "", "totp_enabled": ""}}
    )
    return {"status": "ok", "totp_enabled": False}


@app.get("/auth/2fa/status")
def get_2fa_status(user: str = Depends(auth.get_current_user)):
    user_doc = auth.users_col.find_one({"username": user})
    return {"totp_enabled": bool(user_doc and user_doc.get("totp_enabled"))}


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: str = Depends(auth.get_current_user),
    _csrf: None = Depends(auth.verify_csrf),
):
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        auth.revoke_refresh_token(refresh_token)
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    response.delete_cookie("csrf_token", path="/")
    return {"status": "ok"}


@app.post("/auth/refresh")
def refresh(
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None),
    _csrf: None = Depends(auth.verify_csrf),
):
    if not refresh_token:
        logger.warning("Refresh attempted with no refresh_token cookie", extra={"endpoint": "/auth/refresh"})
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc phiên đã hết hạn")

    payload = auth.decode_token(refresh_token, expected_type="refresh")
    # Must still be present in the allowlist - deleted rows (logout, or a
    # prior refresh's rotation) mean this token has been revoked.
    if not auth.refresh_tokens_col.find_one({"jti": payload["jti"]}):
        logger.warning(
            "Rejected reuse of a revoked/rotated refresh token for user '%s'", payload["sub"],
            extra={"username": payload["sub"], "endpoint": "/auth/refresh"},
        )
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc phiên đã hết hạn")

    new_refresh_token = auth.rotate_refresh_token(payload["jti"], payload["sub"])
    new_access_token = auth.create_access_token(payload["sub"], auth.get_user_role(payload["sub"]))

    response.set_cookie(
        "access_token", new_access_token,
        max_age=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60, **COOKIE_KWARGS,
    )
    response.set_cookie(
        "refresh_token", new_refresh_token,
        max_age=auth.REFRESH_TOKEN_EXPIRE_DAYS * 86400, **COOKIE_KWARGS,
    )
    return {"status": "ok"}


@app.get("/auth/me")
def me(user: str = Depends(auth.get_current_user)):
    return {"username": user, "role": auth.get_user_role(user)}


@app.get("/")
def root():
    return {"message": "Honeypot API V2 đang chạy!", "status": "ok"}

@api_router.get("/stats")
def get_stats(user: str = Depends(auth.get_current_user)):
    return {
        "total":      collection.count_documents({}),
        "failed":     collection.count_documents({"event": "cowrie.login.failed"}),
        "success":    collection.count_documents({"event": "cowrie.login.success"}),
        "commands":   collection.count_documents({"event": "cowrie.command.input"}),
        "unique_ips": len(collection.distinct("src_ip")),
    }

@api_router.get("/attacks")
def get_attacks(
    limit: int = 50,
    start_date: Optional[str] = Query(None),
    end_date:   Optional[str] = Query(None),
    user: str = Depends(auth.get_current_user),
):
    query = {}
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = f"{start_date}T00:00:00"
        if end_date:
            query["timestamp"]["$lte"] = f"{end_date}T23:59:59"
    # Sorted by created_at (a real BSON Date set server-side at insert time),
    # not the `timestamp` string field - `timestamp` comes straight from
    # Cowrie's own log line and sorts lexicographically, which silently
    # breaks "most recent first" if Cowrie's clock/timezone was ever wrong
    # for a stretch (caught live in production 2026-08-06: pre-fix events
    # had an inflated hour digit from a 7-hour clock skew, so string-sorting
    # put them ahead of genuinely newer, correctly-timestamped events).
    # created_at is immune to that class of bug regardless of what Cowrie's
    # own clock is doing.
    attacks = list(collection.find(query, {"_id": 0}).sort("created_at", -1).limit(limit))
    return {"status": "success", "total_returned": len(attacks), "data": attacks}

@api_router.get("/top-ips")
def get_top_ips(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$group":  {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"ip": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@api_router.get("/top-passwords")
def get_top_passwords(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match":  {"password": {"$ne": None}}},
        {"$group":  {"_id": "$password", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"password": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@api_router.get("/top-usernames")
def get_top_usernames(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match":  {"username": {"$ne": None}}},
        {"$group":  {"_id": "$username", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"username": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@api_router.get("/alerts/pending")
def get_pending_alerts(user: str = Depends(auth.require_admin)):
    # require_admin, not get_current_user: this GET has a write side-effect
    # below (marks matched docs alerted=True, consuming the queue) - a
    # read-only viewer shouldn't be able to trigger that.
    alerts = list(
        collection.find(
            {"event": {"$in": ["cowrie.login.success", "cowrie.login.failed"]},
             "alerted": False},
            {"_id": 0}
        ).limit(20)
    )
    if alerts:
        collection.update_many({"alerted": False}, {"$set": {"alerted": True}})
    return {"data": alerts}

@api_router.get("/map-data")
def get_map_data(user: str = Depends(auth.get_current_user)):
    geo_filter = {"latitude": {"$ne": 0}, "longitude": {"$ne": 0}}
    pipeline = [
        {"$match": geo_filter},
        {"$group": {
            "_id":          "$src_ip",
            "count":        {"$sum": 1},
            "country":      {"$first": "$country"},
            "country_code": {"$first": "$country_code"},
            "city":         {"$first": "$city"},
            "latitude":     {"$first": "$latitude"},
            "longitude":    {"$first": "$longitude"},
        }},
        {"$sort":  {"count": -1}},
        {"$limit": 100},
        {"$project": {"ip": "$_id", "count": 1, "country": 1,
                      "country_code": 1, "city": 1, "latitude": 1, "longitude": 1, "_id": 0}}
    ]
    # The map only ever renders the top 100 markers (rendering thousands of
    # Leaflet pins would be slow and cluttered), but "Tổng IP" is a headline
    # stat - it must report the TRUE total unique IP count, not just how
    # many markers happened to fit under that cap (caught live in
    # production 2026-08-06: dashboard said 400 unique IPs, this page said
    # 100 - the same collection, just silently truncated here).
    total_unique_ips = len(collection.distinct("src_ip", geo_filter))
    return {"data": list(collection.aggregate(pipeline)), "total_unique_ips": total_unique_ips}

@api_router.get("/stats/hourly")
def get_hourly_stats(limit: int = 24, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$group": {"_id": {"$substr": ["$timestamp", 0, 13]}, "count": {"$sum": 1}}},
        {"$sort":  {"_id": -1}},
        {"$limit": limit},
        {"$project": {"time": {"$concat": ["$_id", ":00"]}, "count": 1, "_id": 0}}
    ]
    results = list(collection.aggregate(pipeline))
    results.reverse()
    return {"status": "success", "data": results}

@api_router.get("/stats/countries")
def get_top_countries(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match": {"country": {"$ne": None, "$ne": "Local"}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": limit},
        {"$project": {"country": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@api_router.get("/stats/mitre")
def get_mitre_stats(limit: int = 15, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$unwind": "$mitre_techniques"},
        {"$group": {"_id": "$mitre_techniques", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    data = [
        {
            "technique": r["_id"],
            "name": MITRE_TECHNIQUE_NAMES.get(r["_id"], r["_id"]),
            "count": r["count"],
        }
        for r in collection.aggregate(pipeline)
    ]
    return {"data": data}

@api_router.get("/stats/heatmap")
def get_attack_heatmap(user: str = Depends(auth.get_current_user)):
    """Attack volume by day-of-week x hour-of-day (UTC) - lets a real
    repeat pattern ("mostly weekday mornings") emerge once enough data
    accumulates. Computed in Python over collection.find() rather than via
    MongoDB's $dateFromString/$dayOfWeek aggregation operators, which
    mongomock (what the whole test suite runs against - see CLAUDE.md's
    safety notes) doesn't implement."""
    counts = [[0] * 24 for _ in range(7)]  # counts[weekday][hour], Monday=0..Sunday=6
    for doc in collection.find({}, {"timestamp": 1}):
        ts = doc.get("timestamp")
        if not ts:
            continue
        try:
            dt = _parse_iso_timestamp(ts)
        except (ValueError, TypeError):
            continue
        counts[dt.weekday()][dt.hour] += 1

    data = [
        {"day": day, "hour": hour, "count": counts[day][hour]}
        for day in range(7) for hour in range(24)
    ]
    return {"data": data}

@api_router.get("/brute-force")
def get_brute_force(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match": {"event": "cowrie.login.failed"}},
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1},
                    "country": {"$first": "$country"}}},
        {"$match": {"count": {"$gte": 10}}},
        {"$sort":  {"count": -1}},
        {"$limit": limit},
        {"$project": {
            "ip": "$_id", "count": 1, "country": 1,
            "danger": {"$cond": [{"$gte": ["$count", 50]}, "HIGH",
                       {"$cond": [{"$gte": ["$count", 20]}, "MEDIUM", "LOW"]}]},
            "_id": 0
        }}
    ]
    return {"data": list(collection.aggregate(pipeline))}

# Command sequence sent verbatim, in order, by a known scripted IoT-botnet
# loader (Mirai-family shell/device fingerprinting probe, seen live on this
# honeypot) - matched as a whole prefix so a human who happens to type e.g.
# just `system` on its own doesn't get flagged, only the exact scripted
# combination. Add more fixed prefixes here as new bot families show up.
KNOWN_BOT_COMMAND_PREFIXES = [
    ["sh", "shell", "enable", "system", "ping; sh"],
]

# A scripted loader sends its whole command list back-to-back, usually well
# under a second apart. A human reads output and decides what to try next,
# so the pause is normally several seconds+. This is a heuristic, not a
# certainty - a laggy/rate-limited bot or a very fast typist can land on
# either side of it.
HUMAN_AVG_GAP_SECONDS = 3.0

def _parse_iso_timestamp(ts: str):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

@api_router.get("/sessions/human-likely")
def get_human_likely_sessions(limit: int = 20, user: str = Depends(auth.get_current_user)):
    """Surfaces sessions that look like a real person typing rather than a
    scripted bot, based on inter-command timing and whether the command
    sequence matches a known fixed bot script - see the constants above.
    Existing Mongo documents/collection are untouched; this is a read-only
    derived view computed at request time, not stored anywhere."""
    pipeline = [
        {"$match": {"event": "cowrie.command.input", "command": {"$ne": None}}},
        {"$sort": {"timestamp": 1}},
        {"$group": {
            "_id": "$session",
            "commands":   {"$push": "$command"},
            "timestamps": {"$push": "$timestamp"},
            "src_ip":     {"$first": "$src_ip"},
            "country":    {"$first": "$country"},
        }},
        {"$match": {"$expr": {"$gte": [{"$size": "$commands"}, 2]}}},
    ]

    results = []
    for s in collection.aggregate(pipeline):
        commands, timestamps = s["commands"], s["timestamps"]
        gaps = []
        for prev_ts, ts in zip(timestamps, timestamps[1:]):
            try:
                gaps.append((_parse_iso_timestamp(ts) - _parse_iso_timestamp(prev_ts)).total_seconds())
            except (ValueError, TypeError):
                continue
        if not gaps:
            continue

        avg_gap = sum(gaps) / len(gaps)
        is_known_bot = any(
            commands[:len(prefix)] == prefix for prefix in KNOWN_BOT_COMMAND_PREFIXES
        )
        likely_human = avg_gap >= HUMAN_AVG_GAP_SECONDS and not is_known_bot

        results.append({
            "session":         s["_id"],
            "src_ip":          s["src_ip"],
            "country":         s["country"],
            "first_seen":      timestamps[0],
            "command_count":   len(commands),
            "avg_gap_seconds": round(avg_gap, 2),
            "likely_human":    likely_human,
            "commands":        commands,
        })

    results.sort(key=lambda r: (not r["likely_human"], -r["avg_gap_seconds"]))
    return {"data": results[:limit]}

@api_router.get("/sessions/{session_id}/replay")
def get_session_replay(session_id: str, user: str = Depends(auth.get_current_user)):
    """Converts the session's Cowrie TTY log into a JSON frame list the
    dashboard's replay viewer can step through on an xterm.js terminal -
    see dashboard/js/replay.js. Read live via os.getenv() rather than a
    module-level constant so it always reflects the current environment
    (and so tests can monkeypatch it per-case without re-importing main.py)."""
    ttylog_dir = os.getenv("TTYLOG_DIR", "/cowrie-tty")

    doc = collection.find_one(
        {"session": session_id, "event": "cowrie.log.closed", "ttylog": {"$ne": None}},
        {"_id": 0, "ttylog": 1, "src_ip": 1},
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Không có bản ghi phiên (TTY log) cho session này")

    ttylog_hash = doc["ttylog"]
    if not _TTYLOG_HASH_RE.match(ttylog_hash):
        # Can only happen from a corrupted/tampered DB row - a value
        # parser.py/log_watcher.py never write themselves (see their own
        # comment on this field).
        raise HTTPException(status_code=404, detail="TTY log không hợp lệ")

    path = os.path.join(ttylog_dir, ttylog_hash)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File TTY log không còn tồn tại trên đĩa")

    with open(path, "rb") as f:
        raw = f.read()

    frames, duration, truncated = _ttylog_to_frames(raw)
    return {
        "session": session_id,
        "src_ip": doc.get("src_ip"),
        "duration": duration,
        "truncated": truncated,
        "frames": frames,
    }


@api_router.get("/search")
def search_ip(ip: str = Query(...), user: str = Depends(auth.get_current_user)):
    # created_at, not timestamp - see get_attacks()'s comment above.
    attacks = list(collection.find({"src_ip": ip}, {"_id": 0}).sort("created_at", -1).limit(100))
    return {"ip": ip, "total": len(attacks), "data": attacks}

# Admin-only, same as /api/export/csv and /api/alerts/pending: this is the
# system's own access log (who logged into the dashboard/API, from where,
# when, success or failure) - a viewer account has no business reading it.
@api_router.get("/auth-log")
def get_auth_log(limit: int = 50, user: str = Depends(auth.require_admin)):
    entries = list(
        auth.auth_log_col.find({}, {"_id": 0, "prev_hash": 0, "entry_hash": 0})
        .sort("seq", -1)
        .limit(limit)
    )
    return {"data": entries}

@api_router.get("/auth-log/verify")
def verify_auth_log(user: str = Depends(auth.require_admin)):
    """Recomputes the auth_log hash chain end-to-end and reports whether it
    is still intact - see auth.verify_auth_log_integrity()'s docstring for
    what this can and can't detect."""
    result = auth.verify_auth_log_integrity()
    if not result["ok"]:
        logger.warning(
            "Auth log integrity check FAILED at seq %s", result["broken_at_seq"],
            extra={"username": user, "endpoint": "/api/auth-log/verify"},
        )
    return result

# Excel/Google Sheets/LibreOffice treat a cell starting with any of these
# as a formula to evaluate on open. Every field below comes straight from
# an attacker-controlled Cowrie event (username/password/command) or is
# otherwise untrusted, so a crafted value like `=cmd|'/c calc'!A1` in a
# username would execute when the admin opens the exported CSV - the
# classic "CSV/Formula Injection" (OWASP). Prefixing with a single quote
# neutralizes it as a formula while leaving the value readable as text.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


@api_router.get("/export/csv")
def export_csv(user: str = Depends(auth.require_admin)):
    logger.info("CSV export requested by '%s'", user, extra={"username": user, "endpoint": "/api/export/csv"})
    # created_at, not timestamp - see get_attacks()'s comment above.
    data   = list(collection.find({}, {"_id": 0}).sort("created_at", -1).limit(1000))
    output = io.StringIO()
    if data:
        writer = csv.DictWriter(output, fieldnames=["timestamp","src_ip","event","username","password","command","country","city"])
        writer.writeheader()
        for a in data:
            writer.writerow({k: _csv_safe(a.get(k, "")) for k in ["timestamp","src_ip","event","username","password","command","country","city"]})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot_attacks.csv"}
    )


app.include_router(api_router)
