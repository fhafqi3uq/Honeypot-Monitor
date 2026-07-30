import os

from fastapi import APIRouter, Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pymongo import MongoClient
from typing import Optional
import io, csv

import auth
from log_setup import get_logger

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
client     = MongoClient(MONGO_URL)
db         = client[DB_NAME]
collection = db["attacks"]

collection.create_index([("timestamp", -1)])
collection.create_index([("src_ip", 1)])

logger.info(
    "API starting up, connected to database %s",
    DB_NAME,
)  # deliberately not logging MONGO_URL - it may embed credentials (mongodb://user:pass@host)

COOKIE_KWARGS = {"httponly": True, "samesite": "lax", "secure": False, "path": "/"}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    ip = auth.client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    auth.check_rate_limit(ip, payload.username)

    if not auth.authenticate_user(payload.username, payload.password):
        auth.record_failed_attempt(ip, payload.username)
        auth.log_auth_event(ip, payload.username, success=False, user_agent=user_agent)
        logger.warning(
            "Failed login attempt for user '%s'", payload.username,
            extra={"ip": ip, "username": payload.username, "endpoint": "/auth/login"},
        )
        # Deliberately generic - never say which of username/password was wrong.
        raise HTTPException(status_code=401, detail="Sai thông tin đăng nhập")

    auth.reset_attempts(ip, payload.username)
    auth.log_auth_event(ip, payload.username, success=True, user_agent=user_agent)
    logger.info(
        "Successful login for user '%s'", payload.username,
        extra={"ip": ip, "username": payload.username, "endpoint": "/auth/login"},
    )

    role = auth.get_user_role(payload.username)
    access_token = auth.create_access_token(payload.username, role)
    refresh_token = auth.create_refresh_token(payload.username)
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
    return {"status": "ok", "username": payload.username, "role": role, "csrf_token": csrf_token}


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
    attacks = list(collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))
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
    pipeline = [
        {"$match": {"latitude": {"$ne": 0}, "longitude": {"$ne": 0}}},
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
    return {"data": list(collection.aggregate(pipeline))}

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

@api_router.get("/search")
def search_ip(ip: str = Query(...), user: str = Depends(auth.get_current_user)):
    attacks = list(collection.find({"src_ip": ip}, {"_id": 0}).sort("timestamp", -1).limit(100))
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
    data   = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(1000))
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
