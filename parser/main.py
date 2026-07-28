import os

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pymongo import MongoClient
from typing import Optional
import io, csv

import auth

app = FastAPI(
    title="Honeypot API - Version 2 (Pro)",
    description="Hệ thống phân tích và thống kê log tấn công từ Cowrie",
    version="2.0.0"
)

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
        # Deliberately generic - never say which of username/password was wrong.
        raise HTTPException(status_code=401, detail="Sai thông tin đăng nhập")

    auth.reset_attempts(ip, payload.username)
    auth.log_auth_event(ip, payload.username, success=True, user_agent=user_agent)

    access_token = auth.create_access_token(payload.username)
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
    return {"status": "ok", "username": payload.username, "csrf_token": csrf_token}


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
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc phiên đã hết hạn")

    payload = auth.decode_token(refresh_token, expected_type="refresh")
    # Must still be present in the allowlist - deleted rows (logout, or a
    # prior refresh's rotation) mean this token has been revoked.
    if not auth.refresh_tokens_col.find_one({"jti": payload["jti"]}):
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc phiên đã hết hạn")

    new_refresh_token = auth.rotate_refresh_token(payload["jti"], payload["sub"])
    new_access_token = auth.create_access_token(payload["sub"])

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
    return {"username": user}


@app.get("/")
def root():
    return {"message": "Honeypot API V2 đang chạy!", "status": "ok"}

@app.get("/api/stats")
def get_stats(user: str = Depends(auth.get_current_user)):
    return {
        "total":      collection.count_documents({}),
        "failed":     collection.count_documents({"event": "cowrie.login.failed"}),
        "success":    collection.count_documents({"event": "cowrie.login.success"}),
        "commands":   collection.count_documents({"event": "cowrie.command.input"}),
        "unique_ips": len(collection.distinct("src_ip")),
    }

@app.get("/api/attacks")
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

@app.get("/api/top-ips")
def get_top_ips(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$group":  {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"ip": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@app.get("/api/top-passwords")
def get_top_passwords(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match":  {"password": {"$ne": None}}},
        {"$group":  {"_id": "$password", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"password": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@app.get("/api/top-usernames")
def get_top_usernames(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match":  {"username": {"$ne": None}}},
        {"$group":  {"_id": "$username", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"username": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@app.get("/api/alerts/pending")
def get_pending_alerts(user: str = Depends(auth.get_current_user)):
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

@app.get("/api/map-data")
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

@app.get("/api/stats/hourly")
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

@app.get("/api/stats/countries")
def get_top_countries(limit: int = 10, user: str = Depends(auth.get_current_user)):
    pipeline = [
        {"$match": {"country": {"$ne": None, "$ne": "Local"}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": limit},
        {"$project": {"country": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

@app.get("/api/brute-force")
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

@app.get("/api/search")
def search_ip(ip: str = Query(...), user: str = Depends(auth.get_current_user)):
    attacks = list(collection.find({"src_ip": ip}, {"_id": 0}).sort("timestamp", -1).limit(100))
    return {"ip": ip, "total": len(attacks), "data": attacks}

@app.get("/api/export/csv")
def export_csv(user: str = Depends(auth.get_current_user)):
    data   = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(1000))
    output = io.StringIO()
    if data:
        writer = csv.DictWriter(output, fieldnames=["timestamp","src_ip","event","username","password","command","country","city"])
        writer.writeheader()
        for a in data:
            writer.writerow({k: a.get(k,"") for k in ["timestamp","src_ip","event","username","password","command","country","city"]})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot_attacks.csv"}
    )
