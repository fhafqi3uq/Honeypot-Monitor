from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from typing import Optional

app = FastAPI(title="Honeypot API - Version 2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

client     = MongoClient("mongodb://localhost:27017")
db         = client["honeypot"]
collection = db["attacks"]

@app.get("/")
def read_root():
    return {"message": "Honeypot API V2 đang chạy!", "status": "ok"}

# ── 1. Thống kê tổng hợp ─────────────────────────
@app.get("/api/stats")
def get_stats():
    return {
        "total":      collection.count_documents({}),
        "failed":     collection.count_documents({"event": "cowrie.login.failed"}),
        "success":    collection.count_documents({"event": "cowrie.login.success"}),
        "commands":   collection.count_documents({"event": "cowrie.command.input"}),
        "unique_ips": len(collection.distinct("src_ip")),
    }

# ── 2. Danh sách tấn công (lọc theo ngày) ────────
@app.get("/api/attacks")
def get_attacks(
    limit: int = 50,
    start_date: Optional[str] = Query(None, description="YYYY-MM-DD"),
    end_date:   Optional[str] = Query(None, description="YYYY-MM-DD")
):
    query = {}
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = f"{start_date}T00:00:00"
        if end_date:
            query["timestamp"]["$lte"] = f"{end_date}T23:59:59"
    attacks = list(
        collection.find(query, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return {"status": "success", "total_returned": len(attacks), "data": attacks}

# ── 3. Top IP tấn công ───────────────────────────
@app.get("/api/top-ips")
def get_top_ips(limit: int = 10):
    pipeline = [
        {"$group":  {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"ip": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

# ── 4. Top password bị thử ───────────────────────
@app.get("/api/top-passwords")
def get_top_passwords(limit: int = 10):
    pipeline = [
        {"$match":  {"password": {"$ne": None}}},
        {"$group":  {"_id": "$password", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"password": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

# ── 5. Alerts chưa gửi (TV4 dùng) ────────────────
@app.get("/api/alerts/pending")
def get_pending_alerts():
    alerts = list(
        collection.find(
            {"event": {"$in": ["cowrie.login.success", "cowrie.login.failed"]},
             "alerted": False},
            {"_id": 0}
        ).limit(20)
    )
    if alerts:
        collection.update_many(
            {"alerted": False},
            {"$set": {"alerted": True}}
        )
    return {"data": alerts}

# ── 6. Data bản đồ thế giới (TV3 dùng) ───────────
@app.get("/api/map-data")
def get_map_data():
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
        {"$project": {
            "ip":           "$_id",
            "count":        1,
            "country":      1,
            "country_code": 1,
            "city":         1,
            "latitude":     1,
            "longitude":    1,
            "_id":          0
        }}
    ]
    return {"data": list(collection.aggregate(pipeline))}

# ── 7. Thống kê theo giờ (TV3 biểu đồ) ──────────
@app.get("/api/stats/hourly")
def get_hourly_stats(limit: int = 24):
    pipeline = [
        {"$group": {
            "_id":   {"$substr": ["$timestamp", 0, 13]},
            "count": {"$sum": 1}
        }},
        {"$sort":  {"_id": -1}},
        {"$limit": limit},
        {"$project": {
            "time":  {"$concat": ["$_id", ":00"]},
            "count": 1,
            "_id":   0
        }}
    ]
    results = list(collection.aggregate(pipeline))
    results.reverse()
    return {"status": "success", "data": results}

# ── 8. Thống kê theo quốc gia ────────────────────
@app.get("/api/stats/countries")
def get_top_countries(limit: int = 10):
    pipeline = [
        {"$match": {"country": {"$ne": None, "$ne": "Local"}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": limit},
        {"$project": {"country": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}
