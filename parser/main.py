from fastapi import FastAPI, Query
from pymongo import MongoClient
from fastapi.responses import StreamingResponse
import io
import csv

# Khởi tạo API
app = FastAPI(
    title="Honeypot API - Version 2 (Pro)",
    description="Hệ thống phân tích và thống kê log tấn công từ Cowrie",
    version="2.0.0"
)
 HEAD
# Kết nối MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["honeypot"]
=======
client     = MongoClient("mongodb://localhost:27017")
db         = client["honeypot"]
 3acac861a60282e868d43e4d7a11233ce7a6b055
collection = db["attacks"]

# 1. TẠO INDEX (Tăng tốc độ truy xuất dữ liệu)
collection.create_index([("timestamp", -1)])
collection.create_index([("src_ip", 1)])

<<<<<<< HEAD
# ==========================================
# CÁC API ENDPOINT
# ==========================================

# API cũ: Lấy danh sách tấn công chung
@app.get("/api/attacks", tags=["General"])
async def get_attacks(limit: int = 50, start_date: str = None, end_date: str = None):
    query = {}
    if start_date and end_date:
        query["timestamp"] = {"$gte": start_date, "$lte": end_date + "T23:59:59"}
    
    results = list(collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return {"status": "success", "total_returned": len(results), "data": results}

# 2. Thêm API: Thống kê Brute-force
@app.get("/api/brute-force", tags=["Statistics"])
async def get_brute_force_stats():
    total_attempts = collection.count_documents({"event": "cowrie.login.failed"})
    successful_logins = collection.count_documents({"event": "cowrie.login.success"})
    return {
        "total_brute_force_attempts": total_attempts,
        "successful_logins": successful_logins
    }

# 3. Thêm API: Top Usernames bị tấn công nhiều nhất
@app.get("/api/top-usernames", tags=["Statistics"])
async def get_top_usernames(limit: int = 10):
    pipeline = [
        {"$match": {"username": {"$ne": None, "$exists": True}}},
        {"$group": {"_id": "$username", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit}
    ]
    results = list(collection.aggregate(pipeline))
    return [{"username": r["_id"], "count": r["count"]} for r in results]

# 4. Thêm API: Tra cứu lịch sử tấn công theo IP
@app.get("/api/search", tags=["Search"])
async def search_by_ip(ip: str = Query(..., description="Nhập địa chỉ IP cần tra cứu (VD: 192.168.x.x)")):
    query = {"src_ip": ip}
    results = list(collection.find(query, {"_id": 0}).sort("timestamp", -1))
    return {"target_ip": ip, "total_events": len(results), "data": results}

# 5. Thêm API: Xuất dữ liệu ra file CSV báo cáo
@app.get("/api/export/csv", tags=["Export"])
async def export_csv():
    # Lấy 1000 dòng log mới nhất để xuất
    data = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(1000))
    
    output = io.StringIO()
    if data:
        # Lấy tên các cột tự động từ dữ liệu
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot_attacks_report.csv"}
    )
=======
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
>>>>>>> 3acac861a60282e868d43e4d7a11233ce7a6b055
