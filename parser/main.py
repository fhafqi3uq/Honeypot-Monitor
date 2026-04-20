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

# Kết nối MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["honeypot"]
collection = db["attacks"]

# 1. TẠO INDEX (Tăng tốc độ truy xuất dữ liệu)
collection.create_index([("timestamp", -1)])
collection.create_index([("src_ip", 1)])

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
