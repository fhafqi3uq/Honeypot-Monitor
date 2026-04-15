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

# Kết nối MongoDB
client = MongoClient("mongodb://localhost:27017")
db = client["honeypot"]
collection = db["attacks"]

@app.get("/")
def read_root():
    return {"message": "Honeypot API V2 đang chạy!", "status": "ok"}

# 1. NÂNG CẤP: Lọc danh sách tấn công theo thời gian
@app.get("/api/attacks")
def get_attacks(
    limit: int = 50,
    start_date: Optional[str] = Query(None, description="Định dạng: YYYY-MM-DD"),
    end_date: Optional[str] = Query(None, description="Định dạng: YYYY-MM-DD")
):
    """Lấy danh sách tấn công (có hỗ trợ lọc theo ngày)"""
    query = {}
    
    # Nếu có truyền ngày bắt đầu hoặc kết thúc, thêm điều kiện lọc vào query
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = f"{start_date}T00:00:00" # Lớn hơn hoặc bằng
        if end_date:
            query["timestamp"]["$lte"] = f"{end_date}T23:59:59"   # Nhỏ hơn hoặc bằng

    attacks = list(
        collection.find(query, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return {"status": "success", "total_returned": len(attacks), "data": attacks}

# 2. API CŨ: Top IP (Giữ nguyên)
@app.get("/api/top-ips")
def get_top_ips(limit: int = 10):
    """Thống kê các IP tấn công nhiều nhất"""
    pipeline = [
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
        {"$project": {"ip": "$_id", "count": 1, "_id": 0}}
    ]
    return {"status": "success", "data": list(collection.aggregate(pipeline))}

# 3. MỚI: Thống kê số lượng tấn công theo TỪNG GIỜ
@app.get("/api/stats/hourly")
def get_hourly_stats(limit: int = 24):
    """Phục vụ vẽ biểu đồ: Đếm số lượng tấn công theo từng giờ"""
    pipeline = [
        # Cắt chuỗi timestamp (VD: 2024-04-12T15:30:00Z) lấy 13 ký tự đầu để nhóm theo Giờ (2024-04-12T15)
        {"$group": {
            "_id": {"$substr": ["$timestamp", 0, 13]}, 
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": -1}}, # Sắp xếp từ mới nhất đến cũ nhất
        {"$limit": limit},
        {"$project": {
            "time": {"$concat": ["$_id", ":00"]}, # Nối thêm :00 cho đẹp (VD: 2024-04-12T15:00)
            "count": 1, 
            "_id": 0
        }}
    ]
    
    results = list(collection.aggregate(pipeline))
    # Đảo ngược lại list để biểu đồ vẽ từ trái sang phải (cũ đến mới)
    results.reverse() 
    
    return {"status": "success", "data": results}
