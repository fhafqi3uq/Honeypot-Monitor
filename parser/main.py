from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient

app = FastAPI(title="Honeypot API")

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
def root():
    return {"message": "Honeypot API đang chạy!", "status": "ok"}

@app.get("/api/stats")
def get_stats():
    return {
        "total":      collection.count_documents({}),
        "failed":     collection.count_documents({"event": "cowrie.login.failed"}),
        "success":    collection.count_documents({"event": "cowrie.login.success"}),
        "commands":   collection.count_documents({"event": "cowrie.command.input"}),
        "unique_ips": len(collection.distinct("src_ip")),
    }

@app.get("/api/attacks")
def get_attacks(limit: int = 50):
    attacks = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return {"data": attacks, "total": len(attacks)}

@app.get("/api/top-ips")
def get_top_ips(limit: int = 10):
    pipeline = [
        {"$group":  {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  limit},
        {"$project": {"ip": "$_id", "count": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}

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

@app.get("/api/alerts/pending")
def get_pending_alerts():
    alerts = list(
        collection.find(
            {"event": {"$in": ["cowrie.login.success", "cowrie.login.failed"]}, "alerted": False},
            {"_id": 0}
        ).limit(20)
    )
    if alerts:
        collection.update_many({"alerted": False}, {"$set": {"alerted": True}})
    return {"data": alerts}

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
        {"$project": {"ip": "$_id", "count": 1, "country": 1, "country_code": 1, "city": 1, "latitude": 1, "longitude": 1, "_id": 0}}
    ]
    return {"data": list(collection.aggregate(pipeline))}
