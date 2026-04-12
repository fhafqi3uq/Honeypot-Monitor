import geoip2.database
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "geoip/GeoLite2-City.mmdb")

def get_geo(ip: str) -> dict:
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return {"country": "Local", "country_code": "LO", "city": "localhost", "latitude": 0.0, "longitude": 0.0}
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
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

if __name__ == "__main__":
    for ip in ["185.220.101.45", "45.33.32.156", "103.21.244.0", "127.0.0.1"]:
        info = get_geo(ip)
        print(f"{ip:20} → {info['country']:15} | {info['city']}")
