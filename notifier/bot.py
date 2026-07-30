import html
import requests
import os
import time
from dotenv import load_dotenv
from notify_log_setup import get_logger

load_dotenv()

logger = get_logger(__name__)

TOKEN     = os.getenv("TELEGRAM_TOKEN")
CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")

REQUEST_TIMEOUT = 10
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2

def _request_with_retry(method, url, **kwargs):
    """Wrap a requests.get/post call with a fixed timeout and retry-with-
    backoff on Timeout/ConnectionError. Without this, a slow or unreachable
    Telegram/AbuseIPDB/ipinfo.io endpoint hangs (or silently fails) the
    single-threaded realtime alert pipeline - a transient network blip would
    otherwise cost an entire alert with no second attempt."""
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return method(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            last_exc = exc
            logger.warning(
                "Request to %s failed (attempt %d/%d): %s", url, attempt, MAX_RETRIES, exc
            )
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    raise last_exc

def send_message(text: str) -> bool:
    # Never log TOKEN/url - it embeds TELEGRAM_TOKEN.
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    try:
        res = _request_with_retry(requests.post, url, json={
            "chat_id":    CHAT_ID,
            "text":       text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        })
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        logger.error(
            "Telegram send_message failed after %d retries", MAX_RETRIES, exc_info=True
        )
        return False
    if res.status_code != 200:
        logger.warning("Telegram send_message failed with status %s", res.status_code)
    return res.status_code == 200

def check_abuseipdb(ip: str) -> int:
    """Tra cứu điểm tín nhiệm IP trên AbuseIPDB (0-100)"""
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return 0
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': ABUSE_KEY}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        res = _request_with_retry(requests.get, url, headers=headers, params=params).json()
        return res['data']['abuseConfidenceScore']
    except Exception:
        logger.warning("AbuseIPDB lookup failed for %s", ip, extra={"ip": ip}, exc_info=True)
        return 0

def _esc(value) -> str:
    """html.escape() attacker-controlled fields before they land in a
    parse_mode=HTML Telegram message - value may be None (Cowrie doesn't
    always populate username/password/input)."""
    return html.escape(str(value)) if value is not None else ""

def get_severity(eventid, abuse_score=0):
    """Phân loại mức độ cảnh báo 🔴🟠🟡🔵"""
    if eventid == "cowrie.login.success":
        return "🔴 <b>CRITICAL: SUCCESSFUL LOGIN</b>", "High"
    if eventid == "cowrie.command.input":
        return "🟠 <b>WARNING: COMMAND EXECUTED</b>", "Medium"
    if abuse_score > 50:
        return "🟡 <b>SUSPICIOUS: HIGH ABUSE SCORE</b>", "Warning"
    return "🔵 <b>INFO: LOGIN ATTEMPT</b>", "Low"

def get_ip_info(ip: str) -> dict:
    abuse_score = check_abuseipdb(ip)
    try:
        res = _request_with_retry(requests.get, f"https://ipinfo.io/{ip}/json")
        data = res.json()
        loc  = data.get("loc", "")
        lat, lon = loc.split(",") if "," in loc else (None, None)
        return {
            "location": f"{data.get('city', 'Unknown')}, {data.get('country', '??')}",
            "isp": data.get("org", "Unknown"),
            "lat": lat, "lon": lon, "abuse_score": abuse_score
        }
    except Exception:
        logger.warning("ipinfo.io lookup failed for %s", ip, extra={"ip": ip}, exc_info=True)
        return {"location": "Unknown", "isp": "Unknown", "lat": None, "lon": None, "abuse_score": abuse_score}

def alert_login_failed(ip: str, username: str, password: str, count: int):
    info = get_ip_info(ip)
    label, _ = get_severity("cowrie.login.failed", info['abuse_score'])
    msg = (
        f"{label}\n━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{_esc(ip)}</code> (Score: {info['abuse_score']})\n"
        f"📍 Vị trí: <b>{_esc(info['location'])}</b>\n"
        f"🏢 ISP: <i>{_esc(info['isp'])}</i>\n"
        f"👤 User: <code>{_esc(username)}</code>\n"
        f"🔑 Pass: <code>{_esc(password)}</code>\n"
        f"🔢 Số lần thử: <b>{count}</b>"
    )
    return send_message(msg)

def alert_login_success(ip: str, username: str, password: str):
    info = get_ip_info(ip)
    label, _ = get_severity("cowrie.login.success")
    msg = (
        f"{label}\n━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{_esc(ip)}</code>\n"
        f"📍 Vị trí: <b>{_esc(info['location'])}</b>\n"
        f"👤 User: <code>{_esc(username)}</code> | Pass: <code>{_esc(password)}</code>\n"
        f"❗ <b>Kẻ tấn công đã vào được hệ thống!</b>"
    )
    return send_message(msg)

def alert_command(ip: str, command: str):
    info = get_ip_info(ip)
    label, _ = get_severity("cowrie.command.input")
    msg = (
        f"{label}\n━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{_esc(ip)}</code>\n"
        f"📍 Vị trí: <b>{_esc(info['location'])}</b>\n"
        f"⌨️ Lệnh: <code>{_esc(command)}</code>"
    )
    return send_message(msg)
