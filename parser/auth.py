"""
JWT + bcrypt authentication for the Honeypot dashboard/API.

Mechanism summary (see README for the full write-up):

- Passwords are hashed with bcrypt (never stored/compared in plaintext).
- Login issues two JWTs, both set as httpOnly cookies (not readable by JS,
  so an XSS bug can't steal them for exfiltration):
    - access_token  (short-lived, ACCESS_TOKEN_EXPIRE_MINUTES)  - sent with
      every request, checked by get_current_user().
    - refresh_token (long-lived, REFRESH_TOKEN_EXPIRE_DAYS) - only used to
      mint a new access_token via POST /auth/refresh.
  Access tokens are stateless (no DB lookup needed to validate one) so
  there's no server-side "blacklist" for them - the tradeoff is a stolen
  access token stays valid until it naturally expires. Refresh tokens ARE
  tracked in Mongo (refresh_tokens collection) so they can be revoked:
  /auth/logout deletes the refresh token's row, and /auth/refresh checks
  the row still exists before honoring the token. That's the
  "blacklist" - revocation is "no longer present in the allowlist".
- Failed logins are rate-limited per (ip, username) pair in Mongo
  (login_attempts collection) so restarting the API doesn't reset an
  attacker's lockout, and are logged to auth_log for the admin's own
  review - the same monitoring principle this project teaches for SSH
  attackers, applied to its own front door.
- CSRF uses the double-submit cookie pattern: a non-httpOnly csrf_token
  cookie is set alongside the JWT cookies, and every mutating request
  must echo it back in an X-CSRF-Token header. A cross-site page can
  trigger the request (cookies ride along automatically) but can't read
  the cookie to put its value in the header, so the check fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
import pyotp
from dotenv import load_dotenv
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError

import metrics

load_dotenv()


def _read_secret(env_name: str) -> Optional[str]:
    """Reads a secret from <env_name>_FILE (a file path) if set - the
    convention official Docker images use (e.g. POSTGRES_PASSWORD_FILE)
    and where this project's docker-compose.yml `secrets:` mounts land
    (/run/secrets/<name>) - else falls back to the plain env var directly,
    which is what the native venv workflow's .env file sets. Same helper
    duplicated in notifier/bot.py and notifier/telegram_commands.py rather
    than shared, consistent with this project's existing small-helper-
    duplication convention (see CLAUDE.md)."""
    file_path = os.getenv(f"{env_name}_FILE")
    if file_path:
        with open(file_path) as f:
            return f.read().strip()
    return os.getenv(env_name)


SECRET_KEY = _read_secret("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is not set. Generate one with:\n"
        "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "and put it in parser/.env as JWT_SECRET_KEY=<value> (native venv "
        "workflow), or in secrets/jwt_secret_key.txt (Docker Compose)."
    )


def _mongo_auth_kwargs() -> dict:
    """Adds MongoDB username/password auth if MONGO_USERNAME is set -
    the native venv workflow (mongod with no --auth) never sets it, so
    this returns {} and pymongo connects exactly as before. Docker
    Compose's mongo service and every app service opt into auth together
    (see docker-compose.yml's `secrets:` block) once MONGO_USERNAME/
    MONGO_PASSWORD (via _read_secret) are both present."""
    username = _read_secret("MONGO_USERNAME")
    if not username:
        return {}
    return {
        "username": username,
        "password": _read_secret("MONGO_PASSWORD"),
        "authSource": os.getenv("MONGO_AUTH_SOURCE", "admin"),
    }

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90
REFRESH_TOKEN_EXPIRE_DAYS = 7
PENDING_2FA_TOKEN_EXPIRE_MINUTES = 5

MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 15

# Generic per-IP rate limit applied to every /api/* endpoint (separate from
# the /auth/login-specific lockout above, which is keyed by ip+username and
# only guards credential-guessing). Deliberately generous - it exists to
# stop someone hammering the API (e.g. repeatedly calling
# /api/export/csv), not to throttle normal dashboard usage (a page load
# fires a handful of concurrent fetches, refreshed every 30s).
API_RATE_LIMIT_MAX_REQUESTS = 100
API_RATE_LIMIT_WINDOW_SECONDS = 60

# "admin" can do everything; "viewer" is read-only (see require_admin() below
# for exactly which endpoints that blocks). Accounts created before roles
# existed have no "role" field at all - they default to "admin" so upgrading
# this code never silently locks out an existing production account.
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
VALID_ROLES = (ROLE_ADMIN, ROLE_VIEWER)
DEFAULT_ROLE = ROLE_ADMIN

# bcrypt hard limit: it raises ValueError for inputs over 72 bytes rather
# than silently truncating (older bcrypt releases used to truncate).
MAX_PASSWORD_BYTES = 72

_client = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), **_mongo_auth_kwargs())
_db = _client[os.getenv("DB_NAME", "honeypot")]
users_col = _db["users"]
refresh_tokens_col = _db["refresh_tokens"]
login_attempts_col = _db["login_attempts"]
auth_log_col = _db["auth_log"]
api_rate_limits_col = _db["api_rate_limits"]

users_col.create_index("username", unique=True)
refresh_tokens_col.create_index("jti", unique=True)
refresh_tokens_col.create_index("expires_at", expireAfterSeconds=0)
login_attempts_col.create_index("key", unique=True)
api_rate_limits_col.create_index("key", unique=True)
api_rate_limits_col.create_index("expires_at", expireAfterSeconds=0)
# Doubles as the concurrency guard for log_auth_event()'s hash chain below -
# two requests racing to claim the same seq will have one lose to a
# DuplicateKeyError and retry, the same idiom users_col's unique username
# index already uses for registration races.
auth_log_col.create_index("seq", unique=True)

# Genesis value for the audit-log hash chain - the first entry's prev_hash.
AUTH_LOG_GENESIS_HASH = "0" * 64

# A fixed dummy hash to run bcrypt.checkpw against when the username doesn't
# exist, so a login attempt for a nonexistent user takes roughly the same
# time as one for a real user with a wrong password (avoids a timing side
# channel that would otherwise let an attacker enumerate valid usernames).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt())


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        return False
    return bcrypt.checkpw(password_bytes, password_hash.encode("utf-8"))


def _now() -> datetime:
    # Naive UTC on purpose: pymongo stores/returns BSON dates as naive UTC
    # datetimes, and mixing naive/aware datetimes raises a TypeError on
    # comparison. datetime.utcnow() is deprecated (Python 3.12+) but its
    # non-deprecated replacement, datetime.now(timezone.utc), returns an
    # AWARE datetime - stripping tzinfo here keeps every comparison against
    # Mongo-stored dates elsewhere in this file (locked_until, expires_at,
    # first_attempt_at, ...) working exactly as before. PyJWT accepts naive
    # datetimes for iat/exp and treats them as UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_user_role(username: str) -> str:
    """Looked up fresh at login and at every /auth/refresh (not baked into
    the long-lived refresh token), so demoting/promoting a user's role
    takes effect on that user's next token refresh without needing to
    revoke anything."""
    user = users_col.find_one({"username": username})
    if not user:
        return DEFAULT_ROLE
    return user.get("role", DEFAULT_ROLE)


def create_access_token(username: str, role: str) -> str:
    now = _now()
    payload = {
        "sub": username,
        "role": role,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str) -> str:
    now = _now()
    jti = uuid.uuid4().hex
    expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": username,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": expires_at,
    }
    refresh_tokens_col.insert_one(
        {"jti": jti, "username": username, "expires_at": expires_at}
    )
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_pending_2fa_token(username: str) -> str:
    """Issued once a password check succeeds for a user that has 2FA
    enabled, in place of the real access/refresh tokens - proves "this
    browser just proved it knows the password" without granting a real
    session until POST /auth/2fa/verify also checks out. Deliberately not
    tracked in Mongo like refresh tokens are: its 5-minute lifetime is
    short enough that server-side revocation isn't worth the complexity."""
    now = _now()
    payload = {
        "sub": username,
        "type": "pending_2fa",
        "iat": now,
        "exp": now + timedelta(minutes=PENDING_2FA_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Honeypot Monitor")


def verify_totp_code(secret: Optional[str], code: Optional[str]) -> bool:
    """valid_window=1 accepts the current 30s step plus one step of clock
    drift either side - matches how most authenticator apps/servers pair
    TOTP in practice, since phone/server clocks are rarely perfectly
    synced."""
    if not secret or not code:
        return False
    try:
        return pyotp.totp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        # Malformed code (non-numeric, wrong length, ...) - reject, don't 500.
        return False


def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn",
        ) from exc
    if payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn",
        )
    return payload


def revoke_refresh_token(token: str) -> None:
    """Delete the refresh token's row so /auth/refresh will reject it -
    this is the "blacklist": a revoked token is simply no longer found."""
    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False}
        )
    except jwt.PyJWTError:
        return
    jti = payload.get("jti")
    if jti:
        refresh_tokens_col.delete_one({"jti": jti})


def rotate_refresh_token(old_jti: str, username: str) -> str:
    """Issue a new refresh token and invalidate the old one (rotation
    limits how long a stolen refresh token stays useful)."""
    refresh_tokens_col.delete_one({"jti": old_jti})
    return create_refresh_token(username)


def _rate_limit_key(ip: str, username: str) -> str:
    return f"{ip}|{username.lower()}"


def check_rate_limit(ip: str, username: str) -> None:
    key = _rate_limit_key(ip, username)
    doc = login_attempts_col.find_one({"key": key})
    if not doc:
        return
    locked_until = doc.get("locked_until")
    if locked_until and locked_until > _now():
        remaining = int((locked_until - _now()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Quá nhiều lần đăng nhập sai. Thử lại sau {remaining} phút.",
        )


def record_failed_attempt(ip: str, username: str) -> None:
    key = _rate_limit_key(ip, username)
    now = _now()
    doc = login_attempts_col.find_one({"key": key})
    window_start = now - timedelta(minutes=LOGIN_ATTEMPT_WINDOW_MINUTES)
    if not doc or doc.get("first_attempt_at", now) < window_start:
        login_attempts_col.update_one(
            {"key": key},
            {"$set": {"attempts": 1, "first_attempt_at": now, "locked_until": None}},
            upsert=True,
        )
        return
    attempts = doc.get("attempts", 0) + 1
    update = {"attempts": attempts}
    if attempts >= MAX_LOGIN_ATTEMPTS:
        update["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
    login_attempts_col.update_one({"key": key}, {"$set": update})


def reset_attempts(ip: str, username: str) -> None:
    login_attempts_col.delete_one({"key": _rate_limit_key(ip, username)})


def _auth_log_canonical_bytes(
    seq: int, prev_hash: str, timestamp: datetime, ip: str, username: str,
    success: bool, user_agent: str,
) -> bytes:
    # BSON dates only keep millisecond precision, while Python datetimes
    # carry microseconds - hashing the raw datetime would make every
    # verification pass "detect tampering" that's really just precision
    # loss from the MongoDB round-trip. Rounding to milliseconds here
    # first means a value re-read from MongoDB during verification
    # reproduces the exact same bytes (and hash) as when it was written.
    ts = timestamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{timestamp.microsecond // 1000:03d}"
    payload = {
        "seq": seq, "prev_hash": prev_hash, "timestamp": ts,
        "ip": ip, "username": username, "success": success, "user_agent": user_agent,
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def log_auth_event(ip: str, username: str, success: bool, user_agent: str = "") -> None:
    """Appends a tamper-EVIDENT audit log entry: each entry's hash is
    computed over its own fields plus the previous entry's hash, chaining
    every entry to the one before it (the same linking idea a blockchain
    uses, applied to one MongoDB collection). This does NOT stop someone
    with direct database access from editing or deleting a row - nothing
    running only inside this app can prevent that - but it makes it
    DETECTABLE: changing or removing any entry breaks the hash chain from
    that point forward, which verify_auth_log_integrity() below will
    report, down to the exact entry where it broke.

    The retry loop + unique index on "seq" is the concurrency guard: two
    logins racing to read "the current last entry" and append the next one
    would otherwise silently fork the chain (two different entries both
    claiming to be seq N with different prev_hash) instead of extending it
    - the unique index makes the second insert fail with a DuplicateKeyError,
    at which point it retries against the new tip.
    """
    # "seq": {"$exists": True} excludes entries logged before this hash-chain
    # feature existed (a real one is already sitting in production, from
    # 2026-07-28) - those have no seq/entry_hash at all, so treating them as
    # chain members would either KeyError or fork the chain. The chain
    # simply starts fresh at seq 0 the first time this runs; pre-existing
    # entries are left alone, not retroactively covered by tamper-evidence
    # (nothing can prove the integrity of data written before this existed).
    timestamp = _now()
    while True:
        last_entry = auth_log_col.find_one({"seq": {"$exists": True}}, sort=[("seq", -1)])
        seq = (last_entry["seq"] + 1) if last_entry else 0
        prev_hash = last_entry["entry_hash"] if last_entry else AUTH_LOG_GENESIS_HASH

        entry_hash = hashlib.sha256(
            _auth_log_canonical_bytes(seq, prev_hash, timestamp, ip, username, success, user_agent)
        ).hexdigest()

        try:
            auth_log_col.insert_one(
                {
                    "seq": seq,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                    "timestamp": timestamp,
                    "ip": ip,
                    "username": username,
                    "success": success,
                    "user_agent": user_agent,
                }
            )
            return
        except DuplicateKeyError:
            continue  # another request claimed this seq first - retry against the new tip


def verify_auth_log_integrity() -> dict:
    """Walks the entire auth_log hash chain in seq order, recomputing each
    entry's hash from its own stored fields + the previous entry's stored
    hash, and compares it against what's actually stored. Returns
    {"ok": bool, "checked": int, "broken_at_seq": int | None} -
    broken_at_seq is the first entry (if any) whose hash doesn't match what
    the chain predicts, i.e. the first point where a row was edited,
    deleted, or reordered. Entries logged before this feature existed (no
    "seq" field at all) are skipped, not counted, and can't break the
    chain - see log_auth_event()'s comment on the same filter."""
    prev_hash = AUTH_LOG_GENESIS_HASH
    checked = 0
    for entry in auth_log_col.find({"seq": {"$exists": True}}).sort("seq", 1):
        expected_hash = hashlib.sha256(
            _auth_log_canonical_bytes(
                entry.get("seq"), prev_hash, entry.get("timestamp"),
                entry.get("ip"), entry.get("username"), entry.get("success"),
                entry.get("user_agent", ""),
            )
        ).hexdigest()
        if entry.get("prev_hash") != prev_hash or entry.get("entry_hash") != expected_hash:
            return {"ok": False, "checked": checked, "broken_at_seq": entry.get("seq")}
        prev_hash = entry["entry_hash"]
        checked += 1
    return {"ok": True, "checked": checked, "broken_at_seq": None}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_api_rate_limit(request: Request) -> None:
    """FastAPI dependency for every /api/* endpoint: a generic per-IP
    fixed-window request cap, independent of the /auth/login-specific
    lockout above. Uses find_one_and_update's atomic $inc (unlike
    record_failed_attempt's read-then-write above) so concurrent requests
    in the same window can't race past the limit; the window is bucketed
    by floor(now / API_RATE_LIMIT_WINDOW_SECONDS) so each window is a
    fresh document rather than needing a reset step, and the TTL index on
    api_rate_limits_col cleans up old buckets automatically."""
    ip = client_ip(request)
    now = _now()
    # time.time(), not now.timestamp() - _now() is a naive UTC datetime,
    # and .timestamp() on a naive datetime assumes the LOCAL timezone,
    # which would shift bucket boundaries by the server's UTC offset.
    bucket = int(time.time() // API_RATE_LIMIT_WINDOW_SECONDS)
    key = f"{ip}|{bucket}"
    doc = api_rate_limits_col.find_one_and_update(
        {"key": key},
        {
            "$inc": {"count": 1},
            "$setOnInsert": {"expires_at": now + timedelta(seconds=API_RATE_LIMIT_WINDOW_SECONDS * 2)},
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if doc["count"] > API_RATE_LIMIT_MAX_REQUESTS:
        metrics.API_RATE_LIMIT_REJECTIONS.inc()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Quá nhiều yêu cầu, vui lòng thử lại sau ít phút.",
        )


def authenticate_user(username: str, password: str) -> bool:
    """Constant-time-ish check: always runs a bcrypt comparison even for a
    nonexistent username, against the dummy hash, so response timing
    doesn't reveal whether the username exists. An over-length password
    (bcrypt rejects anything over 72 bytes) fails the same way - a wrong
    password, no crash, same generic error message."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        bcrypt.checkpw(b"dummy-password-for-timing", _DUMMY_HASH)
        return False

    user = users_col.find_one({"username": username})
    if not user:
        bcrypt.checkpw(password_bytes, _DUMMY_HASH)
        return False
    return verify_password(password, user["password_hash"])


def _get_access_payload(
    access_token: Optional[str] = Cookie(default=None),
) -> dict:
    """Shared by get_current_user() and require_admin() below - FastAPI
    caches a dependency's result per-request when the same callable is
    depended on more than once, so the token is only decoded once even on
    an endpoint that uses require_admin (which itself depends on this)."""
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Chưa đăng nhập hoặc phiên đã hết hạn",
        )
    return decode_token(access_token, expected_type="access")


def get_current_user(payload: dict = Depends(_get_access_payload)) -> str:
    return payload["sub"]


def get_pending_2fa_payload(
    pending_2fa_token: Optional[str] = Cookie(default=None),
) -> dict:
    """Dependency for POST /auth/2fa/verify - the browser proved the
    password already (see create_pending_2fa_token()); this just confirms
    that proof is present and not expired before checking the TOTP code
    itself."""
    if not pending_2fa_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Chưa xác thực mật khẩu hoặc phiên xác thực 2 lớp đã hết hạn",
        )
    return decode_token(pending_2fa_token, expected_type="pending_2fa")


def require_admin(payload: dict = Depends(_get_access_payload)) -> str:
    """Dependency for endpoints a 'viewer' role must not reach (data export,
    and anything that mutates/consumes data rather than just reading it).
    Tokens issued before roles existed have no "role" claim - treated as
    DEFAULT_ROLE (admin), same backward-compat rule as get_user_role()."""
    if payload.get("role", DEFAULT_ROLE) != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chỉ tài khoản admin mới có quyền truy cập chức năng này",
        )
    return payload["sub"]


def verify_csrf(
    request: Request,
    csrf_token_cookie: Optional[str] = Cookie(default=None, alias="csrf_token"),
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
) -> None:
    if not csrf_token_cookie or not x_csrf_token or not secrets.compare_digest(
        csrf_token_cookie, x_csrf_token
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token không hợp lệ"
        )


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
