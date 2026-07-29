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

import os
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from pymongo import MongoClient

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is not set. Generate one with:\n"
        "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "and put it in parser/.env as JWT_SECRET_KEY=<value>."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90
REFRESH_TOKEN_EXPIRE_DAYS = 7

MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 15

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

_client = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
_db = _client[os.getenv("DB_NAME", "honeypot")]
users_col = _db["users"]
refresh_tokens_col = _db["refresh_tokens"]
login_attempts_col = _db["login_attempts"]
auth_log_col = _db["auth_log"]

users_col.create_index("username", unique=True)
refresh_tokens_col.create_index("jti", unique=True)
refresh_tokens_col.create_index("expires_at", expireAfterSeconds=0)
login_attempts_col.create_index("key", unique=True)

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
    # comparison. Keeping everything naive-UTC (matching datetime.utcnow()
    # used elsewhere in this project) avoids that entirely; PyJWT accepts
    # naive datetimes for iat/exp and treats them as UTC.
    return datetime.utcnow()


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


def log_auth_event(ip: str, username: str, success: bool, user_agent: str = "") -> None:
    auth_log_col.insert_one(
        {
            "timestamp": _now(),
            "ip": ip,
            "username": username,
            "success": success,
            "user_agent": user_agent,
        }
    )


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


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
