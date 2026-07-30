"""
Prometheus metric definitions for the API.

Kept in its own module (not main.py) so auth.py can import and increment
API_RATE_LIMIT_REJECTIONS without a circular import - main.py already
imports auth, so auth importing main back would be circular.

/metrics itself is exposed directly on `app` in main.py, not on
api_router: it must stay reachable without a login cookie (Prometheus has
no way to authenticate against this app's JWT/cookie flow) and is
deliberately not subject to the generic per-IP /api/* rate limit, which
exists to protect the attack-data endpoints, not this project's own
monitoring endpoint.
"""

from __future__ import annotations

from prometheus_client import REGISTRY, Counter, Histogram

HTTP_REQUESTS = Counter(
    "honeypot_http_requests_total",
    "HTTP requests received by the API",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "honeypot_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
)

LOGIN_ATTEMPTS = Counter(
    "honeypot_login_attempts_total",
    "Dashboard/API login attempts via POST /auth/login",
    ["result"],  # "success" or "failed"
)

API_RATE_LIMIT_REJECTIONS = Counter(
    "honeypot_api_rate_limit_rejections_total",
    "Requests rejected by the generic per-IP /api/* rate limit (auth.check_api_rate_limit)",
)

_current_mongo_stats_collector = None


def register_mongo_stats_collector(collector) -> None:
    """Replaces any previously-registered Mongo-stats collector, rather
    than just registering a new one, for the same reason this module (not
    main.py) holds the reference: prometheus_client's default REGISTRY is
    a genuine process-wide singleton, unaffected by tests' fresh_app/
    fresh_module fixtures popping "main" from sys.modules and re-importing
    it fresh per test. Without replacing the old registration, only the
    FIRST test's collector - a closure over that test's own, now-discarded
    mongomock collection - would ever be scraped for the rest of the
    session, silently making every later test's /metrics output stale.
    Real production only ever calls this once (uvicorn imports main.py a
    single time), so the "replace" branch never runs there."""
    global _current_mongo_stats_collector
    if _current_mongo_stats_collector is not None:
        REGISTRY.unregister(_current_mongo_stats_collector)
    REGISTRY.register(collector)
    _current_mongo_stats_collector = collector
