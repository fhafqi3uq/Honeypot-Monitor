# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Honeypot Monitor collects, analyzes, and alerts on SSH attacks captured by a Cowrie honeypot. Attackers hit a fake SSH server, events are parsed into MongoDB, a FastAPI backend serves stats/queries, a static JS dashboard visualizes them, and a Telegram bot pushes realtime + daily alerts. There is no build step or linter configured in this repo; there IS a pytest suite (`tests/`) covering parser/alerting/auth/API/dashboard/E2E layers — see the safety note below before running or writing any script against these modules.

**Safety when touching parser/notifier code**: `parser/log_watcher.py`, `parser/parser.py`, `parser/cleanup.py`, `parser/auth.py`, and `notifier/{realtime_alert,telegram_commands}.py` all do `MongoClient(...)` at import time, pointed at the real `honeypot` database by default. Never `import` or run these directly outside of pytest (which patches `pymongo.MongoClient` session-wide via `tests/conftest.py`'s `_never_touch_real_mongo` fixture) — an ad-hoc script bypasses that safety net and can write real rows into production. Always go through the `fresh_module`/`fresh_app` fixtures in a real test file instead.

## Architecture

Four independent components communicate only through the Cowrie JSON log file and a shared MongoDB `honeypot.attacks` collection — there is no direct import between them:

- **honeypot/cowrie-src** — git submodule running Cowrie, a simulated SSH/Telnet server. Writes one JSON event per line to `honeypot/cowrie-src/var/log/cowrie/cowrie.json`. This is the only integration point other components read from.
- **parser/** — FastAPI backend (`main.py`) + two independent long-running scripts that both tail the same Cowrie log and insert into MongoDB: `log_watcher.py` (backfills the `alerted` flag as `False`, for the dashboard/API path) and, separately, `notifier/realtime_alert.py` (inserts with `alerted: True` and triggers a Telegram push in the same pass). Both watchers detect Cowrie log rotation (`logtype=rotating`, typically at midnight) by comparing `os.stat().st_ino` every poll cycle and reopening the path when the inode changes — the file is never left pointing at a renamed-away, no-longer-updated fd. `parser.py` is the one-shot importer for `honeypot/sample_log.json`, used to seed a demo DB. `cleanup.py` runs on a `schedule` loop and deletes documents older than 30 days at 00:00. `geoip_lookup.py` wraps a local MaxMind `.mmdb` file (path: `parser/geoip/GeoLite2-City.mmdb`, gitignored — must be downloaded separately) to enrich each event with country/city/lat-lon; private IP ranges (`127.`, `192.168.`, `10.`, `172.`) short-circuit to `"Local"` without a DB lookup. `log_setup.py` provides `get_logger(name)` — structured JSON logging (one JSON object per line: timestamp/level/module/message + optional ip/session/username/event/endpoint context) written to `logs/parser.log`, used by `log_watcher.py` and `main.py`. Never log secrets (`JWT_SECRET_KEY`, `MONGO_URL` if it ever embeds credentials) through this logger — it does no redaction, callers must simply not pass secrets in.
- **notifier/** — `bot.py` holds the Telegram send/format helpers (severity levels, AbuseIPDB scoring, ipinfo.io lookups) shared by `realtime_alert.py` (tails the Cowrie log directly, independent of `parser/log_watcher.py`), `daily_report.py` (scheduled 08:00 summary, reads the Cowrie log or falls back to `honeypot/sample_log.json` if it doesn't exist yet), and `telegram_commands.py` (long-polls Telegram `getUpdates` for `/stats`, `/top`, `/brute`, `/help`, querying MongoDB directly, dispatch split into `process_update()` for testability). All three files that build `parse_mode="HTML"` Telegram messages (`bot.py`, `telegram_commands.py`, `daily_report.py`) escape every attacker-controlled field via their own local `_esc()` helper (`html.escape`, `None`-safe) before interpolating it — messages are built with f-strings, so any NEW field added to any alert/report message must go through `_esc()` too, or it reopens the same HTML-injection hole. `telegram_commands.py`'s `process_update()` also rejects any message whose `chat.id` doesn't match the configured `TELEGRAM_CHAT_ID` before dispatching a command — otherwise anyone who could message the bot could pull `/brute`'s plaintext attacker-tried passwords. `notify_log_setup.py` is the notifier-side twin of `parser/log_setup.py` (deliberately a different filename — both directories are on `sys.path` simultaneously in tests, and two identically-named modules would collide in Python's module cache), writing to `logs/notifier.log`; used by `realtime_alert.py`, `daily_report.py`, `bot.py`, and `telegram_commands.py`.
- **dashboard/** — static HTML/CSS/vanilla JS (no build step, no framework). `js/data.js` is the only file that talks to the API (`API_URL` hardcoded to `http://localhost:8000`); `js/app.js` and `js/charts.js` render what `data.js` fetches. Served via `live-server` on port 8080. Every `innerHTML` assignment across `index.html`/`attacks.html`/`stats.html`/`map.html`/`search.html` escapes attacker-controlled fields via `js/escape.js`'s `escapeHtml()` before interpolating them — same rule as the Telegram `_esc()` helpers: a new field written into any of these templates must go through `escapeHtml()` too.

Both `parser/` and `notifier/` duplicate their own `parse_event`/`get_geo` logic against the same Cowrie log rather than sharing a module — when changing event-parsing behavior (new event types, new fields), update it in both `parser/log_watcher.py`/`parser/parser.py` and `notifier/realtime_alert.py`, or the two collections' documents will drift out of sync.

MongoDB document shape (collection `honeypot.attacks`), as produced by every parser above:
```
timestamp, src_ip, event, username, password, command, session, sensor,
country, country_code, city, latitude, longitude, alerted, created_at
```

## Running the system

Each component (`parser/`, `notifier/`) has its own Python venv and `requirements.txt`; there is no shared/root venv.

```bash
bash setup.sh    # first-time only: drops the DB, creates parser/ and notifier/ venvs, installs deps
bash start.sh    # starts MongoDB, Cowrie, FastAPI, dashboard, realtime alert, daily report,
                 # cleanup, telegram commands bot, and a 30s healthcheck loop — all as background
                 # nohup processes under /tmp/*.log
```

`start.sh` and `healthcheck.sh` kill-and-restart each Python watcher by matching on process name (`pkill -f realtime_alert.py`, etc.) — there's no supervisor/systemd unit for the app-level processes, only for `mongod`. `healthcheck.sh` polls every service every 30s and sends a Telegram alert on failure and on recovery.

Running a single piece manually (after activating its venv):
```bash
cd parser && source venv/bin/activate
python parser.py                              # one-shot import of honeypot/sample_log.json (drops collection first)
python log_watcher.py                         # tail real Cowrie log -> Mongo (alerted=False)
uvicorn main:app --host 0.0.0.0 --port 8000   # API only
python cleanup.py                             # 30-day retention loop

cd notifier && source venv/bin/activate
python realtime_alert.py       # tail real Cowrie log -> Mongo (alerted=True) + Telegram push
python daily_report.py         # sends one report immediately, then schedules 08:00 daily
python telegram_commands.py    # bot command long-poller

cd dashboard && live-server . --port=8080
```

Required env files (gitignored, not present in a fresh clone):
- `notifier/.env` (see `notifier/.env.example`) — `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `ABUSEIPDB_KEY`, `MONGO_URL`/`DB_NAME` (only actually read when running via Docker Compose below — the native venv workflow doesn't need them, see next point).
- `parser/.env.example` documents `MONGO_URL`/`DB_NAME`; `parser/main.py`, `parser/auth.py`, `parser/log_watcher.py`, `parser/cleanup.py`, `notifier/realtime_alert.py`, and `notifier/telegram_commands.py` all read `MONGO_URL`/`DB_NAME` (defaulting to `mongodb://localhost:27017`/`honeypot` if unset). `parser/parser.py` (one-shot demo-seed importer) still hardcodes the URL — don't assume changing `.env` affects it, since it's a manual seed tool, not a long-running service.
- `LOG_FILE` (Cowrie's log path) in `parser/log_watcher.py`, `notifier/realtime_alert.py`, and `notifier/daily_report.py`, and the GeoIP `.mmdb` path in `notifier/realtime_alert.py`'s own `get_geo()`, are now overridable via `COWRIE_LOG_FILE`/`GEOIP_DB_PATH` env vars (falling back to the same hardcoded `~/Honeypot-Monitor/...` paths as before when unset) — added so the Docker Compose setup below can point them at bind-mounted paths instead of assuming the container's home directory happens to contain a `Honeypot-Monitor` checkout.

## Docker Compose (optional, alongside the native venv workflow)

`docker-compose.yml` at the repo root containerizes `mongo` + every `parser/`/`notifier/` long-running service + `dashboard/` (nginx serving the static files) — see SETUP.md for the run commands. Deliberately does **not** include Cowrie itself (bind low ports/Twisted-reactor-in-a-container is extra complexity, and the submodule already has its own separate-history story per the safety notes elsewhere) - Cowrie keeps running natively exactly as it does today, and the containerized watchers read its log/GeoIP files through read-only bind mounts (`COWRIE_LOG_FILE`/`GEOIP_DB_PATH` above) rather than copying them into the image. This is an *additional* way to run the stack, not a replacement — the pytest suite's fixtures (`fresh_app`, `live_stack`, `e2e_*`) all still spawn native venv subprocesses and are unaffected by any of this. `parser/log_setup.py`/`notifier/notify_log_setup.py` compute their log directory as two levels above their own file, which resolves to `/logs` inside these containers (their `Dockerfile`s put the code straight at `/app`) — a surprising-looking mount point in `docker-compose.yml`, explained here rather than left as a mystery.

GeoIP database (`parser/geoip/GeoLite2-City.mmdb`) is gitignored and must be downloaded separately (see SETUP.md) before geo enrichment works; without it, `get_geo()` fails closed to `"Unknown"`/`0,0`.

## Observability (Prometheus/Grafana)

`parser/main.py` exposes `GET /metrics` (Prometheus text format) directly on `app`, not on `api_router` - it must stay reachable with no login cookie (Prometheus can't authenticate against the JWT/cookie flow) and isn't subject to `auth.check_api_rate_limit`. Metric definitions live in `parser/metrics.py`, not `main.py`, specifically so `auth.py` can import and increment `API_RATE_LIMIT_REJECTIONS` without a circular import. HTTP request count/latency are recorded by a hand-rolled `@app.middleware("http")` in `main.py` (not the `prometheus-fastapi-instrumentator` package - its current release requires a newer `starlette` than the pinned `fastapi==0.115.0` needs, and installing it broke that pin). Business gauges (`honeypot_attacks_total`, `honeypot_attacks_by_event_total`, `honeypot_pending_alerts`) are computed live from MongoDB at scrape time via a custom `prometheus_client` `Collector` (`main.py`'s `_MongoStatsCollector`), registered through `metrics.register_mongo_stats_collector()` rather than a bare `REGISTRY.register()` call - the register/replace helper exists because `fresh_app`/`fresh_module` re-import `main.py` per test while prometheus_client's default `REGISTRY` is a real process-wide singleton, so a bare second registration would either raise `ValueError` or (if swallowed) leave `/metrics` permanently bound to the first test's already-discarded mongomock collection.

`docker-compose.yml`'s `mongodb-exporter` (official `percona/mongodb_exporter` image, `--collector.diagnosticdata`) exposes MongoDB's own metrics (`mongodb_up`, `mongodb_ss_connections`, `mongodb_ss_opcounters`, ...) with zero application code changes. `prometheus` scrapes both `parser-api:8000/metrics` and `mongodb-exporter:9216/metrics` per `monitoring/prometheus.yml`. `grafana` auto-provisions a `Prometheus` datasource (pinned `uid: prometheus` in `monitoring/grafana/provisioning/datasources/prometheus.yml` - deliberately not left to Grafana's auto-generated UID, so the dashboard JSON's datasource references stay correct across environments) and the starter dashboard `monitoring/grafana/dashboards/honeypot-overview.json`, both of which were built and exported from a real running Grafana instance (not hand-typed) to guarantee the JSON is schema-valid. This only instruments `parser-api` + MongoDB - the 5 other long-running scripts (`log_watcher.py`, `cleanup.py`, `realtime_alert.py`, `daily_report.py`, `telegram_commands.py`) are not instrumented (explicit scope decision, ask before adding).

## Key API endpoints (parser/main.py)

`/api/stats`, `/api/attacks` (supports `start_date`/`end_date`), `/api/top-ips`, `/api/top-passwords`, `/api/top-usernames`, `/api/brute-force` (flags `HIGH`/`MEDIUM`/`LOW` by failed-attempt count), `/api/map-data`, `/api/search?ip=`, `/api/export/csv`, `/api/stats/hourly`, `/api/stats/countries`, `/api/alerts/pending` (marks returned docs `alerted: True` as a side effect — calling it consumes the queue), `/api/auth-log` and `/api/auth-log/verify` (see the audit-log section below). `GET /metrics` (Prometheus scrape endpoint, see the observability section below) is on `app` directly, not `api_router` — no login cookie, no rate limit.

All of the above are registered on `api_router` (an `APIRouter(prefix="/api")` included into `app`), not directly on `app` - this is what applies `auth.check_api_rate_limit` (a generic per-IP fixed-window cap, default 100 requests/60s, atomic via `find_one_and_update`'s `$inc`) to every one of them without repeating a dependency on each route; a new `/api/*` endpoint added later inherits the rate limit automatically just by being registered on `api_router` instead of `app`. This is separate from `auth.check_rate_limit`, which only guards `/auth/login` and is keyed by `(ip, username)` rather than `ip` alone.

## Auth roles (admin / viewer)

`users` documents have a `role` field (`"admin"` or `"viewer"`, see `auth.ROLE_ADMIN`/`auth.ROLE_VIEWER`); accounts created before this field existed have none and default to `"admin"` (`auth.DEFAULT_ROLE`) rather than being locked out. Role is embedded in the access-token JWT at login and re-read from Mongo at every `/auth/refresh`, so a role change takes effect on that user's next refresh without needing to revoke anything. `auth.require_admin` (vs. the ordinary `auth.get_current_user`) gates `/api/export/csv`, `/api/alerts/pending`, `/api/auth-log`, and `/api/auth-log/verify` — `/api/alerts/pending` is GET but mutates (`alerted: True`), which is why it's admin-only despite reading like a query. All other `/api/*` endpoints are readable by both roles. `parser/create_admin.py --role viewer` (or `parser/create_viewer.py`, a thin wrapper) creates a read-only account; default with no flag is `admin`.

## Tamper-evident audit log (`auth_log`)

Every login attempt is recorded in `auth_log` via `auth.log_auth_event()`, and every entry is hash-chained: each document stores `seq`, `prev_hash` (the previous entry's `entry_hash`), and its own `entry_hash` — a SHA-256 over its own fields plus `prev_hash` (`auth._auth_log_canonical_bytes`). This doesn't stop someone with direct database access from editing or deleting a row (nothing running only inside the app can prevent that), but it makes it *detectable*: changing or removing any entry breaks the chain from that point forward. `auth.verify_auth_log_integrity()` (exposed as `GET /api/auth-log/verify`, admin-only) walks the whole chain and reports the exact `seq` where it broke, if any; `GET /api/auth-log` (also admin-only) lists entries newest-first for human review, with `prev_hash`/`entry_hash` excluded from the response (plumbing, not something the dashboard needs to render). Two logins racing to append use MongoDB's unique index on `seq` as an atomic compare-and-swap: the loser gets a `DuplicateKeyError` and retries against the new tip, rather than forking the chain. Entries logged before this feature existed have no `seq` field at all (a real one from 2026-07-28 predates it) — both `log_auth_event()` and `verify_auth_log_integrity()` filter on `{"seq": {"$exists": True}}` so a legacy entry is skipped rather than crashing the next login or being reported as a broken link; the chain simply starts fresh at `seq: 0`.
