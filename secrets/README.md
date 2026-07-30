# secrets/

Only used by the Docker Compose workflow (`docker-compose.yml`'s top-level
`secrets:` block) - the native venv workflow (`start.sh`) doesn't need this
directory at all, it reads the same values straight out of `parser/.env` /
`notifier/.env` as before.

Create these 8 files before `docker compose up` (all gitignored - never
commit real values here):

```bash
mkdir -p secrets

# Generate a random JWT signing key:
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret_key.txt

# From @BotFather:
echo -n "<your-telegram-bot-token>" > secrets/telegram_token.txt

# Message your bot once, then check https://api.telegram.org/bot<TOKEN>/getUpdates:
echo -n "<your-telegram-chat-id>" > secrets/telegram_chat_id.txt

# Optional - AbuseIPDB free-tier key (bot.py's check_abuseipdb() just scores
# 0 for every IP if this is left as an empty file):
echo -n "<your-abuseipdb-key>" > secrets/abuseipdb_key.txt

# MongoDB ROOT credentials - admin work only (backups, manual mongosh
# troubleshooting, mongodb-exporter's own metrics access). Bootstrapped by
# the mongo service ONLY on its very first start with an empty data volume
# (MONGO_INITDB_ROOT_USERNAME/_PASSWORD semantics - changing these later
# does nothing until you `docker compose down -v`, which DELETES the
# mongo_data volume). The app itself never uses these - see the app-user
# pair below.
echo -n "honeypot_root"                                       > secrets/mongo_username.txt
python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/mongo_password.txt

# MongoDB APP credentials - what every app service actually connects as.
# mongo-init/create-app-user.sh creates this user automatically (same
# first-start-only window as the root user above) with readWrite on just
# the "honeypot" database - NOT root, so a compromised app container can't
# touch other databases or run admin commands.
echo -n "honeypot_app"                                       > secrets/mongo_app_username.txt
python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/mongo_app_password.txt
```

Each file's content is read by the relevant container at
`/run/secrets/<name>` (Compose's standalone/non-swarm secret support - a
bind-mounted read-only file, not swarm's encrypted secret store) via the
`_read_secret()` helper duplicated in `parser/auth.py`, `parser/log_watcher.py`,
`parser/cleanup.py`, `notifier/bot.py`, `notifier/realtime_alert.py`, and
`notifier/telegram_commands.py`. `parser/main.py` reuses `auth.py`'s copy
rather than duplicating a 3rd time in the same directory.

One more file, NOT part of the 8 above - `mongodb-exporter` (Percona's
Go binary) has no `<NAME>_FILE` convention of its own, so it can't use the
same file-mount mechanism. Create a small plain env file for it instead
(also gitignored, just not file-mounted) - use the ROOT credentials here,
not the app ones: mongodb-exporter's diagnosticdata collector needs
clusterMonitor-level access, broader than the scoped app user has.

```bash
cat > secrets/mongodb_exporter.env <<EOF
MONGODB_USER=$(cat secrets/mongo_username.txt)
MONGODB_PASSWORD=$(cat secrets/mongo_password.txt)
EOF
```
