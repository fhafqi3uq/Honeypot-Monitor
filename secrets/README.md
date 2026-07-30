# secrets/

Only used by the Docker Compose workflow (`docker-compose.yml`'s top-level
`secrets:` block) - the native venv workflow (`start.sh`) doesn't need this
directory at all, it reads the same values straight out of `parser/.env` /
`notifier/.env` as before.

Create these 4 files before `docker compose up` (all gitignored - never
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
```

Each file's content is read by the relevant container at
`/run/secrets/<name>` (Compose's standalone/non-swarm secret support - a
bind-mounted read-only file, not swarm's encrypted secret store) via the
`_read_secret()` helper in `parser/auth.py` / `notifier/bot.py` /
`notifier/telegram_commands.py`.
