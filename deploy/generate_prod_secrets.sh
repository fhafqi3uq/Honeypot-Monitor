#!/bin/bash
# Sinh secrets/ THẬT cho VPS production - không copy secrets dev từ máy
# local. Gói lại đúng các lệnh trong secrets/README.md, thêm 2 việc
# README không tự làm: (1) từ chối ghi đè nếu secrets/ đã có nội dung (tránh
# vô tình regenerate mongo creds - đổi sau lần bootstrap đầu tiên của
# container mongo không có tác dụng gì trừ `docker compose down -v`, việc
# đó xoá sạch dữ liệu), (2) prompt nhập Telegram/AbuseIPDB thay vì để trống
# placeholder dễ quên điền.
#
# Dùng: bash deploy/generate_prod_secrets.sh [--force]
set -euo pipefail

cd "$(dirname "$0")/.."
FORCE="${1:-}"

if [ -d secrets ] && [ -n "$(find secrets -maxdepth 1 -name '*.txt' -o -name '*.env' 2>/dev/null)" ] && [ "$FORCE" != "--force" ]; then
    echo "secrets/ đã có sẵn file bí mật. Không ghi đè để tránh mất mongo creds" >&2
    echo "đang dùng thật (đổi sau lần bootstrap đầu của mongo không có tác dụng" >&2
    echo "trừ 'docker compose down -v', việc đó XOÁ SẠCH dữ liệu)." >&2
    echo "Chạy lại với --force nếu bạn chắc chắn muốn tạo mới toàn bộ." >&2
    exit 1
fi

mkdir -p secrets

echo "==> JWT signing key"
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/jwt_secret_key.txt

read -rp "Telegram bot token (@BotFather, để trống nếu chưa có): " tg_token
echo -n "$tg_token" > secrets/telegram_token.txt

read -rp "Telegram chat ID (để trống nếu chưa có): " tg_chat_id
echo -n "$tg_chat_id" > secrets/telegram_chat_id.txt

read -rp "AbuseIPDB API key (tuỳ chọn, Enter để bỏ qua - score sẽ luôn là 0): " abuseipdb_key
echo -n "$abuseipdb_key" > secrets/abuseipdb_key.txt

echo "==> MongoDB root credentials"
echo -n "honeypot_root" > secrets/mongo_username.txt
python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/mongo_password.txt

echo "==> MongoDB app (least-privilege) credentials"
echo -n "honeypot_app" > secrets/mongo_app_username.txt
python3 -c "import secrets; print(secrets.token_urlsafe(24))" > secrets/mongo_app_password.txt

echo "==> mongodb-exporter env (dùng root creds - cần clusterMonitor)"
cat > secrets/mongodb_exporter.env <<EOF
MONGODB_USER=$(cat secrets/mongo_username.txt)
MONGODB_PASSWORD=$(cat secrets/mongo_password.txt)
EOF

chmod 600 secrets/*.txt secrets/*.env

cat <<EOF

Đã tạo xong secrets/ (8 file, permission 600). Tiếp theo:
  docker compose up -d --build

Nhắc lại: secrets/*.txt và *.env đã gitignore - đừng commit, đừng copy
sang máy khác qua kênh không mã hoá.
EOF
