#!/bin/bash
# NAT public port 80 (HTTP) -> cổng nội bộ của parser/http_honeypot.py (mặc
# định 8899). Giống hệt deploy/expose_cowrie_port22.sh/port23.sh nhưng cho
# trang admin login giả - khớp với bait "var/www/html/admin/login.php" đã
# có sẵn trong honeyfs của Cowrie (xem honeypot/README-honeyfs.md).
#
# Dùng: sudo bash deploy/expose_webtrap_port80.sh [HTTP_HONEYPOT_INTERNAL_PORT=8899]
set -euo pipefail

HTTP_HONEYPOT_INTERNAL_PORT="${1:-8899}"
PUBLIC_PORT=80

if ss -tlnp 2>/dev/null | grep -q ":${PUBLIC_PORT} "; then
    echo "LỖI: đã có gì đó đang bind cổng $PUBLIC_PORT rồi (kiểm tra 'ss -tlnp | grep :80')." >&2
    exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "LỖI: iptables chưa được cài." >&2
    exit 1
fi

echo "==> Thêm rule NAT: public $PUBLIC_PORT -> 127.0.0.1:$HTTP_HONEYPOT_INTERNAL_PORT"
iptables -t nat -A PREROUTING -p tcp --dport "$PUBLIC_PORT" -j REDIRECT --to-port "$HTTP_HONEYPOT_INTERNAL_PORT"

echo "==> Persist rule qua reboot"
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
elif dpkg -l iptables-persistent >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
else
    cat <<EOF

CHƯA PERSIST: cài iptables-persistent để rule này sống qua reboot:
  sudo apt-get install -y iptables-persistent
  sudo netfilter-persistent save

Nếu không cài, rule sẽ mất sau khi VPS restart và cần chạy lại script này.
EOF
fi

cat <<EOF

Đã redirect: internet:$PUBLIC_PORT -> 127.0.0.1:$HTTP_HONEYPOT_INTERNAL_PORT (trang admin login giả)

Xác minh (từ máy khác, sau khi parser/http_honeypot.py đã chạy):
  curl http://<vps-ip>/admin/login.php   # kỳ vọng thấy HTML trang login giả "PaymentCo Admin Panel"

QUAN TRỌNG: nhớ allow cổng nội bộ (không phải 80) trong ufw - xem
deploy/setup_firewall.sh, đã tự bao gồm cổng này.
EOF
