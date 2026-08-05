#!/bin/bash
# NAT public port 23 (Telnet) -> cổng nội bộ Cowrie (mặc định 2223, khớp
# honeypot/cowrie.cfg's [telnet] listen_endpoints = tcp:2223:interface=0.0.0.0).
# Giống hệt deploy/expose_cowrie_port22.sh nhưng cho Telnet - nhiều botnet
# IoT/router chuyên quét cổng 23 hơn cả 22, mở thêm cổng này giúp honeypot
# bị bot tìm ra và tấn công nhiều hơn.
#
# Dùng: sudo bash deploy/expose_cowrie_port23.sh [COWRIE_INTERNAL_PORT=2223]
set -euo pipefail

COWRIE_INTERNAL_PORT="${1:-2223}"
PUBLIC_PORT=23

if ss -tlnp 2>/dev/null | grep -q ":${PUBLIC_PORT} "; then
    echo "LỖI: đã có gì đó đang bind cổng $PUBLIC_PORT rồi (kiểm tra 'ss -tlnp | grep :23')." >&2
    exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "LỖI: iptables chưa được cài." >&2
    exit 1
fi

echo "==> Thêm rule NAT: public $PUBLIC_PORT -> 127.0.0.1:$COWRIE_INTERNAL_PORT"
iptables -t nat -A PREROUTING -p tcp --dport "$PUBLIC_PORT" -j REDIRECT --to-port "$COWRIE_INTERNAL_PORT"

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

Đã redirect: internet:$PUBLIC_PORT -> 127.0.0.1:$COWRIE_INTERNAL_PORT (Cowrie Telnet)

Xác minh (từ máy khác, sau khi Cowrie đã start với [telnet] enabled = true):
  telnet <vps-ip> 23    # kỳ vọng thấy banner Cowrie giả (hostname "svr04"), không phải telnetd thật
EOF
