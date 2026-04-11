#!/bin/bash
# Cowrie Honeypot Setup Script
# For Ubuntu/WSL

set -e

echo "[*] Cowrie Honeypot Setup Script"
echo "[*] Must be run as non-root user with sudo access"

# Check if running as non-root
if [ "$EUID" -eq 0 ]; then
    echo "[!] Please run as non-root user, not sudo"
    exit 1
fi

# Update & install dependencies
echo "[1/6] Installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git iptables

# Create cowrie user
echo "[2/6] Creating cowrie user..."
if id "cowrie" &>/dev/null; then
    echo "[*] User cowrie already exists"
else
    sudo useradd -m -s /bin/bash cowrie
fi

# Clone Cowrie
echo "[3/6] Cloning Cowrie..."
COWRIE_DIR="/home/cowrie/cowrie"
if [ -d "$COWRIE_DIR" ]; then
    echo "[*] Cowrie already exists at $COWRIE_DIR"
    echo "[*] Pulling latest..."
    cd $COWRIE_DIR && git pull
else
    sudo mkdir -p /home/cowrie
    sudo chown cowrie:cowrie /home/cowrie
    sudo -u cowrie git clone https://github.com/cowrie/cowrie.git $COWRIE_DIR
fi

# Setup virtual environment
echo "[4/6] Setting up Python virtual environment..."
cd $COWRIE_DIR
sudo -u cowrie python3 -m venv cowrie-env
sudo -u cowrie ./cowrie-env/bin/pip install -r requirements.txt

# Copy config
echo "[5/6] Configuring Cowrie..."
if [ ! -f "$COWRIE_DIR/etc/cowrie.cfg" ]; then
    sudo -u cowrie cp $COWRIE_DIR/etc/cowrie.cfg.dist $COWRIE_DIR/etc/cowrie.cfg
fi

# Configure SSH port forwarding (redirect 22 -> 2222)
echo "[6/6] Setting up SSH port redirection..."
# Note: This requires sudo - use iptables to redirect traffic
# For WSL: use Windows firewall rules instead
# For Linux: iptables -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

echo ""
echo "========================================"
echo "[OK] Cowrie installed successfully!"
echo "========================================"
echo ""
echo "To start Cowrie:"
echo "  source /home/cowrie/cowrie/cowrie-env/bin/activate"
echo "  /home/cowrie/cowrie/cowrie-env/bin/cowrie start"
echo ""
echo "To view logs:"
echo "  tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
echo ""
echo "To SSH into honeypot (from another terminal):"
echo "  ssh -p 2222 root@localhost"
echo ""