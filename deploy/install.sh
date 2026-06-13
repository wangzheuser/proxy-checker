#!/bin/bash
set -e

echo "=== VPN Proxy Checker - Install Script ==="
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found"
    exit 1
fi

# Create directory
INSTALL_DIR="/opt/proxy-checker"
mkdir -p "$INSTALL_DIR"

# Install dependencies
echo "[1/4] Installing Python dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

# Copy files
echo "[2/4] Copying files..."
cp server.py index.html app.js requirements.txt "$INSTALL_DIR/"

# Install systemd service
echo "[3/4] Installing systemd service..."
cp deploy/vpntest.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable vpntest

# Start service
echo "[4/4] Starting service..."
systemctl restart vpntest

echo ""
echo "=== Done! ==="
echo "Service: systemctl status vpntest"
echo "Logs:    journalctl -u vpntest -f"
IP=$(hostname -I | awk '{print $1}')
echo "Web UI:  http://${IP}:8888/"
