#!/bin/bash

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="vuln-scanner"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="${PROJECT_DIR}/venv/bin/python"

echo "=============================================="
echo "  Vulnerability Assessment Scanner — Install"
echo "  by Abbas Khan | github.com/cod735"
echo "=============================================="
echo ""

# Check Python 3.12
if ! command -v python3.12 &>/dev/null; then
    echo "[!] Python 3.12 not found. Please install it first."
    exit 1
fi

echo "[*] Creating virtual environment..."
python3.12 -m venv "${PROJECT_DIR}/venv"

echo "[*] Installing dependencies..."
"${PROJECT_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${PROJECT_DIR}/venv/bin/pip" install --quiet -r "${PROJECT_DIR}/requirements.txt"

echo "[*] Creating data directories..."
mkdir -p "${PROJECT_DIR}/data"

echo "[*] Setting up environment file..."
if [ ! -f "${PROJECT_DIR}/config/.env" ]; then
    mkdir -p "${PROJECT_DIR}/config"
    cat > "${PROJECT_DIR}/config/.env" <<EOF
NVD_API_KEY=
FLASK_PORT=5004
FLASK_SECRET=vuln_scanner_secret_$(openssl rand -hex 8)
EOF
    echo "[*] Created config/.env — add your NVD API key for CVE lookup"
else
    echo "[*] config/.env already exists — skipping"
fi

echo "[*] Installing systemd service..."
sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Vulnerability Assessment Scanner — SOC Dashboard
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=${USER}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PYTHON_BIN} dashboard/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"

echo ""
echo "=============================================="
echo "  Installation complete"
echo ""
echo "  Dashboard : http://localhost:5004"
echo "  Service   : sudo systemctl status ${SERVICE_NAME}"
echo ""
echo "  Run a scan:"
echo "  source venv/bin/activate"
echo "  python main.py <target>"
echo "=============================================="