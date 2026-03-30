#!/bin/bash

SERVICE_NAME="vuln-scanner"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "=============================================="
echo "  Vulnerability Assessment Scanner — Uninstall"
echo "=============================================="
echo ""

echo "[*] Stopping and disabling service..."
sudo systemctl stop    "${SERVICE_NAME}" 2>/dev/null || true
sudo systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

echo "[*] Removing service file..."
sudo rm -f "${SERVICE_FILE}"
sudo systemctl daemon-reload

echo "[*] Removing virtual environment..."
rm -rf venv

echo ""
echo "[*] Uninstall complete."
echo "[*] Scan data in data/ has been preserved."
echo "[*] To remove data: rm -rf data/"
echo ""