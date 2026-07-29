#!/usr/bin/env bash
# ==========================================================
# AISOC Enterprise - Open Source One-Click Installer
# ==========================================================

set -e

echo "=========================================================="
echo "  AISOC Enterprise Platform Installation"
echo "=========================================================="

if [ ! -d "venv" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[+] Installing project dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

if [ ! -f ".env" ]; then
    echo "[+] Creating .env configuration from template..."
    cp .env.example .env
fi

echo "=========================================================="
echo "  Installation Complete!"
echo "  Start platform using: ./venv/bin/python web_app.py"
echo "  Navigate to: http://localhost:5000"
echo "=========================================================="
