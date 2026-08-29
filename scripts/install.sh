#!/bin/bash

# Xray-core Management Panel Installation Script
set -e

echo "=========================================="
echo "Installing Xray-core Management Panel..."
echo "=========================================="

# Check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "لطفاً این اسکریپت را با دسترسی root (sudo) اجرا کنید."
  exit 1
fi

INSTALL_DIR="/usr/local/panel"
mkdir -p $INSTALL_DIR

echo "[1/5] Installing dependencies (curl, python3, venv, git)..."
apt-get update && apt-get install -y curl python3 python3-pip python3-venv git unzip

echo "[2/5] Downloading / setting up panel files..."
# Copy current workspace or clone repo
if [ -d "." ]; then
  cp -r ./* $INSTALL_DIR/
fi

cd $INSTALL_DIR

echo "[3/5] Setting up Python virtual environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "[4/5] Installing Xray-core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo "[5/5] Configuring systemd service..."
cp systemd/panel.service /etc/systemd/system/xray-panel.service
systemctl daemon-reload
systemctl enable xray-panel
systemctl restart xray-panel

echo "=========================================="
echo "Installation completed successfully!"
echo "Panel URL: http://<your-server-ip>:8000"
echo "Default Username: admin"
echo "Default Password: admin123"
echo "=========================================="
