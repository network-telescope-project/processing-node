#!/usr/bin/env bash
set -e

SYSTEM_DEPS=("docker.io" "docker-compose" "python3-venv" "python3-pip")
MISSING_DEPS=()

echo "[*] Auditing PROCESSING node dependencies..."

for pkg in "${SYSTEM_DEPS[@]}"; do
    if ! dpkg -l | grep -q "ii  $pkg "; then
        MISSING_DEPS+=("$pkg")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "[!] Missing: ${MISSING_DEPS[*]}"
    echo "[*] Updating package lists and installing missing dependencies..."
    sudo apt update && sudo apt install -y "${MISSING_DEPS[@]}"
else
    echo "[+] Processing dependencies satisfied."
fi

# Setup Docker Group
if ! groups "$USER" | grep -q "\bdocker\b"; then
    echo "[*] Adding user to docker group..."
    sudo usermod -aG docker "$USER"
    echo "[!] Note: You may need to log out and back in for docker group changes to take effect."
fi

# Setup Python Environment
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
echo "[*] Setting up Python virtual environment..."
if [ ! -d "$PROJECT_ROOT/venv" ]; then
    python3 -m venv "$PROJECT_ROOT/venv"
fi

source "$PROJECT_ROOT/venv/bin/activate"
echo "[*] Updating pip and installing Python libraries..."
pip install --upgrade pip
pip install scapy clickhouse-connect geoip2

echo "[*] Finalizing directory structure..."
mkdir -p "$PROJECT_ROOT/data/queue"

echo -e "\n[DONE] Processing node setup is done."
echo "[>] To start, run: source venv/bin/activate"