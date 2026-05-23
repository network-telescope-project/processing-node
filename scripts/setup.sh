#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

NT_USER="telescope"
NT_GROUP="telescope"

DATA_DIR="/var/lib/network-telescope/data/queue"
CONF_DIR="/etc/network-telescope"
VENV_DIR="${PROJECT_ROOT}/.venv"
ENV_FILE="${PROJECT_ROOT}/.env"
SSH_DIR="/home/${NT_USER}/.ssh"

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
err()  { echo -e "\033[1;31m[!]\033[0m ERROR: $*" >&2; }
require_root() {
    if [[ $EUID -ne 0 ]]; then
       err "This script must be run as root (use sudo)."
       exit 1
    fi
 }

# --Pre flight----------------------------------------------------------------
require_root

OS=$(. /etc/os-release && echo "${ID}")
if [[ ! "${OS}" =~ ^(ubuntu|debian)$ ]]; then
    err "Only Ubuntu/Debian supported."
    exit 1
fi

# --Dependencies--------------------------------------------------------------
# TODO docker V1 instead of V2
SYSTEM_DEPS=("python3" "python3-venv" "python3-pip" "libpcap-dev" "curl" "git" "rsync" "openssh-server" "ufw" "jq" "gettext-base")
MISSING_DEPS=()

log "Auditing PROCESSING node dependencies..."

for pkg in "${SYSTEM_DEPS[@]}"; do
    if ! dpkg -l | grep -q "ii  $pkg "; then
        MISSING_DEPS+=("$pkg")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    warn "Missing: ${MISSING_DEPS[*]}"
    log "Updating package lists and installing missing dependencies..."
    sudo apt update -qq && sudo apt install -y -qq "${MISSING_DEPS[@]}"
else
    ok "System dependencies satisfied."
fi

# Docker engine + compose v2
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    if ! curl -fsSL --retry 3 --retry-delay 2 https://get.docker.com | sh -e; then
        log "ERROR: Docker installation script failed."
        exit 1
    fi

    systemctl enable --now docker

    ok "Docker installed: $(docker --version)"
else
    ok "Docker: $(docker --version)"
fi

if ! docker compose version &>/dev/null; then
    err "Docker Compose v2 not found. Please install the docker-compose-plugin."
    exit 1
else
    ok "Docker Compose: $(docker compose version)"
fi

# --User and directories-----------------------------------------------------
log "Creating user and directories"
if ! getent group "${NT_GROUP}" &>/dev/null; then
    groupadd --system "${NT_GROUP}"
    ok "Created group '${NT_GROUP}'."
fi

if ! id "${NT_USER}" &>/dev/null; then
    useradd --system --create-home --shell /bin/bash -g "${NT_GROUP}" \
        --comment "Network Telescope capture daemon" "${NT_USER}"
    ok "Created user '${NT_USER}'."
fi

# Setup Docker Group
if ! groups "$NT_USER" | grep -q "\bdocker\b"; then
    log "Adding user to docker group..."
    sudo usermod -aG docker "$NT_USER"
    warn "Note: You may need to log out and back in for docker group changes to take effect."
fi

mkdir -p "${DATA_DIR}" "${CONF_DIR}"
chown -R "${NT_USER}:${NT_USER}" "${DATA_DIR}"

# Docker bind-mount dirs
DOCKER_DIR="${PROJECT_ROOT}/docker"
mkdir -p \
    "${DOCKER_DIR}/clickhouse/clickhouse_data" \
    "${DOCKER_DIR}/clickhouse/clickhouse_logs" \
    "${DOCKER_DIR}/grafana/grafana_data" \
    "${DOCKER_DIR}/geoip"
chown -R 101:101 \
    "${DOCKER_DIR}/clickhouse/clickhouse_data" \
    "${DOCKER_DIR}/clickhouse/clickhouse_logs" 2>/dev/null || true
ok "Docker bind-mount directories created."

# --Environment file---------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
    cp "${PROJECT_ROOT}/.env.example" "${ENV_FILE}"
    warn ".env created from .env.example - edit before running start.sh"
    warn "  nano ${ENV_FILE}"
else
    log ".env already exists."
fi

# --Python virtual environment-----------------------------------------------
if [ ! -d "${VENV_DIR}" ]; then
    log "Setting up Python virtual environment: ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
    "${VENV_DIR}/bin/pip" install --quiet -r "${PROJECT_ROOT}/requirements.txt"
    chown -R "${NT_USER}:${NT_USER}" "${VENV_DIR}"
    ok "Python venv ready."
else
    ok "Python venv exists - refreshing packages."
    "${VENV_DIR}/bin/pip" install --quiet -r "${PROJECT_ROOT}/requirements.txt"
fi

# --prometheus.yml from template---------------------------------------------
PROM_TEMPLATE="${DOCKER_DIR}/prometheus/prometheus.yml.template"
PROM_OUT="${DOCKER_DIR}/prometheus/prometheus.yml"
if [[ -f "${ENV_FILE}" ]]; then
    set -a; source "${ENV_FILE}"; set +a
    envsubst < "${PROM_TEMPLATE}" > "${PROM_OUT}"
    ok "Generated prometheus.yml (capturing node: ${CAPTURING_NODE_IP:-localhost}:${CAPTURING_NODE_EXPORTER_PORT:-9100})"
else
    warn "No .env yet - run setup.sh again after creating .env to generate prometheus.yml"
fi

# --SSH configuration--------------------------------------------------------
log "Configuring SSH for file reception..."
mkdir -p "${SSH_DIR}"
chown "${NT_USER}:${NT_USER}" "${SSH_DIR}"
chmod 700 "${SSH_DIR}"

AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"
if [[ ! -f "${AUTHORIZED_KEYS}" ]]; then
    touch "${AUTHORIZED_KEYS}"
    chown "${NT_USER}:${NT_USER}" "${AUTHORIZED_KEYS}"
    chmod 600 "${AUTHORIZED_KEYS}"
fi

warn "Paste the capturing node's public key into: ${AUTHORIZED_KEYS}"
warn "Run this on the capturing node:"
warn "ssh-copy-id -i ~/.ssh/id_ed25519.pub ${NT_USER}@<THIS_NODE_IP>"
echo ""

# --Firewall-----------------------------------------------------------------
# TODO implement firewall later

# --Systemd service for processing-------------------------------------------
cat > /etc/systemd/system/nt-processing.service <<EOF
[Unit]
Description=Network Telescope - Processing Pipeline
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=${NT_USER}
Group=${NT_GROUP}
WorkingDirectory=${PROJECT_ROOT}
EnvironmentFile=${ENV_FILE}
Environment=GEOIP_DB_DIR=${DOCKER_DIR}/geoip
ExecStart=${VENV_DIR}/bin/python -m src.main
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nt-processing

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nt-processing
ok "Systemd unit 'nt-processing' installed and enabled."

ok "\n[DONE] Processing node setup is done."
echo ""
echo -e "\033[1;33mNext steps:\033[0m"
echo -e "\033[1;33m   1. Edit ${ENV_FILE}\033[0m"
echo -e "\033[1;33m   2. Add the capturing node's SSH public key to ${AUTHORIZED_KEYS}"
echo -e "\033[1;33m   3. Run: sudo ./scripts/start.sh\033[0m"