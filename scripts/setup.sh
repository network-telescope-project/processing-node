#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

NT_USER="telescope"
NT_GROUP="telescope"

DATA_DIR="/var/lib/network-telescope/data/queue"
ARCHIVE_DIR="/var/lib/network-telescope/data/archive"
QUARANTINE_DIR="/var/lib/network-telescope/data/quarantine"
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

if [[ "${PROJECT_ROOT}" == /home/* || "${PROJECT_ROOT}" == /root/* ]]; then
    err "The repo is in ${PROJECT_ROOT}, which user '${NT_USER}' cannot read."
    err "Clone it to /opt/network-telescope and run scripts/setup.sh from there."
    exit 1
fi

# --Dependencies--------------------------------------------------------------
SYSTEM_DEPS=("python3" "python3-venv" "python3-pip" "curl" "git" "rsync" "openssh-server" "ufw" "jq" "gettext-base")
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

mkdir -p "${DATA_DIR}" "${ARCHIVE_DIR}" "${QUARANTINE_DIR}" "${CONF_DIR}"
chown -R "${NT_USER}:${NT_USER}" "${DATA_DIR}" "${ARCHIVE_DIR}" "${QUARANTINE_DIR}"

# --Environment file---------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
    cp "${PROJECT_ROOT}/.env.example" "${ENV_FILE}"
    warn ".env created from .env.example - edit before running start.sh"
    warn "  sudo nano ${ENV_FILE}"
else
    log ".env already exists."
fi
chown "root:${NT_GROUP}" "${ENV_FILE}"
chmod 640 "${ENV_FILE}"
set -a; source "${ENV_FILE}"; set +a

# Docker bind-mount dirs
DOCKER_DIR="${PROJECT_ROOT}/docker"
CH_DIR="${CLICKHOUSE_DATA_DIR:-${DOCKER_DIR}/clickhouse}"
mkdir -p \
    "${CH_DIR}/clickhouse_data" \
    "${CH_DIR}/clickhouse_logs" \
    "${DOCKER_DIR}/grafana/grafana_data" \
    "${DOCKER_DIR}/geoip" \
    "${DOCKER_DIR}/prometheus/targets"
chown -R 101:101 \
    "${CH_DIR}/clickhouse_data" \
    "${CH_DIR}/clickhouse_logs" 2>/dev/null || true
chown "${NT_USER}:${NT_GROUP}" "${DOCKER_DIR}/prometheus/targets"
ok "Docker bind-mount directories created."

# --Python virtual environment-----------------------------------------------
if [ ! -d "${VENV_DIR}" ]; then
    log "Setting up Python virtual environment: ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
    "${VENV_DIR}/bin/pip" install --quiet -r "${PROJECT_ROOT}/requirements.txt"
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
    ok "Generated prometheus.yml"
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

warn "Capturing nodes are added with scripts/add-sensor.sh"

SSH_PORT="${SSH_INGEST_PORT:-8500}"
listening() { [[ -n "$(ss -ltnH "sport = :$1")" ]]; }
if listening "${SSH_PORT}"; then
    ok "sshd already listens on port ${SSH_PORT}."
else
    if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        # Ubuntu socket activation
        SSH_UNIT="ssh.socket"
        SSH_DROPIN="/etc/systemd/system/ssh.socket.d/nt-transfer-port.conf"
        mkdir -p "$(dirname "${SSH_DROPIN}")"
        printf '[Socket]\nListenStream=%s\n' "${SSH_PORT}" > "${SSH_DROPIN}"
    else
        SSH_UNIT="ssh"
        SSH_DROPIN="/etc/ssh/sshd_config.d/nt-transfer-port.conf"
        printf 'Port 22\nPort %s\n' "${SSH_PORT}" > "${SSH_DROPIN}"
        sshd -t || { rm -f "${SSH_DROPIN}"; err "sshd config check failed - change reverted."; exit 1; }
    fi
    systemctl daemon-reload
    systemctl restart "${SSH_UNIT}"
    sleep 1
    if listening 22 && listening "${SSH_PORT}"; then
        ok "sshd listens on 22 and ${SSH_PORT}."
    else
        rm -f "${SSH_DROPIN}"
        systemctl daemon-reload
        systemctl restart "${SSH_UNIT}"
        err "sshd does not listen on both 22 and ${SSH_PORT} - change reverted."
        exit 1
    fi
fi

# TODO grafana dashboard is complete shit - has to be remade

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
Environment=PROMETHEUS_TARGETS_FILE=${DOCKER_DIR}/prometheus/targets/capturing-nodes.json
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

# --Firewall-----------------------------------------------------------------
if [[ -z "${MGMT_ALLOW_FROM:-}" ]]; then
    err "MGMT_ALLOW_FROM is not set in ${ENV_FILE} (networks allowed to ssh to port 22) - not enabling the firewall."
    exit 1
fi
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow proto tcp from "${MGMT_ALLOW_FROM}" to any port 22 comment "nt-mgmt-ssh" > /dev/null
# Prometheus (in a Docker bridge network) scrapes the pipeline's /metrics on the host
ufw allow proto tcp from 172.16.0.0/12 to any port "${METRICS_PORT:-8000}" comment "nt-docker-metrics" > /dev/null

if ufw status | grep -q "^Status: active"; then
    ok "Firewall already active - rules updated."
else
    systemd-run --quiet --unit=nt-ufw-rollback --on-active=5min /usr/sbin/ufw disable
    ufw --force enable > /dev/null
    warn "Firewall enabled; it disables itself in 5 minutes unless you confirm."
    warn "Open a NEW ssh session to this node now (keep this one open), then answer here."
    read -r -p "Does the new session work? [y/N] " ANSWER
    systemctl stop nt-ufw-rollback.timer
    if [[ "${ANSWER}" =~ ^[Yy]$ ]]; then
        ok "Firewall confirmed."
    else
        ufw disable > /dev/null
        err "Firewall disabled again. Fix MGMT_ALLOW_FROM in ${ENV_FILE} and re-run setup.sh."
        exit 1
    fi
fi

ok "\n[DONE] Processing node setup is done."
echo ""
echo -e "\033[1;33mNext steps:\033[0m"
echo -e "\033[1;33m   1. Edit ${ENV_FILE}\033[0m"
echo -e "\033[1;33m   2. Run: sudo ./scripts/start.sh\033[0m"
echo -e "\033[1;33m   3. Register each capturing node: run the 'add-sensor.sh' command that its setup script prints\033[0m"
echo -e "\033[1;33m   4. The capturing nodes ask you to confirm this SSH host key on their first setup:\033[0m"
echo -e "\033[1;33m      $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || echo 'ed25519 host key not found')\033[0m"