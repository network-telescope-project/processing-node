#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

DATA_DIR="${PCAP_INBOX_DIR:-/var/lib/network-telescope/data/queue}"
CONF_DIR="/etc/network-telescope"
VENV_DIR="${PROJECT_ROOT}/.venv"
ENV_FILE="${PROJECT_ROOT}/.env"
SSH_DIR="/home/${NT_USER}/.ssh"
DOCKER_DIR="${PROJECT_ROOT}/docker"
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.yml"

NT_USER="telescope"
NT_GROUP="telescope"

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
err()  { echo -e "\033[1;31m[x]\033[0m $*"; }
require_root() {
    if [[ $EUID -ne 0 ]]; then
       err "This script must be run as root (use sudo)."
       exit 1
    fi
 }
require_root

ERRORS=0

check_or_start_service() {
    local svc="$1"
    if systemctl is-active --quiet "${svc}"; then
        ok "${svc} is running"
    else
        warn "${svc} is not running - starting..."
        systemctl start "${svc}" && ok "${svc} started" || { err "Could not start ${svc}"; ERRORS=$(( ERRORS + 1 )); }
    fi
}

# --env file------------------------------------------------------------------
log "Processing Node Check"
echo ""

if [[ -f "${ENV_FILE}" ]]; then
    ok "Environment file found: ${ENV_FILE}"
    set -a; source "${ENV_FILE}"; set +a
else
    err "Environment file missing: ${ENV_FILE} - run setup.sh first"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Python venv---------------------------------------------------------------
if [[ -x "${VENV_DIR}/bin/python" ]]; then
    ok "Python venv OK: $(${VENV_DIR}/bin/python --version)"
else
    err "Python venv not found at ${VENV_DIR}/bin/python - run setup.sh"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Docker--------------------------------------------------------------------
if command -v docker &>/dev/null && docker info &>/dev/null; then
    ok "Docker running"
else
    err "Docker not running or not installed"
fi

# prometheus.yml
PROM_YML="${DOCKER_DIR}/prometheus/prometheus.yml"
if [[ -f "${PROM_YML}" ]]; then
    ok "prometheus.yml exists."
else
    warn "prometheus.yml missing - regenerating from template..."
    envsubst < "${DOCKER_DIR}/prometheus/prometheus.yml.template" > "${PROM_YML}"
    ok "prometheus.yml generated."
fi

# --Docker compose------------------------------------------------------------
log "Starting Docker Compose stack..."
docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d
ok "Docker Compose stack started."
#[[ -f "${COMPOSE_FILE}" ]] || COMPOSE_FILE="${PROJECT_ROOT}/docker/docker-compose.local.yml"
#
#for svc in clickhouse prometheus grafana; do
#    if docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" \
#        ps --status running "${svc}" 2>/dev/null | grep -q "${svc}"; then
#        ok "Container ${svc} running"
#    else
#        warn "Container ${svc} not running - starting..."
#        docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d "${svc}" \
#            && ok "${svc} started" || err "Could not start ${svc}"
#    fi
#done

# --Clickhouse----------------------------------------------------------------
CH_HOST="${CLICKHOUSE_HOST:-localhost}"
CH_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
CH_USER="${CLICKHOUSE_USER:-telescope}"
CH_PASS="${CLICKHOUSE_PASSWORD:-}"
CH_DB="${CLICKHOUSE_DB:-telescope}"

log "Waiting for ClickHouse on ${CH_HOST}:${CH_PORT}..."
for i in $(seq 1 30); do
    if curl -sf "http://${CH_HOST}:${CH_PORT}/?user=${CH_USER}&password=${CH_PASS}&query=SELECT+1" \
        | grep -q "^1$"; then
        ok "ClickHouse ready."
        break
    fi
    if [[ ${i} -eq 30 ]]; then
        err "ClickHouse not responding after 60s"
        ERRORS=$(( ERRORS + 1 ))
    fi
    sleep 2
done

# Check schema
TABLES=$(curl -sf \
    "http://${CH_HOST}:${CH_PORT}/?user=${CH_USER}&password=${CH_PASS}&database=${CH_DB}&query=SHOW+TABLES" \
    2>/dev/null || echo "")
if echo "${TABLES}" | grep -q "packets"; then
    ok "ClickHouse schema OK (packets table present)."
else
    err "packets table missing - ClickHouse schema not initialised."
    ERRORS=$(( ERRORS + 1 ))
fi

# --Data directory------------------------------------------------------------
if [[ -d "${DATA_DIR}" ]]; then
    ok "PCAP inbox exists: ${DATA_DIR}"
    PENDING=$(find "${DATA_DIR}" -name "*.pcap" 2>/dev/null | wc -l)
    [[ ${PENDING} -gt 0 ]] && warn "  ${PENDING} .pcap file(s) waiting to be processed"
else
    err "PCAP inbox missing: ${DATA_DIR}"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Systemd service-----------------------------------------------------------
echo ""
check_or_start_service nt-processing

# --Summary-------------------------------------------------------------------
echo ""
if [[ ${ERRORS} -eq 0 ]]; then
    ok "All checks passed. Node is healthy and running."
else
    err "${ERRORS} check(s) errored. Review errors above."
    exit 1
fi