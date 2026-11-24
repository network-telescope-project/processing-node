#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

NT_USER="telescope"
NT_GROUP="telescope"

CONF_DIR="/etc/network-telescope"
VENV_DIR="${PROJECT_ROOT}/.venv"
ENV_FILE="${PROJECT_ROOT}/.env"
SSH_DIR="/home/${NT_USER}/.ssh"
DOCKER_DIR="${PROJECT_ROOT}/docker"
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.yml"

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
    if ! systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
        err "${svc} is not enabled (would not come back after a reboot): systemctl enable ${svc}"
        ERRORS=$(( ERRORS + 1 ))
    fi
}

ch_query() {        # ch_query <user> <password> <query>
    curl -sf --max-time 10 "http://${CH_HOST}:${CH_PORT}/" -H "X-ClickHouse-User: $1" -H "X-ClickHouse-Key: $2" --data-binary "$3" 2>/dev/null
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

INBOX_DIR="${PCAP_INBOX_DIR:-/var/lib/network-telescope/data/queue}"
ARCHIVE_DIR="${PCAP_ARCHIVE_DIR:-/var/lib/network-telescope/data/archive}"
QUARANTINE_DIR="${PCAP_QUARANTINE_DIR:-/var/lib/network-telescope/data/quarantine}"

# --Clock---------------------------------------------------------------------
if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]; then
    ok "Clock synchronised: $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
else
    warn "Clock is not synchronised by NTP and will slowly drift: $(date -u '+%Y-%m-%d %H:%M:%S') UTC (setup.sh sets it once)"
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
    if ! systemctl is-enabled --quiet docker 2>/dev/null; then
        err "Docker is not enabled: the containers would not come back after a reboot (systemctl enable docker)"
        ERRORS=$(( ERRORS + 1 ))
    fi
else
    err "Docker not running or not installed"
    ERRORS=$(( ERRORS + 1 ))
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

CH_DIR="${CLICKHOUSE_DATA_DIR:-${DOCKER_DIR}/clickhouse}"
if [[ -d "${CH_DIR}/clickhouse_data" ]]; then
    ok "ClickHouse storage exists: ${CH_DIR}"
else
    err "ClickHouse storage missing: ${CH_DIR} - run setup.sh"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Docker compose------------------------------------------------------------
log "Starting Docker Compose stack..."
if docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d; then
    ok "Docker Compose stack started."
else
    err "docker compose up failed"
    ERRORS=$(( ERRORS + 1 ))
fi

for container in nt_clickhouse nt_prometheus nt_grafana nt-geoipupdate; do
    STATE=$(docker inspect -f '{{.State.Status}}{{if .State.Health}} {{.State.Health.Status}}{{end}}' "${container}" 2>/dev/null) || STATE="missing"
    case "${STATE}" in
        "running"|"running healthy") ok "Container ${container}: ${STATE}" ;;
        "running starting")          warn "Container ${container}: ${STATE}" ;;
        *)                           err "Container ${container}: ${STATE} (docker logs ${container})"; ERRORS=$(( ERRORS + 1 )) ;;
    esac
done

# --Clickhouse----------------------------------------------------------------
CH_HOST="${CLICKHOUSE_HOST:-localhost}"
CH_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
CH_USER="${CLICKHOUSE_USER:-telescope}"
CH_PASS="${CLICKHOUSE_PASSWORD:-}"
CH_DB="${CLICKHOUSE_DB:-telescope}"

log "Waiting for ClickHouse on ${CH_HOST}:${CH_PORT}..."
for i in $(seq 1 30); do
    if [[ "$(ch_query "${CH_USER}" "${CH_PASS}" "SELECT 1")" == "1" ]]; then
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
TABLES=" $(ch_query "${CH_USER}" "${CH_PASS}" "SELECT concat(database, '.', name) FROM system.tables WHERE database IN ('${CH_DB}', 'mgmt')" | tr '\n' ' ') " || true
MISSING=""
for table in "${CH_DB}.packets" "${CH_DB}.source_enrichment" "${CH_DB}.pcap_ingest_log" "${CH_DB}.telescope_health" \
             mgmt.sensors mgmt.sensor_prefixes mgmt.ip_branches; do
    [[ "${TABLES}" == *" ${table} "* ]] || MISSING+=" ${table}"
done
if [[ -z "${MISSING}" ]]; then
    ok "ClickHouse schema OK."
else
    err "ClickHouse tables missing:${MISSING}"
    ERRORS=$(( ERRORS + 1 ))
fi
if ch_query nt_reader "${CLICKHOUSE_RO_PASSWORD:-}" "SELECT count() FROM mgmt.sensors" > /dev/null; then
    ok "Read-only user nt_reader (Grafana) can read."
else
    err "Read-only user nt_reader cannot read (CLICKHOUSE_RO_PASSWORD changed? - recreate the clickhouse container)"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Data directories----------------------------------------------------------
for dir in "${INBOX_DIR}" "${ARCHIVE_DIR}" "${QUARANTINE_DIR}"; do
    if [[ ! -d "${dir}" ]]; then
        err "Directory missing: ${dir} - run setup.sh"
        ERRORS=$(( ERRORS + 1 ))
    elif ! runuser -u "${NT_USER}" -- test -w "${dir}"; then
        err "${dir} is not writable by ${NT_USER}"
        ERRORS=$(( ERRORS + 1 ))
    else
        ok "Directory OK: ${dir}"
    fi
done
PENDING=$(find "${INBOX_DIR}" -name "*.pcap" 2>/dev/null | wc -l) || true
[[ ${PENDING} -eq 0 ]] || warn "${PENDING} PCAP file(s) waiting to be processed"
QUARANTINED=$(find "${QUARANTINE_DIR}" -type f ! -name "*.error.txt" 2>/dev/null | wc -l) || true
[[ ${QUARANTINED} -eq 0 ]] || warn "${QUARANTINED} file(s) in quarantine (could not be read): ${QUARANTINE_DIR}"

if [[ -d "${ARCHIVE_DIR}" ]]; then
    FREE_GB=$(( $(df -Pk "${ARCHIVE_DIR}" | awk 'NR==2 {print $4}') / 1024 / 1024 ))
    if [[ ${FREE_GB} -lt ${ARCHIVE_MIN_FREE_GB:-20} ]]; then
        err "Low disk space: ${FREE_GB} GB free, below ARCHIVE_MIN_FREE_GB=${ARCHIVE_MIN_FREE_GB:-20}: the oldest archive files are being deleted"
        ERRORS=$(( ERRORS + 1 ))
    else
        ok "Disk space OK: ${FREE_GB} GB free"
    fi
fi

# TODO change when we'll use a different enriching sources
# --GeoIP databases-----------------------------------------------------------
for edition in GeoLite2-City GeoLite2-ASN; do
    MMDB="${DOCKER_DIR}/geoip/${edition}.mmdb"
    if [[ ! -f "${MMDB}" ]]; then
        err "${edition} missing: check the MaxMind account in ${ENV_FILE} (docker logs nt-geoipupdate)"
        ERRORS=$(( ERRORS + 1 ))
    elif [[ -n "$(find "${MMDB}" -mtime +30)" ]]; then
        warn "${edition} is older than 30 days: it is not being updated (docker logs nt-geoipupdate)"
    else
        ok "${edition} present"
    fi
done

# --Transfer port-------------------------------------------------------------
if (exec 3<>"/dev/tcp/127.0.0.1/${SSH_INGEST_PORT:-8500}") 2>/dev/null; then
    ok "sshd listens on the transfer port ${SSH_INGEST_PORT:-8500}"
else
    err "Nothing listens on the transfer port ${SSH_INGEST_PORT:-8500} - run setup.sh"
    ERRORS=$(( ERRORS + 1 ))
fi

# --WireGuard tunnel of the capturing nodes-----------------------------------
WG_IF="wg-nt"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
HANDSHAKE_MAX_AGE=180
echo ""
check_or_start_service "wg-quick@${WG_IF}"
if [[ "${WG_WRAPPER:-tcp}" == "tcp" ]]; then
    check_or_start_service nt-wstunnel
fi
if [[ "$(ufw status 2>/dev/null)" == "Status: active"* ]]; then
    ok "Firewall active"
else
    err "Firewall is not active - run setup.sh"
    ERRORS=$(( ERRORS + 1 ))
fi
if wg show "${WG_IF}" > /dev/null 2>&1; then
    NOW=$(date +%s)
    PEERS=0
    while read -r pubkey last; do
        PEERS=$(( PEERS + 1 ))
        sensor=$(awk -v pub="${pubkey}" '/^# nt-sensor:/ { id = substr($0, 13) } $1 == "PublicKey" && $3 == pub { print id; exit }' "${WG_CONF}")
        if [[ "${last}" -eq 0 ]]; then
            warn "Tunnel: ${sensor:-unknown peer} has not connected yet"
        elif (( NOW - last > HANDSHAKE_MAX_AGE )); then
            err "Tunnel: ${sensor:-unknown peer} last seen $(( NOW - last )) s ago - is the node down or its tunnel broken?"
            ERRORS=$(( ERRORS + 1 ))
        else
            ok "Tunnel: ${sensor:-unknown peer} connected ($(( NOW - last )) s ago)"
        fi
    done < <(wg show "${WG_IF}" latest-handshakes)
    [[ ${PEERS} -gt 0 ]] || warn "Tunnel: no capturing node registered yet (scripts/add-sensor.sh)"
fi

# --Systemd service-----------------------------------------------------------
echo ""
check_or_start_service nt-processing
check_or_start_service prometheus-node-exporter

METRICS_OK=0
for _ in $(seq 1 10); do
    [[ "$(curl -s --max-time 5 "http://127.0.0.1:${METRICS_PORT:-8000}/metrics")" == *telescope_held_files* ]] && { METRICS_OK=1; break; }
    sleep 1
done
if [[ ${METRICS_OK} -eq 1 ]]; then
    ok "nt-processing answers on its metrics port ${METRICS_PORT:-8000}"
else
    err "nt-processing does not answer on its metrics port ${METRICS_PORT:-8000} (journalctl -u nt-processing)"
    ERRORS=$(( ERRORS + 1 ))
fi

# --What Prometheus reaches----------------------------------------------------
if TARGETS=$(curl -sf --max-time 10 "http://127.0.0.1:9090/api/v1/targets?state=active" \
             | jq -r '.data.activeTargets[] | "\(.health) \(.labels.job) \(.labels.sensor // "-")"' 2>/dev/null); then
    while read -r health job sensor; do
        [[ -n "${health}" ]] || continue
        [[ "${sensor}" == "-" ]] || job="${job} ${sensor}"
        case "${health}" in
            up)      ok "Prometheus reaches ${job}" ;;
            unknown) warn "Prometheus has not scraped ${job} yet" ;;
            *)       err "Prometheus does not reach ${job}"; ERRORS=$(( ERRORS + 1 )) ;;
        esac
    done <<< "${TARGETS}"
else
    err "Prometheus does not answer"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Alerts--------------------------------------------------------------------
[[ -n "${ALERT_WEBHOOK_URL:-}" ]] && ok "Alerts go to the Slack webhook" \
    || warn "ALERT_WEBHOOK_URL is not set: alerts are only in the log (journalctl -u nt-processing)"
[[ -n "${HEARTBEAT_URL:-}" ]] && ok "Heartbeat configured" \
    || warn "HEARTBEAT_URL is not set: nobody notices when this machine itself is down"

# --Summary-------------------------------------------------------------------
echo ""
if [[ ${ERRORS} -eq 0 ]]; then
    ok "All checks passed. Node is healthy and running."
else
    err "${ERRORS} check(s) errored. Review errors above."
    exit 1
fi