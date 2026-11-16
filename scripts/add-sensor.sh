#!/usr/bin/env bash
# Register a capturing node on this processing node: registry entry, locked SSH key and firewall rule.
#
#   sudo scripts/add-sensor.sh [--name <sensor_id>] <node_public_ip> <prefix[,prefix...]> "<ssh public key>"
#
# The capturing node's setup.sh prints this command ready to paste. The sensor id is assigned here (sensor-001, ... or
# --name), never by the node: it is the delivery directory and the sensor_id in ClickHouse, so it must be unique. The node's
# key identifies it: re-running with a key that is already registered keeps its id and replaces its firewall rule
# (new IP) and adds prefixes that are not monitored yet.

set -euo pipefail

# --Configuration-------------------------------------------------------------
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

NT_USER="telescope"
NT_GROUP="telescope"
VENV_DIR="${PROJECT_ROOT}/.venv"
ENV_FILE="${PROJECT_ROOT}/.env"
SSH_DIR="/home/${NT_USER}/.ssh"
AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"
EXPORTER_PORT=9100

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
err()  { echo -e "\033[1;31m[!]\033[0m ERROR: $*" >&2; }
registry() { (cd "${PROJECT_ROOT}" && runuser -u "${NT_USER}" -- "${VENV_DIR}/bin/python" -m src.registry "$@"); }

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (use sudo)."
    exit 1
fi

NAME=""
if [[ "${1:-}" == "--name" ]]; then
    [[ $# -ge 2 ]] || { err "--name needs a value."; exit 1; }
    NAME="$2"
    shift 2
fi
if [[ $# -ne 3 ]]; then
    err "usage: sudo $0 [--name <sensor_id>] <node_public_ip> <prefix[,prefix...]> \"<ssh public key>\""
    exit 1
fi
NODE_IP="$1"; PREFIXES="$2"; PUBLIC_KEY="$3"

# --Validate (these values end up in authorized_keys, sed and ufw)------------
if [[ -n "${NAME}" && ! "${NAME}" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]]; then
    err "sensor id: 1-32 characters of a-z, 0-9, '-' and '_', starting with a letter or digit."
    exit 1
fi
if ! python3 -c 'import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])' "${NODE_IP}" 2>/dev/null; then
    err "'${NODE_IP}' is not an IPv4 address."
    exit 1
fi
read -r KEY_TYPE KEY_BLOB _ <<< "${PUBLIC_KEY}"
if [[ "${KEY_TYPE:-}" != "ssh-ed25519" || ! "${KEY_BLOB:-}" =~ ^[A-Za-z0-9+/=]+$ ]]; then
    err "The public key must be a single 'ssh-ed25519 AAAA...' line."
    exit 1
fi
if ! FINGERPRINT=$(ssh-keygen -lf /dev/stdin <<< "${KEY_TYPE} ${KEY_BLOB}" 2>/dev/null); then
    err "ssh-keygen does not accept given public key."
    exit 1
fi
RRSYNC=$(command -v rrsync) || { err "rrsync not found (it ships with the rsync package)."; exit 1; }

if [[ ! -f "${ENV_FILE}" ]]; then
    err "Environment file missing: ${ENV_FILE} - run setup.sh first"
    exit 1
fi
set -a; source "${ENV_FILE}"; set +a
INBOX="${PCAP_INBOX_DIR:-/var/lib/network-telescope/data/queue}"
SSH_PORT="${SSH_INGEST_PORT:-8500}"

# --Sensor id: the key identifies the node, the id is assigned here------------
SENSORS=$(registry list)
KEY_OWNER=""
if [[ -f "${AUTHORIZED_KEYS}" ]]; then
    KEY_OWNER=$(awk -v blob="${KEY_BLOB}" '$(NF-1) == blob && $NF ~ /^nt-sensor:/ {sub(/^nt-sensor:/, "", $NF); print $NF; exit}' "${AUTHORIZED_KEYS}")
fi

if [[ -n "${KEY_OWNER}" ]]; then
    if [[ ! "${KEY_OWNER}" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]]; then
        err "${AUTHORIZED_KEYS} has an invalid sensor id '${KEY_OWNER}' for this key; fix it by hand."
        exit 1
    fi
    if [[ -n "${NAME}" && "${NAME}" != "${KEY_OWNER}" ]]; then
        err "This key is already registered as '${KEY_OWNER}'; a sensor id cannot be renamed."
        exit 1
    fi
    SENSOR_ID="${KEY_OWNER}"
    warn "This key is already registered as '${SENSOR_ID}' - updating it."
elif [[ -n "${NAME}" ]]; then
    if grep -q "^${NAME}  " <<< "${SENSORS}" || [[ -e "${INBOX}/${NAME}" ]]; then
        err "Sensor id '${NAME}' is already used by another node."
        exit 1
    fi
    SENSOR_ID="${NAME}"
else
    n=1
    while SENSOR_ID=$(printf 'sensor-%03d' "${n}"); grep -q "^${SENSOR_ID}  " <<< "${SENSORS}" || [[ -e "${INBOX}/${SENSOR_ID}" ]]; do
        n=$(( n + 1 ))
    done
fi

# --Registry------------------------------------------------------------------
log "Registering '${SENSOR_ID}' (${NODE_IP})..."
if grep -q "^${SENSOR_ID}  " <<< "${SENSORS}"; then
    registry set-sensor "${SENSOR_ID}" --exporter "${NODE_IP}:${EXPORTER_PORT}"
    warn "Sensor already registered - exporter updated."
else
    registry add-sensor "${SENSOR_ID}" --description "capture node ${NODE_IP}" --exporter "${NODE_IP}:${EXPORTER_PORT}"
fi

PREFIX_FAILED=0
IFS=',' read -ra PREFIX_LIST <<< "${PREFIXES}"
for prefix in "${PREFIX_LIST[@]}"; do
    if ! out=$(registry add-prefix "${SENSOR_ID}" "${prefix}" 2>&1); then
        grep -q "is already monitored by '${SENSOR_ID}'" <<< "${out}" && continue
        echo "${out}" >&2
        PREFIX_FAILED=1
    fi
done

# --Delivery directory and locked SSH key-------------------------------------
install -d -o "${NT_USER}" -g "${NT_GROUP}" -m 755 "${INBOX}/${SENSOR_ID}"

install -d -o "${NT_USER}" -g "${NT_GROUP}" -m 700 "${SSH_DIR}"
touch "${AUTHORIZED_KEYS}"
sed -i "/ nt-sensor:${SENSOR_ID}\$/d" "${AUTHORIZED_KEYS}"
echo "restrict,from=\"${NODE_IP}\",command=\"${RRSYNC} -wo ${INBOX}/${SENSOR_ID}\" ${KEY_TYPE} ${KEY_BLOB} nt-sensor:${SENSOR_ID}" \
    >> "${AUTHORIZED_KEYS}"
chown "${NT_USER}:${NT_GROUP}" "${AUTHORIZED_KEYS}"
chmod 600 "${AUTHORIZED_KEYS}"

# --Firewall: this node's IP may reach the transfer port----------------------
while num=$(ufw status numbered | grep -E "# nt-sensor:${SENSOR_ID}\$" | head -1 | sed -E 's/^\[ *([0-9]+)\].*/\1/'); [[ -n "${num}" ]]; do
    ufw --force delete "${num}" > /dev/null
done
ufw allow proto tcp from "${NODE_IP}" to any port "${SSH_PORT}" comment "nt-sensor:${SENSOR_ID}" > /dev/null

# --Summary-------------------------------------------------------------------
if [[ ${PREFIX_FAILED} -ne 0 ]]; then
    err "Some prefixes were not added (see above). The key and firewall rule are in place; check: python -m src.registry list"
    exit 1
fi
ok "Sensor '${SENSOR_ID}' ready."
echo "   key       ${FINGERPRINT}"
echo "   delivers  ${NT_USER}@<this node>:${SSH_PORT}, from ${NODE_IP} only, into ${INBOX}/${SENSOR_ID}/"
echo "   metrics   ${NODE_IP}:${EXPORTER_PORT} (Prometheus picks it up from the registry)"
