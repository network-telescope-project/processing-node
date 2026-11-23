#!/usr/bin/env bash
# Register a capturing node on this processing node: registry entry, WireGuard peer, locked SSH key and firewall rule.
#
#   sudo scripts/add-sensor.sh [--name <sensor_id>] <node_public_ip> <prefix[,prefix...]> "<ssh public key>" "<wireguard public key>"
#
# The capturing node's setup.sh prints this command ready to paste. The sensor id is assigned here (sensor-001, ... or
# --name), never by the node: it is the delivery directory and the sensor_id in ClickHouse, so it must be unique. The node's
# SSH key identifies it: re-running with a key that is already registered keeps its id and tunnel address, replaces its
# WireGuard key and firewall rule (new IP, new WG_WRAPPER) and adds prefixes that are not monitored yet.
#
# The node reaches this machine only through the WireGuard tunnel: it gets a tunnel address here (10.77.0.2 ...), its
# SSH key works only from that address, and Prometheus scrapes it there. The last line printed ("nt-tunnel ...") is
# what the node's setup.sh asks for.

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

WG_IF="wg-nt"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
WG_KEY="/etc/wireguard/${WG_IF}.key"
WG_SERVER_ADDR="10.77.0.1"
WG_NET_PREFIX="10.77.0"

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
err()  { echo -e "\033[1;31m[!]\033[0m ERROR: $*" >&2; }
registry() { (cd "${PROJECT_ROOT}" && runuser -u "${NT_USER}" -- "${VENV_DIR}/bin/python" -m src.registry "$@"); }

peer_field() {      # peer_field <sensor_id> <PublicKey|AllowedIPs>: the value in that sensor's block
    awk -v tag="# nt-sensor:$1" -v key="$2" '
        $0 == tag { inside = 1; next }
        /^# nt-sensor:/ { inside = 0 }
        inside && $1 == key { print $3; exit }' "${WG_CONF}"
}
peer_owner() {      # peer_owner <wireguard public key>: the sensor whose block has it
    awk -v pub="$1" '
        /^# nt-sensor:/ { id = substr($0, 13) }
        $1 == "PublicKey" && $3 == pub { print id; exit }' "${WG_CONF}"
}
remove_peer_block() {
    local tmp
    tmp=$(mktemp "${WG_CONF}.XXXXXX")
    awk -v tag="# nt-sensor:$1" '
        $0 == tag { skip = 1; next }
        /^# nt-sensor:/ { skip = 0 }
        !skip' "${WG_CONF}" > "${tmp}"
    chmod 600 "${tmp}"
    mv "${tmp}" "${WG_CONF}"
}

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
if [[ $# -ne 4 ]]; then
    err "usage: sudo $0 [--name <sensor_id>] <node_public_ip> <prefix[,prefix...]> \"<ssh public key>\" \"<wireguard public key>\""
    exit 1
fi
NODE_IP="$1"; PREFIXES="$2"; PUBLIC_KEY="$3"; WG_PUBKEY="$4"

# --Validate (these values end up in authorized_keys, sed, ufw and the WireGuard configuration)
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
# A WireGuard key is 32 bytes in base64: 43 characters and '=' (the last character carries only 4 bits)
if [[ ! "${WG_PUBKEY}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]]; then
    err "The WireGuard public key must be one 44-character base64 key (wg pubkey)."
    exit 1
fi
RRSYNC=$(command -v rrsync) || { err "rrsync not found (it ships with the rsync package)."; exit 1; }

if [[ ! -f "${ENV_FILE}" ]]; then
    err "Environment file missing: ${ENV_FILE} - run setup.sh first"
    exit 1
fi
if [[ ! -f "${WG_CONF}" || ! -f "${WG_KEY}" ]]; then
    err "WireGuard is not configured (${WG_CONF}) - run setup.sh first"
    exit 1
fi
set -a; source "${ENV_FILE}"; set +a
INBOX="${PCAP_INBOX_DIR:-/var/lib/network-telescope/data/queue}"
SSH_PORT="${SSH_INGEST_PORT:-8500}"
WG_PORT="${WG_PORT:-8501}"
WG_WRAPPER="${WG_WRAPPER:-tcp}"
[[ "${WG_WRAPPER}" =~ ^(tcp|none)$ ]] || { err "WG_WRAPPER must be tcp or none (${ENV_FILE})."; exit 1; }

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

# --Tunnel address: kept for a known sensor, else the first free one---------
WG_OWNER=$(peer_owner "${WG_PUBKEY}")
if [[ -n "${WG_OWNER}" && "${WG_OWNER}" != "${SENSOR_ID}" ]]; then
    err "This WireGuard key is already used by '${WG_OWNER}'."
    exit 1
fi
TUNNEL_ADDR=$(peer_field "${SENSOR_ID}" AllowedIPs)
TUNNEL_ADDR="${TUNNEL_ADDR%/32}"
OLD_WG_PUBKEY=$(peer_field "${SENSOR_ID}" PublicKey)
if [[ -z "${TUNNEL_ADDR}" ]]; then
    for host in $(seq 2 254); do
        if ! grep -q "^AllowedIPs = ${WG_NET_PREFIX}.${host}/32\$" "${WG_CONF}"; then
            TUNNEL_ADDR="${WG_NET_PREFIX}.${host}"
            break
        fi
    done
    [[ -n "${TUNNEL_ADDR}" ]] || { err "No free tunnel address left in ${WG_NET_PREFIX}.0/24."; exit 1; }
fi

# --Registry------------------------------------------------------------------
log "Registering '${SENSOR_ID}' (${NODE_IP}, tunnel address ${TUNNEL_ADDR})..."
if grep -q "^${SENSOR_ID}  " <<< "${SENSORS}"; then
    registry set-sensor "${SENSOR_ID}" --exporter "${TUNNEL_ADDR}:${EXPORTER_PORT}"
    warn "Sensor already registered - exporter updated."
else
    registry add-sensor "${SENSOR_ID}" --description "capture node ${NODE_IP}" --exporter "${TUNNEL_ADDR}:${EXPORTER_PORT}"
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

# --WireGuard peer------------------------------------------------------------
remove_peer_block "${SENSOR_ID}"
printf '%s\n' "# nt-sensor:${SENSOR_ID}" "[Peer]" "PublicKey = ${WG_PUBKEY}" "AllowedIPs = ${TUNNEL_ADDR}/32" "" >> "${WG_CONF}"
if wg show "${WG_IF}" > /dev/null 2>&1; then
    if [[ -n "${OLD_WG_PUBKEY}" && "${OLD_WG_PUBKEY}" != "${WG_PUBKEY}" ]]; then
        wg set "${WG_IF}" peer "${OLD_WG_PUBKEY}" remove
    fi
    wg set "${WG_IF}" peer "${WG_PUBKEY}" allowed-ips "${TUNNEL_ADDR}/32"
else
    warn "${WG_IF} is not up: the peer takes effect when it starts (systemctl start wg-quick@${WG_IF})."
fi

# --Delivery directory and locked SSH key-------------------------------------
install -d -o "${NT_USER}" -g "${NT_GROUP}" -m 755 "${INBOX}/${SENSOR_ID}"

install -d -o "${NT_USER}" -g "${NT_GROUP}" -m 700 "${SSH_DIR}"
touch "${AUTHORIZED_KEYS}"
sed -i "/ nt-sensor:${SENSOR_ID}\$/d" "${AUTHORIZED_KEYS}"
echo "restrict,from=\"${TUNNEL_ADDR}\",command=\"${RRSYNC} -wo ${INBOX}/${SENSOR_ID}\" ${KEY_TYPE} ${KEY_BLOB} nt-sensor:${SENSOR_ID}" \
    >> "${AUTHORIZED_KEYS}"
chown "${NT_USER}:${NT_GROUP}" "${AUTHORIZED_KEYS}"
chmod 600 "${AUTHORIZED_KEYS}"

# --Firewall: this node's public IP may reach the tunnel port-----------------
WG_PROTO=$([[ "${WG_WRAPPER}" == "tcp" ]] && echo tcp || echo udp)
while num=$(ufw status numbered | grep -E "# nt-sensor:${SENSOR_ID}\$" | head -1 | sed -E 's/^\[ *([0-9]+)\].*/\1/'); [[ -n "${num}" ]]; do
    ufw --force delete "${num}" > /dev/null
done
ufw allow proto "${WG_PROTO}" from "${NODE_IP}" to any port "${WG_PORT}" comment "nt-sensor:${SENSOR_ID}" > /dev/null

# --Summary-------------------------------------------------------------------
ok "Sensor '${SENSOR_ID}' ready."
echo "   key       ${FINGERPRINT}"
echo "   tunnel    ${TUNNEL_ADDR}, from ${NODE_IP} to ${WG_PROTO}/${WG_PORT} (wrapper: ${WG_WRAPPER})"
echo "   delivers  ${NT_USER}@${WG_SERVER_ADDR}:${SSH_PORT}, through the tunnel only, into ${INBOX}/${SENSOR_ID}/"
echo "   metrics   ${TUNNEL_ADDR}:${EXPORTER_PORT} (Prometheus picks it up from the registry)"
echo ""
warn "Paste this line into the capturing node's setup.sh:"
echo "nt-tunnel addr=${TUNNEL_ADDR} server=${WG_SERVER_ADDR} key=$(wg pubkey < "${WG_KEY}") port=${WG_PORT} wrapper=${WG_WRAPPER}"
if [[ ${PREFIX_FAILED} -ne 0 ]]; then
    err "Some prefixes were not added (see above); check: python -m src.registry list"
    exit 1
fi
