#!/bin/sh

set -e

SRC="/etc/grafana/provisioning"
DST="/tmp/grafana-provisioning"

# Copy the entire provisioning tree to a writable location
cp -r "${SRC}/." "${DST}"

# Substitute placeholders in datasources.yml
sed \
  -e "s|__CLICKHOUSE_USER__|${CLICKHOUSE_USER:-telescope}|g" \
  -e "s|__CLICKHOUSE_PASSWORD__|${CLICKHOUSE_PASSWORD:-}|g" \
  "${DST}/datasources/datasources.yml" > "${DST}/datasources/datasources.yml.tmp"

mv "${DST}/datasources/datasources.yml.tmp" "${DST}/datasources/datasources.yml"

# Tell Grafana to use our substituted copy
export GF_PATHS_PROVISIONING="${DST}"

exec /run.sh
