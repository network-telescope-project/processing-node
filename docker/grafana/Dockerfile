FROM grafana/grafana:11.6.8

# Pre-install the ClickHouse datasource plugin so it's available on first boot without a restart (avoids the
# GF_INSTALL_PLUGINS race condition). Pinned: newer versions may need a newer Grafana.
RUN grafana cli --pluginsDir /var/lib/grafana/plugins plugins install grafana-clickhouse-datasource 4.21.3
