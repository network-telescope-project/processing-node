FROM grafana/grafana:10.4.2

# Pre-install the ClickHouse datasource plugin so it's available on first boot
# without a restart (avoids the GF_INSTALL_PLUGINS race condition).
RUN grafana cli --pluginsDir /var/lib/grafana/plugins plugins install grafana-clickhouse-datasource

# Copy entrypoint that substitutes env vars into datasources.yml before Grafana starts
COPY entrypoint.sh /entrypoint.sh

USER root
RUN chmod +x /entrypoint.sh
USER grafana

ENTRYPOINT ["/entrypoint.sh"]
