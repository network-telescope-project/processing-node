-- Management database: the registry of capture nodes (sensors) and the address space each one monitors
-- Append-only -> edit with "python -m src.registry", not the DB directly
CREATE DATABASE IF NOT EXISTS mgmt;

CREATE TABLE IF NOT EXISTS mgmt.sensors
(
    sensor_id    String,
    description  String DEFAULT '',
    exporter     String DEFAULT '', -- host:port of the node's node-exporter, scraped by Prometheus ('' = not scraped)
    active       UInt8,             -- 0 = files from this node are held, not ingested
    version      UInt64 DEFAULT toUnixTimestamp64Micro(now64(6))
)
ENGINE = ReplacingMergeTree(version)
ORDER BY sensor_id;


CREATE TABLE IF NOT EXISTS mgmt.sensor_prefixes
(
    sensor_id    String,
    prefix       String,        -- IPv4 network in CIDR notation, a single address as /32
    valid_from   DateTime('UTC'),
    valid_to     Nullable(DateTime('UTC')),   -- NULL = still monitored
    version      UInt64 DEFAULT toUnixTimestamp64Micro(now64(6)),
    mode         LowCardinality(String) DEFAULT 'passive'
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (sensor_id, prefix, valid_from);
