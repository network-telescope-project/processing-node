-- Management database: the registry of capture nodes (sensors), the address space each one monitors and the
-- branch (passive or active) of every monitored address
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
    version      UInt64 DEFAULT toUnixTimestamp64Micro(now64(6))
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (sensor_id, prefix, valid_from);


-- Branch of every monitored address: passive, r-irregular or r-regular (active)
CREATE TABLE IF NOT EXISTS mgmt.ip_branches
(
    sensor_id    String,
    ip           IPv4,
    branch       LowCardinality(String),    -- passive | r-irregular | r-regular
    flag         LowCardinality(String),
    valid_from   DateTime('UTC'),
    manifest     LowCardinality(String),    -- sha256 of the delivered file
    seed         UInt64
)
ENGINE = MergeTree
ORDER BY (sensor_id, valid_from, ip);
