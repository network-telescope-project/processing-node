-- Main Database
CREATE DATABASE IF NOT EXISTS telescope;

-- Main Table (packet data)
-- TODO remake the table - what we want to save matters
CREATE TABLE IF NOT EXISTS telescope.packets (
    ts DateTime64(3, 'UTC'),
    ip_version UInt8,
    src_ip LowCardinality(String),
    dst_ip LowCardinality(String),
    src_port Nullable(Int32),
    dst_port Nullable(Int32),
    protocol LowCardinality(String),
    ttl UInt8,
    length UInt32,
    flags LowCardinality(String),
    tcp_window UInt16,
    src_asn String,
    src_asn_name String,
    src_country_code LowCardinality(String),
    src_country_name LowCardinality(String),
    src_city String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, dst_port)
SETTINGS allow_nullable_key = 1;    -- TODO deal with the nullable bullshit later


-- Telescope Health table
-- TODO think about what high-level health data we might store
CREATE TABLE IF NOT EXISTS telescope.telescope_health
(
    ts DateTime('UTC'),
    ingestion_pps Float64,    -- packets per second reaching DB
    rx_dropped_rate Float64,    -- NIC rx_dropped per second
    rx_missed_rate Float64, -- NIC rx_missed_errors per second
    rx_fifo_rate Float64,   -- NIC rx_fifo_errors per second
    udp_rx_errors Float64,    -- cumulative UDP Rx errors
    disk_avail_bytes Float64,   -- available bytes in capture dir
    disk_io_util Float64,   -- disk I/O utilisation (0-1)
    dumpcap_cpu_pct Float64,    -- dumpcap CPU usage %
    nic_temp_celsius Float64,   -- NIC temperature
    pps_drop_alert Bool     -- true if >90% PPS drop detected
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;


-- Aggregated View for Dashboards
-- TODO more aggregated views - get inspiration from papers
CREATE MATERIALIZED VIEW IF NOT EXISTS telescope.mv_hourly_country_pkt_count
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, src_country_code)
AS SELECT
    toStartOfHour(ts) AS hour,
    src_country_code,
    count() AS packet_count,
    uniq(src_ip) AS unique_src_ips
FROM telescope.packets
GROUP BY hour, src_country_code;

CREATE MATERIALIZED VIEW IF NOT EXISTS telescope.mv_hourly_protocol_pkt_count
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, protocol)
AS SELECT
    toStartOfHour(ts) AS hour,
    protocol,
    count() AS packet_count
FROM telescope.packets
GROUP BY hour, protocol;

CREATE MATERIALIZED VIEW IF NOT EXISTS telescope.mv_hourly_dst_port_count
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, dst_port)
SETTINGS allow_nullable_key = 1    -- TODO deal with the nullable bullshit later
AS SELECT
    toStartOfHour(ts) AS hour,
    dst_port,
    count() AS packet_count
FROM telescope.packets
WHERE dst_port IS NOT NULL
GROUP BY hour, dst_port;