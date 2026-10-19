-- Main Database
CREATE DATABASE IF NOT EXISTS telescope;

-- Main Table (packet data)
CREATE TABLE IF NOT EXISTS telescope.packets (
    ts           DateTime64(6, 'UTC') CODEC(DoubleDelta, ZSTD(3)),
    src_ip       IPv4,
    dst_ip       IPv4,
    src_port     UInt16,
    dst_port     UInt16,
    ttl          UInt8,
    ip_len       UInt16,
    ip_id        UInt16,
    ip_df        UInt8,
    flags        UInt8,
    tcp_window   UInt16,
    tcp_seq      UInt32,
    tcp_ack      UInt32,
    tcp_options  LowCardinality(String),
    tcp_mss      UInt16,
    tcp_wscale   UInt8,
    payload_len  UInt16,
    sensor_id    LowCardinality(String),   -- capture node the packet came from (mgmt.sensors)
    pcap_file    LowCardinality(String),   -- file name, unique only together with sensor_id
    INDEX idx_pcap_file pcap_file TYPE bloom_filter GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (toStartOfHour(ts), src_ip, ts);


-- Enrichment of the source addresses (GeoIP / ASN), one row per source.
CREATE TABLE IF NOT EXISTS telescope.source_enrichment
(
    ip            IPv4,
    asn           UInt32,
    asn_name      LowCardinality(String),
    country_code  LowCardinality(String),
    country_name  LowCardinality(String),
    city          String
)
ENGINE = MergeTree
ORDER BY ip;


-- One row per handled PCAP file (ingested, empty or quarantined)
CREATE TABLE IF NOT EXISTS telescope.pcap_ingest_log
(
    ingested_at  DateTime64(3, 'UTC'),
    sensor_id    LowCardinality(String),
    file_name    String,
    file_sha256  String,
    file_size    UInt64,
    ts_min       Nullable(DateTime64(3, 'UTC')),
    ts_max       Nullable(DateTime64(3, 'UTC')),
    frames       UInt32,
    parsed       UInt32,
    non_ip       UInt32,
    non_tcp      UInt32,
    out_of_scope UInt32,
    malformed    UInt32,
    duplicates   UInt32,
    inserted     UInt32,
    tool_version String,
    status       LowCardinality(String),
    message      String DEFAULT ''
)
ENGINE = MergeTree
ORDER BY (file_sha256, ingested_at);


-- Telescope Health table
-- TODO think about what high-level health data we might store
CREATE TABLE IF NOT EXISTS telescope.telescope_health
(
    ts DateTime('UTC'),
    sensor_id LowCardinality(String),   -- capture node ID
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
ORDER BY (sensor_id, ts)
TTL toDateTime(ts) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;