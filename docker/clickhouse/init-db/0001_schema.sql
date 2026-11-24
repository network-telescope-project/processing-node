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
CREATE TABLE IF NOT EXISTS telescope.telescope_health
(
    ts                   DateTime('UTC'),
    sensor_id            LowCardinality(String),
    exporter_up          Nullable(UInt8),           -- node-exporter answers (NULL = not scraped)
    problems             Array(String),
    disk_avail_bytes     Nullable(Float64),
    disk_size_bytes      Nullable(Float64),
    cpu_busy_pct         Nullable(Float64),
    mem_avail_pct        Nullable(Float64),
    net_rx_pps           Nullable(Float64),         -- packets per second received by the NIC
    net_drop_pps         Nullable(Float64),         -- packets per second dropped by the NIC / driver
    softnet_drop_pps     Nullable(Float64),         -- packets per second dropped by the kernel
    disk_io_util         Nullable(Float64),         -- busiest disk (0-1)
    clock_synced         Nullable(UInt8),
    clock_offset_s       Nullable(Float64),
    -- capture nodes only
    capture_running      Nullable(UInt8),
    capture_cpu_pct      Nullable(Float64),
    capture_last_loss    Nullable(UInt64),          -- packets lost by the last capture (within 7 days) that lost any, as dumpcap said when it stopped
    units_down           Nullable(UInt16),          -- our services that are not running
    unsent_files         Nullable(UInt32),          -- closed PCAP files not yet transferred
    unsent_oldest_s      Nullable(UInt32)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (sensor_id, ts)
TTL toDateTime(ts) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;