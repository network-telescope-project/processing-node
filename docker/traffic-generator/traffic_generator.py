import os
import random
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [traffic-gen] %(message)s")
log = logging.getLogger(__name__)

# Suppress scapy banner
import logging as _l
_l.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import IP, TCP, UDP, send, conf

conf.verb = 0  # silence per-packet output

TARGET_IP = os.environ.get("TARGET_IP", "127.0.0.1")
PPS = int(os.environ.get("PACKETS_PER_SECOND", "100"))
INTERVAL = 1.0 / PPS

# Realistic source IPs — public ranges that look like IBR scanners
# (Shodan, Censys, Mirai-style botnets, academic scanners)
SOURCE_RANGES = [
    ("198.108.0.0", "198.108.255.255"),
    ("45.33.0.0",   "45.33.255.255"),
    ("104.131.0.0", "104.131.255.255"),
    ("66.240.192.0","66.240.223.255"),
    ("71.6.128.0",  "71.6.143.255"),
    ("89.248.160.0","89.248.175.255"),
    ("185.220.0.0", "185.220.255.255"),
    ("193.32.127.0","193.32.127.255"),
]

# Common TCP ports targeted by IBR
TCP_PORTS = [
    22, 23, 25, 80, 443, 445, 3389,    # SSH, Telnet, SMTP, HTTP, HTTPS, SMB, RDP
    8080, 8443, 1433, 3306, 5432,       # alt-HTTP, MSSQL, MySQL, PostgreSQL
    21, 110, 143, 993, 995,             # FTP, POP3, IMAP
    6379, 27017, 11211,                 # Redis, MongoDB, Memcached
    9200, 2375,                         # Elasticsearch, Docker API
]

# Common UDP ports targeted by IBR
UDP_PORTS = [
    53, 123, 161, 1900, 137, 5353,     # DNS, NTP, SNMP, SSDP, NetBIOS, mDNS
    69, 514, 623,                       # TFTP, syslog, IPMI
]


def _rand_ip() -> str:
    lo_int, hi_int = random.choice(SOURCE_RANGES)
    lo = [int(x) for x in lo_int.split(".")]
    hi = [int(x) for x in hi_int.split(".")]
    return ".".join(str(random.randint(lo[i], hi[i])) for i in range(4))


def _rand_sport() -> int:
    return random.randint(1024, 65535)


def make_tcp_syn() -> "scapy packet":
    return (
        IP(src=_rand_ip(), dst=TARGET_IP, ttl=random.randint(32, 128)) /
        TCP(sport=_rand_sport(), dport=random.choice(TCP_PORTS), flags="S",
            window=random.choice([1024, 8192, 65535]),
            seq=random.randint(0, 2**32 - 1))
    )


def make_udp_probe() -> "scapy packet":
    return (
        IP(src=_rand_ip(), dst=TARGET_IP, ttl=random.randint(32, 128)) /
        UDP(sport=_rand_sport(), dport=random.choice(UDP_PORTS)) /
        (b"\x00" * random.randint(4, 32))  # minimal payload
    )


def main():
    log.info(f"Starting traffic generator: target={TARGET_IP}, rate={PPS} pps")
    log.info(f"TCP ports: {len(TCP_PORTS)}, UDP ports: {len(UDP_PORTS)}")

    sent = 0
    last_report = time.time()

    while True:
        # 80% TCP SYN (matches the dumpcap filter), 20% UDP
        if random.random() < 0.8:
            pkt = make_tcp_syn()
        else:
            pkt = make_udp_probe()

        send(pkt, iface="lo", verbose=False)
        sent += 1

        now = time.time()
        if now - last_report >= 10:
            log.info(f"Sent {sent} packets in last 10s ({sent / 10:.1f} pps actual)")
            sent = 0
            last_report = now

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
