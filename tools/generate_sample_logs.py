"""
Demo driver. Sends realistic sample logs from three different real-world
formats (syslog key-value, JSON, CSV-ish) into the running ULPF instance so
you can watch one framework normalize all three into the same OCSF shape.

Usage:
    python tools/generate_sample_logs.py            # send N good events per source
    python tools/generate_sample_logs.py --bad       # also send malformed/unknown logs
    python tools/generate_sample_logs.py --count 50
"""
import argparse
import json
import random
import socket
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
SQUID_LOG_FILE = BASE_DIR / "data" / "incoming" / "squid_access.log"
HTTP_API = "http://localhost:8080"
SYSLOG_HOST, SYSLOG_PORT = "localhost", 5514

IPS = ["10.1.2.3", "10.1.2.7", "192.168.5.20", "172.16.0.9"]
DESTS = ["192.168.1.5", "192.168.1.10", "8.8.8.8"]


def send_pfsense(n):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(n):
        line = (f"Sep 16 10:22:{random.randint(0,59):02d} pfsense filterlog: "
                f"rule {random.randint(1,50)} {random.choice(['block','pass'])} in on em0 "
                f"src={random.choice(IPS)} dst={random.choice(DESTS)} proto={random.choice(['tcp','udp'])}")
        sock.sendto(line.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
    print(f"[pfsense] sent {n} events via UDP syslog")


def send_suricata(n):
    for _ in range(n):
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "src_ip": random.choice(IPS),
            "dest_ip": random.choice(DESTS),
            "proto": random.choice(["TCP", "UDP"]),
            "event_type": "alert",
        }
        requests.post(f"{HTTP_API}/ingest",
                       json={"channel": "http", "source_hint": "suricata", "raw": event}, timeout=3)
    print(f"[suricata] sent {n} events via HTTP")


def send_squid(n):
    SQUID_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SQUID_LOG_FILE, "a") as f:
        for _ in range(n):
            line = f"{time.time():.3f} {random.choice(IPS)} TCP_MISS/200 GET http://example.com"
            f.write(line + "\n")
    print(f"[squid] appended {n} events to {SQUID_LOG_FILE}")


def send_bad(n):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(n):
        # deliberately unknown format -- no existing parser fingerprint matches this
        garbage = f"###UNKNOWN_DEVICE### code={i} weird_field~~value blah"
        sock.sendto(garbage.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
    print(f"[bad] sent {n} unparseable events via UDP syslog -> should land in DLQ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10, help="events per source")
    ap.add_argument("--bad", action="store_true", help="also send unparseable events to populate the DLQ")
    args = ap.parse_args()

    send_pfsense(args.count)
    send_suricata(args.count)
    send_squid(args.count)
    if args.bad:
        send_bad(max(args.count // 2, 3))

    print("\nDone. Check results with:")
    print("  curl http://localhost:8080/metrics")
    print("  curl 'http://localhost:8080/events/recent?source=pfsense'")
    print("  curl http://localhost:8080/dlq")


if __name__ == "__main__":
    main()
