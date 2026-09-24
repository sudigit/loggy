"""
Scenario-Based Log Simulator for ULPF.

Generates realistic network security telemetry across three channels:
  1. UDP Syslog (:5514)          -> pfSense firewall filter logs
  2. HTTP Ingestion (:8080)      -> Suricata IDS/IPS EVE JSON events
  3. File Watcher (squid_access) -> Squid HTTP proxy access logs

Scenarios supported:
  - normal: Continuous legitimate enterprise baseline traffic.
  - attack: Port scans, brute force, and C2 beaconing attacks.
  - drift:  Unrecognized formats (Cisco ASA, FortiGate, corrupt headers) to populate DLQ.
  - demo:   Scripted 30-second walkthrough (Normal -> Attack -> Drift).

Usage:
  # Quick test batch (backward compatible with original tool):
  python tools/generate_sample_logs.py --count 10
  python tools/generate_sample_logs.py --count 10 --bad

  # Run specific scenarios:
  python tools/generate_sample_logs.py --scenario normal --eps 30 --duration 10
  python tools/generate_sample_logs.py --scenario attack --eps 50 --duration 15
  python tools/generate_sample_logs.py --scenario drift  --count 15

  # Run the full live presentation sequence:
  python tools/generate_sample_logs.py --scenario demo

  # Run continuous background stream:
  python tools/generate_sample_logs.py --continuous --eps 25
"""
import argparse
import json
import random
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
SQUID_LOG_FILE = BASE_DIR / "data" / "incoming" / "squid_access.log"
DEFAULT_HTTP_API = "http://localhost:8080"
DEFAULT_SYSLOG_HOST = "localhost"
DEFAULT_SYSLOG_PORT = 5514

# Realistic enterprise IP pools
INTERNAL_IPS = [
    "10.1.2.15", "10.1.2.32", "10.1.2.45", "10.1.2.88", "10.1.2.105",
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.100",
    "172.16.10.4", "172.16.10.12", "172.16.20.8",
]

EXTERNAL_SERVERS = [
    "8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14",
    "151.101.65.140", "104.244.42.1", "185.199.108.153",
]

ATTACKER_IPS = [
    "198.51.100.23", "203.0.113.19", "185.220.101.5", "45.155.205.233"
]

COMMON_DOMAINS = [
    "github.com", "api.github.com", "google.com", "update.microsoft.com",
    "cloudflare.com", "aws.amazon.com", "internal-auth.corp.local",
]

SUSPICIOUS_DOMAINS = [
    "c2-beacon.darkops.biz", "pastebin.com/raw/d9f8s7", "evil-dyn-dns.ru", "exfil-node.onion.ws"
]


class LogGenerator:
    def __init__(self, syslog_host: str = DEFAULT_SYSLOG_HOST, syslog_port: int = DEFAULT_SYSLOG_PORT,
                 http_api: str = DEFAULT_HTTP_API, squid_file: Path = SQUID_LOG_FILE):
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.http_api = http_api
        self.squid_file = squid_file
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.http_session = requests.Session()
        self.squid_file.parent.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # 1. Normal Traffic Generators
    # -------------------------------------------------------------
    def sample_pfsense_normal(self) -> str:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_SERVERS)
        proto = random.choice(["tcp", "udp"])
        disposition = "pass" if random.random() < 0.92 else "block"
        rule = random.randint(10, 45)
        now_str = time.strftime("%b %d %H:%M:%S")
        return (f"{now_str} pfsense filterlog: rule {rule} {disposition} in on em0 "
                f"src={src} dst={dst} proto={proto}")

    def sample_suricata_normal(self) -> dict:
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "src_ip": random.choice(INTERNAL_IPS),
            "dest_ip": random.choice(EXTERNAL_SERVERS),
            "proto": random.choice(["TCP", "UDP"]),
            "event_type": "alert",
            "alert": {
                "signature": random.choice([
                    "SURICATA STREAM ESTABLISHED",
                    "INFO TLS Handshake Completed",
                    "DNS Standard query response",
                    "HTTP GET 200 OK Response",
                ]),
                "severity": 3,
                "category": "Generic Protocol Command",
            },
        }

    def sample_squid_normal(self) -> str:
        ts = f"{time.time():.3f}"
        src = random.choice(INTERNAL_IPS)
        status = random.choice(["TCP_MISS/200", "TCP_HIT/200", "TCP_REFRESH_MODIFIED/200"])
        domain = random.choice(COMMON_DOMAINS)
        return f"{ts} {src} {status} GET http://{domain}/index.html"

    # -------------------------------------------------------------
    # 2. Attack Scenario Generators
    # -------------------------------------------------------------
    def sample_pfsense_portscan(self, attacker: str = None) -> str:
        attacker = attacker or random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)
        scanned_port = random.choice([21, 22, 23, 25, 80, 135, 443, 445, 1433, 3306, 3389, 8080])
        now_str = time.strftime("%b %d %H:%M:%S")
        # Target firewall drops port scan attempts
        return (f"{now_str} pfsense filterlog: rule 99 block in on em0 "
                f"src={attacker} dst={target} proto=tcp")

    def sample_suricata_threat(self, attacker: str = None) -> dict:
        attacker = attacker or random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)
        threats = [
            ("ET EXPLOIT Cobalt Strike Beaconing Detected", 1, "A Network Trojan was detected"),
            ("ET SCAN Nmap Scripting Engine Probe", 2, "Attempted Information Leak"),
            ("ET WEB_SPECIFIC_APPS Apache Log4j RCE Attempt", 1, "Web Application Attack"),
            ("ET ATTACK_RESPONSE Metasploit Reverse Shell Stager", 1, "A Network Trojan was detected"),
        ]
        sig, sev, cat = random.choice(threats)
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "src_ip": attacker,
            "dest_ip": target,
            "proto": "TCP",
            "event_type": "alert",
            "alert": {
                "signature": sig,
                "severity": sev,
                "category": cat,
            },
        }

    def sample_squid_exfil(self) -> str:
        ts = f"{time.time():.3f}"
        src = random.choice(INTERNAL_IPS)
        status = random.choice(["TCP_MISS/200", "TCP_TUNNEL/200"])
        bad_domain = random.choice(SUSPICIOUS_DOMAINS)
        return f"{ts} {src} {status} POST http://{bad_domain}/upload_payload"

    # -------------------------------------------------------------
    # 3. Drift & Unknown Format Generators (Seeds the DLQ)
    # -------------------------------------------------------------
    def sample_drift_logs(self) -> List[Tuple[str, str, any]]:
        """Returns a list of (channel, source_hint, raw_data) for unmapped devices."""
        cisco_asa = (
            f"%ASA-4-106023: Deny tcp src outside:{random.choice(ATTACKER_IPS)}/51820 "
            f"dst inside:{random.choice(INTERNAL_IPS)}/443 by access-group 'outside_access_in'"
        )
        fortigate = (
            f'date={time.strftime("%Y-%m-%d")} time={time.strftime("%H:%M:%S")} devname="FGT60D" '
            f'type="traffic" subtype="forward" action="deny" srcip={random.choice(ATTACKER_IPS)} '
            f'dstip={random.choice(INTERNAL_IPS)} proto=6 policyid=102'
        )
        malformed_pfsense = (
            f"{time.strftime('%b %d %H:%M:%S')} pfsense filterlog: MALFORMED_HEADER_NO_REGEX_MATCH "
            f"code=BAD_DATA junk=true"
        )
        unknown_json = {
            "vendor": "crowdstrike_falcon",
            "aid": "f3b89081e7d2",
            "event_name": "ProcessRollup2",
            "CommandLine": "powershell.exe -enc SQBYAFMA...",
        }

        return [
            ("syslog", "cisco_asa", cisco_asa),
            ("syslog", "fortigate", fortigate),
            ("syslog", "pfsense_corrupt", malformed_pfsense),
            ("http", "crowdstrike", unknown_json),
        ]

    # -------------------------------------------------------------
    # Transport Dispatchers
    # -------------------------------------------------------------
    def send_syslog(self, raw_line: str):
        self.udp_sock.sendto(raw_line.encode("utf-8"), (self.syslog_host, self.syslog_port))

    def send_http(self, payload: dict, source_hint: str = "suricata"):
        try:
            self.http_session.post(
                f"{self.http_api}/ingest",
                json={"channel": "http", "source_hint": source_hint, "raw": payload},
                timeout=2.0,
            )
        except requests.RequestException:
            pass  # Pipeline might be busy or starting up

    def send_squid(self, raw_line: str):
        with open(self.squid_file, "a") as f:
            f.write(raw_line + "\n")


def run_scenario(gen: LogGenerator, scenario: str, eps: int, duration: float, print_progress: bool = True):
    interval = 1.0 / max(eps, 1)
    end_time = time.time() + duration if duration > 0 else float("inf")
    counts = {"syslog": 0, "http": 0, "file": 0, "drift": 0}
    start_ts = time.time()

    attacker = random.choice(ATTACKER_IPS)

    try:
        while time.time() < end_time:
            tick_start = time.time()

            if scenario == "normal":
                choice = random.random()
                if choice < 0.40:
                    gen.send_syslog(gen.sample_pfsense_normal())
                    counts["syslog"] += 1
                elif choice < 0.75:
                    gen.send_http(gen.sample_suricata_normal())
                    counts["http"] += 1
                else:
                    gen.send_squid(gen.sample_squid_normal())
                    counts["file"] += 1

            elif scenario == "attack":
                choice = random.random()
                if choice < 0.50:
                    gen.send_syslog(gen.sample_pfsense_portscan(attacker))
                    counts["syslog"] += 1
                elif choice < 0.85:
                    gen.send_http(gen.sample_suricata_threat(attacker))
                    counts["http"] += 1
                else:
                    gen.send_squid(gen.sample_squid_exfil())
                    counts["file"] += 1

            elif scenario == "drift":
                # Injects drift logs that fail fingerprinting or regex parsing
                drift_items = gen.sample_drift_logs()
                item = random.choice(drift_items)
                chan, hint, raw_content = item
                if chan == "syslog":
                    gen.send_syslog(raw_content)
                else:
                    gen.send_http(raw_content, source_hint=hint)
                counts["drift"] += 1

            # Sleep to match target EPS rate
            elapsed = time.time() - tick_start
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

            if print_progress and int(time.time() - start_ts) > 0 and int(time.time() - start_ts) % 3 == 0:
                tot = sum(counts.values())
                actual_eps = tot / max(time.time() - start_ts, 0.001)
                sys.stdout.write(
                    f"\r  [{scenario.upper()}] Sent: {tot} events (Syslog: {counts['syslog']}, "
                    f"HTTP: {counts['http']}, File: {counts['file']}, Drift: {counts['drift']}) "
                    f"@ {actual_eps:.1f} EPS   "
                )
                sys.stdout.flush()

    except KeyboardInterrupt:
        if print_progress:
            print("\n  [!] Stopped by user.")

    return counts


def run_demo_walkthrough(gen: LogGenerator):
    """Executes a 30-second scripted presentation walkthrough."""
    print("=" * 65)
    print("  ULPF LIVE DEMONSTRATION WALKTHROUGH (30-second sequence)")
    print("=" * 65)

    print("\n[Phase 1/3] Normal Baseline Telemetry (10s @ 30 EPS)...")
    print("  -> Ingesting standard firewall, proxy, and IDS traffic.")
    c1 = run_scenario(gen, scenario="normal", eps=30, duration=10)
    print(f"\n  Phase 1 complete: {sum(c1.values())} normalized events sent.")

    print("\n[Phase 2/3] Attack Incident Burst (10s @ 60 EPS)...")
    print("  -> Simulating port scans, brute force, and C2 beacons.")
    c2 = run_scenario(gen, scenario="attack", eps=60, duration=10)
    print(f"\n  Phase 2 complete: {sum(c2.values())} attack telemetry events sent.")

    print("\n[Phase 3/3] Drift & Unknown Format Injection (10s @ 15 EPS)...")
    print("  -> Injecting Cisco ASA, FortiGate, and malformed packets into DLQ.")
    c3 = run_scenario(gen, scenario="drift", eps=15, duration=10)
    print(f"\n  Phase 3 complete: {sum(c3.values())} drift events routed to DLQ.")

    total_events = sum(c1.values()) + sum(c2.values()) + sum(c3.values())
    print("\n" + "=" * 65)
    print(f"Demo complete! Total events dispatched: {total_events}")
    print("=" * 65)
    print("Verify results with:")
    print("  1. curl http://localhost:8080/metrics | python -m json.tool")
    print("  2. curl http://localhost:8080/dlq | python -m json.tool")
    print("  3. python -m src.selfheal.review_dlq")


def run_legacy_batch(gen: LogGenerator, count: int, bad: bool):
    """Preserves 100% backward compatibility with original tool."""
    print(f"Sending legacy batch: {count} events per source...")
    for _ in range(count):
        gen.send_syslog(gen.sample_pfsense_normal())
    print(f"[pfsense] sent {count} events via UDP syslog")

    for _ in range(count):
        gen.send_http(gen.sample_suricata_normal())
    print(f"[suricata] sent {count} events via HTTP")

    for _ in range(count):
        gen.send_squid(gen.sample_squid_normal())
    print(f"[squid] appended {count} events to {gen.squid_file}")

    if bad:
        drift_items = gen.sample_drift_logs()
        bad_count = max(count // 2, 3)
        for i in range(bad_count):
            item = drift_items[i % len(drift_items)]
            if item[0] == "syslog":
                gen.send_syslog(item[2])
            else:
                gen.send_http(item[2], source_hint=item[1])
        print(f"[bad] sent {bad_count} unparseable events -> landed in DLQ")

    print("\nDone. Check results with:")
    print("  curl http://localhost:8080/metrics")
    print("  curl 'http://localhost:8080/events/recent?source=pfsense'")
    print("  curl http://localhost:8080/dlq")


def main():
    parser = argparse.ArgumentParser(description="ULPF Scenario-Based Log Simulator")
    parser.add_argument("--scenario", choices=["normal", "attack", "drift", "demo"],
                        help="traffic scenario to simulate")
    parser.add_argument("--eps", type=int, default=30, help="target events per second (default: 30)")
    parser.add_argument("--duration", type=float, default=10.0, help="duration in seconds (0 = infinite)")
    parser.add_argument("--continuous", action="store_true", help="run continuously until Ctrl+C")
    parser.add_argument("--syslog-port", type=int, default=DEFAULT_SYSLOG_PORT, help="syslog UDP port")
    parser.add_argument("--http-api", type=str, default=DEFAULT_HTTP_API, help="HTTP API URL")

    # Backward compatibility arguments
    parser.add_argument("--count", type=int, default=None, help="send fixed batch count (legacy mode)")
    parser.add_argument("--bad", action="store_true", help="include malformed logs in fixed batch")

    args = parser.parse_args()
    gen = LogGenerator(syslog_port=args.syslog_port, http_api=args.http_api)

    if args.count is not None:
        run_legacy_batch(gen, args.count, args.bad)
        return

    if args.scenario == "demo":
        run_demo_walkthrough(gen)
        return

    scenario = args.scenario or "normal"
    duration = 0 if args.continuous else args.duration

    print(f"Starting [{scenario.upper()}] simulation at ~{args.eps} EPS (duration: {'continuous' if duration == 0 else f'{duration}s'})...")
    counts = run_scenario(gen, scenario=scenario, eps=args.eps, duration=duration)
    print(f"\nCompleted! Total sent: {sum(counts.values())} events.")


if __name__ == "__main__":
    main()
