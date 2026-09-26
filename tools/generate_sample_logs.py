"""
Scenario-based perimeter log simulator for ULPF.

Sends realistic traffic from 8 vendors over the real ingestion channels:
  UDP syslog :5514   pfSense, Cisco ASA, FortiGate, Palo Alto (CSV), Check Point (CEF), Juniper (LEEF)
  HTTP /ingest       Suricata EVE JSON
  File tail          Squid access.log

Scenarios:
  normal  legitimate enterprise baseline
  attack  port scans, exploit attempts, C2 / exfil from one attacker IP
  drift   formats ULPF has no parser for yet (SonicWall, Juniper text, CrowdStrike, pfSense IPv6)
          -> DLQ -> the self-heal watcher proposes parsers within seconds
  demo    scripted ~45 s walkthrough: normal -> attack -> drift

Usage:
  python tools/generate_sample_logs.py --scenario demo
  python tools/generate_sample_logs.py --scenario normal --eps 50 --duration 20
  python tools/generate_sample_logs.py --scenario drift --count 40
  python tools/generate_sample_logs.py --continuous --eps 30         # normal traffic until Ctrl+C
  python tools/generate_sample_logs.py --count 10 --bad              # quick fixed batch per vendor
"""
import argparse
import random
import socket
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import log_samples as S  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
SQUID_LOG_FILE = BASE_DIR / "data" / "incoming" / "squid_access.log"


class Sender:
    def __init__(self, host: str, syslog_port: int, http_api: str, squid_file: Path):
        self.addr = (host, syslog_port)
        self.http_api = http_api.rstrip("/")
        self.squid_file = squid_file
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.http = requests.Session()
        self.squid_file.parent.mkdir(parents=True, exist_ok=True)
        self.counts = {}

    def send(self, item):
        transport, hint, raw = item
        if transport == "syslog":
            self.udp.sendto(S.as_bytes(raw), self.addr)
        elif transport == "http":
            try:
                self.http.post(f"{self.http_api}/ingest", json={"channel": "http", "source_hint": hint, "raw": raw},
                               timeout=3)
            except requests.RequestException:
                pass
        else:
            with open(self.squid_file, "a", encoding="utf-8") as f:
                f.write(raw + "\n")
        self.counts[hint] = self.counts.get(hint, 0) + 1


def pick(scenario: str, attacker: str):
    if scenario == "attack":
        fn = random.choice(S.ATTACK)
        return fn(attack=True, attacker=attacker) if fn is not S.squid else fn(attack=True)
    if scenario == "drift":
        return random.choice(S.DRIFT)()
    return random.choice(S.KNOWN)()


def run(sender: Sender, scenario: str, eps: float, duration: float = 0, count: int = 0, quiet=False):
    interval = 1.0 / max(eps, 0.1)
    attacker = random.choice(S.ATTACKERS)
    start, sent = time.time(), 0
    try:
        while (not duration or time.time() - start < duration) and (not count or sent < count):
            t0 = time.time()
            sender.send(pick(scenario, attacker))
            sent += 1
            if not quiet and sent % max(1, int(eps)) == 0:
                el = time.time() - start
                sys.stdout.write(f"\r  [{scenario}] {sent} events in {el:4.1f}s ({sent / max(el, .001):.0f} EPS)   ")
                sys.stdout.flush()
            time.sleep(max(0.0, interval - (time.time() - t0)))
    except KeyboardInterrupt:
        pass
    if not quiet:
        print()
    return sent


def demo(sender: Sender):
    print("=" * 66)
    print("  ULPF live demo  --  open http://localhost:8080/ alongside")
    print("=" * 66)
    print("\n[1/3] Baseline: 8 vendors, 6 formats -> one OCSF schema (15 s @ 40 EPS)")
    run(sender, "normal", 40, duration=15)
    print("\n[2/3] Incident: one attacker seen by every device (10 s @ 60 EPS)")
    run(sender, "attack", 60, duration=10)
    print("\n[3/3] Drift: 4 unknown formats arrive -> DLQ -> self-heal proposals (15 s @ 8 EPS)")
    run(sender, "drift", 8, duration=15)
    print("\nDone. Per-source counts:", ", ".join(f"{k}={v}" for k, v in sorted(sender.counts.items())))
    print("Now open the Self-heal tab: review a proposal, dry-run it, promote it, watch the DLQ replay.")


def main():
    ap = argparse.ArgumentParser(description="ULPF perimeter log simulator")
    ap.add_argument("--scenario", choices=["normal", "attack", "drift", "demo"], default="normal")
    ap.add_argument("--eps", type=float, default=30, help="events per second (default 30)")
    ap.add_argument("--duration", type=float, default=10, help="seconds to run (default 10)")
    ap.add_argument("--count", type=int, default=0, help="send exactly N events (overrides --duration)")
    ap.add_argument("--continuous", action="store_true", help="run until Ctrl+C")
    ap.add_argument("--bad", action="store_true", help="with --count: also send N drift events")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--syslog-port", type=int, default=5514)
    ap.add_argument("--http-api", default="http://127.0.0.1:8080")
    ap.add_argument("--squid-file", default=str(SQUID_LOG_FILE), help="access.log tailed by the file watcher")
    args = ap.parse_args()

    sender = Sender(args.host, args.syslog_port, args.http_api, Path(args.squid_file))
    if args.scenario == "demo":
        demo(sender)
        return
    if args.count and args.scenario == "normal" and not args.continuous:
        # quick fixed batch: N events from EVERY known vendor (+ N drift events with --bad)
        for fn in S.KNOWN:
            for _ in range(args.count):
                sender.send(fn())
        if args.bad:
            for _ in range(args.count):
                sender.send(random.choice(S.DRIFT)())
        print("Sent:", ", ".join(f"{k}={v}" for k, v in sorted(sender.counts.items())))
        return
    duration = 0 if args.continuous or args.count else args.duration
    n = run(sender, args.scenario, args.eps, duration=duration, count=args.count)
    print(f"Sent {n} events:", ", ".join(f"{k}={v}" for k, v in sorted(sender.counts.items())))


if __name__ == "__main__":
    main()
