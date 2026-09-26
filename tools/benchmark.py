"""
Throughput benchmark -- evidence for the "billions of events per day" claim.

Measures, on ONE worker process / core:
  engine    parse + normalize + enrich + JSON-Schema validate (the CPU-bound hot path)
  pipeline  engine + raw archive (gzip + SHA-256 to disk) + JSONL sink (full direct-mode path)

and projects events/day and the worker count needed for a target volume.
Workers are stateless (Redis Streams consumer group), so throughput scales
horizontally by adding workers/partitions.

Usage:
  python tools/benchmark.py                 # 20k events, mixed 8-vendor traffic
  python tools/benchmark.py --events 100000 --no-validate
"""
import argparse
import os
import random
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

# isolate: temp data dir, direct buffer, local raw store, JSONL sink only
_tmp = tempfile.mkdtemp(prefix="ulpf-bench-")
os.environ.update({"ULPF_DATA_DIR": _tmp, "ULPF_BUFFER_TYPE": "direct", "ULPF_RAW_STORE": "local",
                   "ULPF_SINKS": "jsonl", "ULPF_SELFHEAL_ENABLED": "false"})

import log_samples as S  # noqa: E402

from src import config  # noqa: E402
from src.parser.engine import ParserEngine  # noqa: E402
from src.pipeline import process_event  # noqa: E402


def build_corpus(n: int):
    random.seed(7)
    S.R.seed(7)
    out = []
    for _ in range(n):
        fn = random.choice(S.KNOWN)
        transport, _, raw = fn(attack=random.random() < 0.2)
        out.append((S.as_bytes(raw), S.CHANNELS[transport]))
    return out


def fmt(n: float) -> str:
    for unit, div in (("B", 1e9), ("M", 1e6), ("k", 1e3)):
        if n >= div:
            return f"{n / div:,.1f}{unit}"
    return f"{n:,.0f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=20000)
    ap.add_argument("--no-validate", action="store_true", help="skip JSON-Schema validation in the engine run")
    ap.add_argument("--target-per-day", type=float, default=5e9, help="sizing target (default 5 billion/day)")
    args = ap.parse_args()

    corpus = build_corpus(args.events)
    engine = ParserEngine()
    uid = "33333333-3333-4333-8333-333333333333"
    raw_info = {"sha256": "c" * 64, "raw_ref": "local://bench/" + uid, "size_bytes": 1}
    now = "2026-09-16T10:00:00+00:00"

    # warm-up
    for raw, ch in corpus[:500]:
        engine.process(raw.decode("utf-8", "replace"), ch, uid, now, raw_info=raw_info)

    t0 = time.perf_counter()
    for raw, ch in corpus:
        engine.process(raw.decode("utf-8", "replace"), ch, uid, now, raw_info=raw_info,
                       validate=not args.no_validate)
    engine_s = time.perf_counter() - t0

    n_pipe = min(len(corpus), 5000)
    t0 = time.perf_counter()
    for raw, ch in corpus[:n_pipe]:
        process_event(raw, channel=ch)
    pipe_s = time.perf_counter() - t0

    eng_eps = len(corpus) / engine_s
    pipe_eps = n_pipe / pipe_s
    print("=" * 66)
    print(f" ULPF throughput benchmark  ({len(corpus):,} events, 8 vendors, 6 formats, 1 core)")
    print("=" * 66)
    print(f" engine   (parse+normalize+enrich{'' if args.no_validate else '+validate'}): {eng_eps:10,.0f} EPS  "
          f"-> {fmt(eng_eps * 86400)} events/day/core")
    print(f" pipeline (+ raw gzip/SHA-256 archive + JSONL sink):    {pipe_eps:10,.0f} EPS  "
          f"-> {fmt(pipe_eps * 86400)} events/day/core")
    need = args.target_per_day / 86400
    print(f"\n Sizing for {fmt(args.target_per_day)} events/day ({need:,.0f} EPS average):")
    print(f"   ~{need / eng_eps:,.1f} parser workers  (raw archive on MinIO + Redis/Kafka buffer scale separately)")
    print(f"   ~{need / pipe_eps:,.1f} workers for the full single-node path as measured here")
    print(f"\n (scratch data written to {config.DATA_DIR})")


if __name__ == "__main__":
    main()
