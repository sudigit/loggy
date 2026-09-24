"""
Converts the normalized JSONL output into columnar Parquet -- the format a
real data lake / ML pipeline would actually consume (requirement h,
AI/ML-ready analytics). Kept as a separate offline step so the hot path
never pays for batching or compression.

Usage:
    python tools/export_parquet.py                 # export all sources
    python tools/export_parquet.py --source pfsense
"""
import argparse
import json
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
NORMALIZED_DIR = BASE_DIR / "data" / "normalized"
PARQUET_DIR = BASE_DIR / "data" / "parquet"


def export_source(source_dir: Path):
    records = []
    for jsonl_file in sorted(source_dir.glob("*.jsonl")):
        with open(jsonl_file) as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
    if not records:
        return None
    df = pd.json_normalize(records)
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PARQUET_DIR / f"{source_dir.name}.parquet"
    df.to_parquet(out_path, index=False)
    return out_path, len(records)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="export only this source (default: all)")
    args = ap.parse_args()

    if not NORMALIZED_DIR.exists():
        print("No normalized data yet -- run the pipeline and send some sample logs first.")
        return

    sources = [NORMALIZED_DIR / args.source] if args.source else list(NORMALIZED_DIR.iterdir())
    for source_dir in sources:
        if not source_dir.is_dir():
            continue
        result = export_source(source_dir)
        if result:
            path, count = result
            print(f"[{source_dir.name}] {count} records -> {path}")
        else:
            print(f"[{source_dir.name}] no records found, skipped")


if __name__ == "__main__":
    main()
