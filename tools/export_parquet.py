"""
Normalized JSONL -> columnar Parquet for the data lake / ML (requirement h).

  data/parquet/<source>.parquet   full OCSF records, flattened to dotted columns
  data/parquet/features.parquet   one fixed-schema, ML-ready feature table across ALL
                                  sources (numeric/boolean/categorical columns only)

Kept off the hot path: the pipeline writes JSONL, this batches + compresses.

Usage:
    python tools/export_parquet.py                 # every source + feature table
    python tools/export_parquet.py --source pfsense
"""
import argparse
import json
import os
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ULPF_DATA_DIR", BASE_DIR / "data"))
NORMALIZED_DIR = DATA_DIR / "normalized"
PARQUET_DIR = DATA_DIR / "parquet"

FEATURES = {
    # column: (dotted path in the OCSF record, dtype)
    "time_ms": ("time", "Int64"),
    "source_id": ("metadata.source_id", "category"),
    "vendor": ("metadata.product.vendor_name", "category"),
    "class_uid": ("class_uid", "Int64"),
    "activity_id": ("activity_id", "Int64"),
    "severity_id": ("severity_id", "Int64"),
    "action_id": ("action_id", "Int64"),
    "disposition_id": ("disposition_id", "Int64"),
    "src_ip": ("src_endpoint.ip", "string"),
    "dst_ip": ("dst_endpoint.ip", "string"),
    "src_port": ("src_endpoint.port", "Int64"),
    "dst_port": ("dst_endpoint.port", "Int64"),
    "protocol_num": ("connection_info.protocol_num", "Int64"),
    "direction_id": ("connection_info.direction_id", "Int64"),
    "bytes_in": ("traffic.bytes_in", "Int64"),
    "bytes_out": ("traffic.bytes_out", "Int64"),
    "src_is_internal": ("enrichments.src_is_internal", "boolean"),
    "dst_is_internal": ("enrichments.dst_is_internal", "boolean"),
    "dst_port_risky": ("enrichments.dst_port_risky", "boolean"),
    "is_blocked": ("enrichments.is_blocked", "boolean"),
    "is_finding": ("enrichments.is_finding", "boolean"),
    "uid": ("metadata.uid", "string"),
    "raw_sha256": ("metadata.raw_sha256", "string"),
}


def _get(d, path):
    for p in path.split("."):
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


def read_records(source_dir: Path) -> list:
    records = []
    for jsonl_file in sorted(source_dir.glob("*.jsonl")):
        with open(jsonl_file, encoding="utf-8") as f:
            records.extend(json.loads(line) for line in f if line.strip())
    return records


def export_source(source_dir: Path, records: list):
    df = pd.json_normalize(records)
    # mixed-type object columns (e.g. unmapped vendor fields) -> strings so Arrow accepts them
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].map(lambda v: None if v is None else v if isinstance(v, str) else json.dumps(v))
    out_path = PARQUET_DIR / f"{source_dir.name}.parquet"
    df.to_parquet(out_path, index=False)
    return out_path


def export_features(all_records: list):
    rows = [{col: _get(r, path) for col, (path, _) in FEATURES.items()} for r in all_records]
    df = pd.DataFrame(rows, columns=list(FEATURES))
    for col, (_, dtype) in FEATURES.items():
        if dtype == "Int64":
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
        else:
            df[col] = df[col].astype(dtype)
    out_path = PARQUET_DIR / "features.parquet"
    df.sort_values("time_ms").to_parquet(out_path, index=False)
    return out_path, len(df)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="export only this source (default: all)")
    args = ap.parse_args()

    if not NORMALIZED_DIR.exists():
        print("No normalized data yet -- run the pipeline and send some sample logs first.")
        return
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    sources = [NORMALIZED_DIR / args.source] if args.source else sorted(NORMALIZED_DIR.iterdir())
    everything = []
    for source_dir in sources:
        if not source_dir.is_dir():
            continue
        records = read_records(source_dir)
        if not records:
            print(f"[{source_dir.name}] no records, skipped")
            continue
        path = export_source(source_dir, records)
        everything.extend(records)
        print(f"[{source_dir.name}] {len(records)} records -> {path}")
    if everything:
        path, n = export_features(everything)
        print(f"[features] {n} rows x {len(FEATURES)} ML-ready columns -> {path}")


if __name__ == "__main__":
    main()
