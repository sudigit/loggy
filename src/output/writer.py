"""
Writes normalized OCSF-subset records. Primary sink is append-only JSONL
per source per day (trivial to inspect for the demo and to tail live).

tools/export_parquet.py converts these to columnar Parquet on demand --
that's the artifact a real data lake / SIEM would actually ingest, kept as
a separate step here so the hot path never pays for batching/compression.
"""
import json
import threading
from datetime import datetime, timezone

from src import config

_lock = threading.Lock()


def write(ocsf_record: dict):
    source_id = ocsf_record["metadata"]["product"]["vendor_name"]
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    folder = config.NORMALIZED_DIR / source_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{day}.jsonl"
    with _lock, open(path, "a") as f:
        f.write(json.dumps(ocsf_record) + "\n")
