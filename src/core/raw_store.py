"""
Raw event store.

In the full architecture this is MinIO (S3-compatible object storage) so it
scales out and works air-gapped. For this local prototype we use the
filesystem with the exact same layout convention (source/uuid), so swapping
in a real object store later is a one-file change (see write()/read()).

Every raw event is stored byte-for-byte, gzip-compressed, next to a sidecar
.meta.json carrying the SHA-256 hash, ingestion channel, and timestamp --
this is what satisfies "no information loss" and "traceability" in the
architecture doc.
"""
import gzip
import json
from pathlib import Path

from src import config
from src.core.ids import sha256_hex


def _paths(source_id: str, event_id: str):
    folder = config.RAW_DIR / source_id
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{event_id}.raw.gz", folder / f"{event_id}.meta.json"


def save(event_id: str, source_id: str, raw_bytes: bytes, meta: dict) -> str:
    raw_path, meta_path = _paths(source_id, event_id)
    with gzip.open(raw_path, "wb") as f:
        f.write(raw_bytes)
    full_meta = {
        "event_id": event_id,
        "source_id": source_id,
        "sha256": sha256_hex(raw_bytes),
        "size_bytes": len(raw_bytes),
        **meta,
    }
    meta_path.write_text(json.dumps(full_meta, indent=2))
    return full_meta["sha256"]


def read(event_id: str, source_id: str) -> bytes:
    raw_path, _ = _paths(source_id, event_id)
    with gzip.open(raw_path, "rb") as f:
        return f.read()


def read_meta(event_id: str, source_id: str) -> dict:
    _, meta_path = _paths(source_id, event_id)
    return json.loads(meta_path.read_text())
