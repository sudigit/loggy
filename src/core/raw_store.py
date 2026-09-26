"""
Raw event store with MinIO (S3-compatible) & local filesystem support.

Satisfies requirements:
  (a) Preserve complete raw event data without information loss.
  (d) Maintain traceability between normalized and original events.
  (j) Deployable in an air-gapped network (MinIO is self-hosted and air-gap native).

Storage layout
  local disk -- append-only, hourly SEGMENT files per source (WORM-friendly, no
                per-event file creation):  raw/<source_id>/<YYYYMMDDHH>.seg
                each record = one JSON header line (event id, sha256, sizes, channel,
                ingest time) + the gzip'd original bytes. Records are self-describing,
                so a segment can be verified or re-indexed without any database.
                raw_ref = "local://<source_id>/<segment>.seg@<byte offset>#<event_id>"
  MinIO/S3   -- one object per event: <source_id>/<event_id>.raw.gz (+ .meta.json)
                raw_ref = "minio://<source_id>/<event_id>"

Every normalized record carries `metadata.raw_ref` and `metadata.raw_sha256`,
so the original can always be fetched and re-verified.

If MinIO is not configured or not reachable, it falls back to local disk.
The backend is chosen ONCE at first use -- a dead MinIO is never retried per event.
"""
import gzip
import io
import json
import logging
import threading
from datetime import datetime, timezone

from src import config
from src.core.ids import sha256_hex

logger = logging.getLogger("ulpf.raw_store")

_minio_client = None
_store_mode = None  # "minio" | "local" -- resolved once
_init_lock = threading.Lock()


def _resolve_backend():
    global _minio_client, _store_mode
    if _store_mode is not None:
        return
    with _init_lock:
        if _store_mode is not None:
            return
        wants_minio = config.RAW_STORE_TYPE == "minio" or (
            config.RAW_STORE_TYPE == "auto" and config.MINIO_ACCESS_KEY and config.MINIO_SECRET_KEY
        )
        if not wants_minio:
            _store_mode = "local"
            return
        try:
            import urllib3
            from minio import Minio
            client = Minio(
                endpoint=config.MINIO_ENDPOINT,
                access_key=config.MINIO_ACCESS_KEY,
                secret_key=config.MINIO_SECRET_KEY,
                secure=config.MINIO_SECURE,
                http_client=urllib3.PoolManager(timeout=3.0, retries=urllib3.Retry(total=1)),
            )
            if not client.bucket_exists(config.MINIO_BUCKET):
                client.make_bucket(config.MINIO_BUCKET)
                logger.info(f"[raw_store] Created MinIO bucket '{config.MINIO_BUCKET}'")
            _minio_client = client
            _store_mode = "minio"
            logger.info(f"[raw_store] Using MinIO object store at {config.MINIO_ENDPOINT}")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[raw_store] MinIO unavailable ({e}). Using local disk storage.")
            _store_mode = "local"


def get_store_mode() -> str:
    _resolve_backend()
    return _store_mode


def parse_ref(raw_ref: str):
    """'local://pfsense/2026091610.seg@123#<uuid>' or 'minio://pfsense/<uuid>'
    -> ('pfsense', '<uuid>')"""
    path = raw_ref.split("://", 1)[-1]
    source_id, rest = path.split("/", 1)
    return source_id, rest.rsplit("#", 1)[-1]


# ------------------------------------------------------------------ local segments
_segments = {}          # source_id -> {"key": hour, "fh": file, "lock": Lock}
_segments_lock = threading.Lock()


def _segment(source_id: str):
    hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    with _segments_lock:
        seg = _segments.get(source_id)
        if seg is None:
            seg = _segments[source_id] = {"key": None, "fh": None, "lock": threading.Lock()}
    if seg["key"] != hour:
        with seg["lock"]:
            if seg["key"] != hour:
                if seg["fh"]:
                    seg["fh"].close()
                folder = config.RAW_DIR / source_id
                folder.mkdir(parents=True, exist_ok=True)
                seg["fh"] = open(folder / f"{hour}.seg", "ab")
                seg["key"] = hour
    return seg


def _append_segment(source_id: str, header: dict, compressed: bytes) -> str:
    seg = _segment(source_id)
    head = (json.dumps(header, separators=(",", ":")) + "\n").encode("utf-8")
    with seg["lock"]:
        fh = seg["fh"]
        fh.seek(0, 2)
        offset = fh.tell()
        fh.write(head + compressed + b"\n")
        fh.flush()
        name = f"{seg['key']}.seg"
    return f"local://{source_id}/{name}@{offset}#{header['event_id']}"


def _read_segment(raw_ref: str):
    """Returns (raw_bytes, header) for a segment reference."""
    path = raw_ref.split("://", 1)[-1]
    source_id, rest = path.split("/", 1)
    seg_name, pos = rest.split("@", 1)
    offset = int(pos.split("#", 1)[0])
    with open(config.RAW_DIR / source_id / seg_name, "rb") as f:
        f.seek(offset)
        header = json.loads(f.readline().decode("utf-8"))
        compressed = f.read(header["compressed_bytes"])
    return gzip.decompress(compressed), header


def _local_paths(source_id: str, event_id: str, create: bool = True):
    folder = config.RAW_DIR / source_id
    if create:
        folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{event_id}.raw.gz", folder / f"{event_id}.meta.json"


def save(event_id: str, source_id: str, raw_bytes: bytes, meta: dict) -> dict:
    """
    Saves raw bytes verbatim (gzip) plus a sidecar metadata record.
    Returns {"sha256": ..., "raw_ref": ..., "size_bytes": ...}.
    """
    _resolve_backend()
    hash_val = sha256_hex(raw_bytes)
    compressed_bytes = gzip.compress(raw_bytes, compresslevel=6, mtime=0)
    raw_ref = f"{_store_mode}://{source_id}/{event_id}"

    full_meta = {
        "event_id": event_id,
        "source_id": source_id,
        "sha256": hash_val,
        "size_bytes": len(raw_bytes),
        "compressed_bytes": len(compressed_bytes),
        "raw_ref": raw_ref,
        **meta,
    }
    meta_json = json.dumps(full_meta, indent=2).encode("utf-8")

    if _store_mode == "minio":
        try:
            _minio_client.put_object(
                bucket_name=config.MINIO_BUCKET,
                object_name=f"{source_id}/{event_id}.raw.gz",
                data=io.BytesIO(compressed_bytes),
                length=len(compressed_bytes),
                content_type="application/gzip",
                metadata={"sha256": hash_val, "event_id": event_id, "source_id": source_id},
            )
            _minio_client.put_object(
                bucket_name=config.MINIO_BUCKET,
                object_name=f"{source_id}/{event_id}.meta.json",
                data=io.BytesIO(meta_json),
                length=len(meta_json),
                content_type="application/json",
            )
            return {"sha256": hash_val, "raw_ref": raw_ref, "size_bytes": len(raw_bytes)}
        except Exception as e:  # noqa: BLE001
            logger.error(f"[raw_store] MinIO upload failed: {e}. Writing to local disk instead.")
            raw_ref = f"local://{source_id}/{event_id}"
            full_meta["raw_ref"] = raw_ref
            meta_json = json.dumps(full_meta, indent=2).encode("utf-8")

    full_meta.pop("raw_ref", None)
    raw_ref = _append_segment(source_id, full_meta, compressed_bytes)
    return {"sha256": hash_val, "raw_ref": raw_ref, "size_bytes": len(raw_bytes)}


def _minio_get(key: str) -> bytes:
    response = _minio_client.get_object(config.MINIO_BUCKET, key)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def read(event_id: str, source_id: str) -> bytes:
    """Reads and decompresses raw event bytes by event_id and source_id."""
    _resolve_backend()
    if _store_mode == "minio":
        try:
            return gzip.decompress(_minio_get(f"{source_id}/{event_id}.raw.gz"))
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[raw_store] MinIO get failed, trying local: {e}")
    raw_path, _ = _local_paths(source_id, event_id, create=False)
    with gzip.open(raw_path, "rb") as f:
        return f.read()


def read_meta(event_id: str, source_id: str) -> dict:
    _resolve_backend()
    if _store_mode == "minio":
        try:
            return json.loads(_minio_get(f"{source_id}/{event_id}.meta.json").decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[raw_store] MinIO get meta failed, trying local: {e}")
    _, meta_path = _local_paths(source_id, event_id, create=False)
    return json.loads(meta_path.read_text())


def read_ref(raw_ref: str) -> bytes:
    if "@" in raw_ref:
        return _read_segment(raw_ref)[0]
    source_id, event_id = parse_ref(raw_ref)
    return read(event_id, source_id)


def verify(raw_ref: str) -> dict:
    """Re-reads the archived original and re-hashes it (chain-of-custody check)."""
    if "@" in raw_ref:
        raw, meta = _read_segment(raw_ref)
    else:
        source_id, event_id = parse_ref(raw_ref)
        raw = read(event_id, source_id)
        meta = read_meta(event_id, source_id)
    actual = sha256_hex(raw)
    return {
        "raw_ref": raw_ref,
        "raw_bytes": raw,
        "stored_sha256": meta.get("sha256"),
        "computed_sha256": actual,
        "verified": actual == meta.get("sha256"),
        "meta": meta,
    }


def find_ref(event_id: str):
    """Best-effort lookup of a raw_ref from just the event id (scans recent local
    segments). Normal lookups never need this: records and DLQ rows carry raw_ref."""
    for meta_path in config.RAW_DIR.glob(f"*/{event_id}.meta.json"):
        return f"local://{meta_path.parent.name}/{event_id}"
    needle = f'"event_id":"{event_id}"'.encode("utf-8")
    for seg in sorted(config.RAW_DIR.glob("*/*.seg"), key=lambda p: p.stat().st_mtime, reverse=True)[:48]:
        with open(seg, "rb") as f:
            while True:
                offset = f.tell()
                line = f.readline()
                if not line:
                    break
                try:
                    header = json.loads(line)
                except ValueError:
                    break
                if needle in line:
                    return f"local://{seg.parent.name}/{seg.name}@{offset}#{event_id}"
                f.seek(header["compressed_bytes"] + 1, 1)
    return None
