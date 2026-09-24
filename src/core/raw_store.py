"""
Raw event store with MinIO (S3-compatible) & local filesystem support.

Satisfies requirements:
  (a) Preserve complete raw event data without information loss.
  (d) Maintain traceability between normalized and original events.
  (j) Deployable in an air-gapped network (MinIO is self-hosted and air-gap native).

Storage layout:
  Bucket: ulpf-raw-events
  Keys:   <source_id>/<event_id>.raw.gz
          <source_id>/<event_id>.meta.json

If MinIO is not available or disabled, it transparently falls back to local
filesystem storage (data/raw/<source_id>/<event_id>.*) without breaking execution.
"""
import gzip
import io
import json
import logging
from pathlib import Path
from typing import Optional

from src import config
from src.core.ids import sha256_hex

logger = logging.getLogger("ulpf.raw_store")

_minio_client = None
_store_mode = "local"  # "minio" or "local"


def _get_minio_client():
    global _minio_client, _store_mode
    if _minio_client is not None:
        return _minio_client

    if config.RAW_STORE_TYPE == "local":
        _store_mode = "local"
        return None

    try:
        from minio import Minio
        client = Minio(
            endpoint=config.MINIO_ENDPOINT,
            access_key=config.MINIO_ACCESS_KEY,
            secret_key=config.MINIO_SECRET_KEY,
            secure=config.MINIO_SECURE,
        )
        # Ensure bucket exists
        if not client.bucket_exists(config.MINIO_BUCKET):
            client.make_bucket(config.MINIO_BUCKET)
            logger.info(f"[raw_store] Created MinIO bucket '{config.MINIO_BUCKET}'")
        _minio_client = client
        _store_mode = "minio"
        logger.info(f"[raw_store] Connected to MinIO S3 object store at {config.MINIO_ENDPOINT}")
        return _minio_client
    except Exception as e:
        logger.warning(f"[raw_store] MinIO unavailable ({e}). Falling back to local disk storage.")
        _store_mode = "local"
        return None


def get_store_mode() -> str:
    _get_minio_client()
    return _store_mode


def _local_paths(source_id: str, event_id: str):
    folder = config.RAW_DIR / source_id
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{event_id}.raw.gz", folder / f"{event_id}.meta.json"


def save(event_id: str, source_id: str, raw_bytes: bytes, meta: dict) -> str:
    """
    Saves raw bytes verbatim (gzip compressed) and a sidecar metadata record
    with the SHA-256 hash. Returns the computed SHA-256 hash.
    """
    hash_val = sha256_hex(raw_bytes)
    compressed_bytes = gzip.compress(raw_bytes)

    full_meta = {
        "event_id": event_id,
        "source_id": source_id,
        "sha256": hash_val,
        "size_bytes": len(raw_bytes),
        "compressed_bytes": len(compressed_bytes),
        **meta,
    }
    meta_json = json.dumps(full_meta, indent=2).encode("utf-8")

    client = _get_minio_client()
    if client is not None and _store_mode == "minio":
        try:
            raw_key = f"{source_id}/{event_id}.raw.gz"
            meta_key = f"{source_id}/{event_id}.meta.json"

            # Upload compressed raw object
            client.put_object(
                bucket_name=config.MINIO_BUCKET,
                object_name=raw_key,
                data=io.BytesIO(compressed_bytes),
                length=len(compressed_bytes),
                content_type="application/gzip",
                metadata={"sha256": hash_val, "event_id": event_id, "source_id": source_id},
            )

            # Upload metadata object
            client.put_object(
                bucket_name=config.MINIO_BUCKET,
                object_name=meta_key,
                data=io.BytesIO(meta_json),
                length=len(meta_json),
                content_type="application/json",
            )
            return hash_val
        except Exception as e:
            logger.error(f"[raw_store] MinIO upload failed: {e}. Falling back to local disk.")

    # Local fallback
    raw_path, meta_path = _local_paths(source_id, event_id)
    raw_path.write_bytes(compressed_bytes)
    meta_path.write_bytes(meta_json)
    return hash_val


def read(event_id: str, source_id: str) -> bytes:
    """Reads and decompresses raw event bytes by event_id and source_id."""
    client = _get_minio_client()
    if client is not None and _store_mode == "minio":
        try:
            raw_key = f"{source_id}/{event_id}.raw.gz"
            response = client.get_object(config.MINIO_BUCKET, raw_key)
            compressed = response.read()
            response.close()
            response.release_conn()
            return gzip.decompress(compressed)
        except Exception as e:
            logger.debug(f"[raw_store] MinIO get failed, trying local: {e}")

    # Fallback to local
    raw_path, _ = _local_paths(source_id, event_id)
    with gzip.open(raw_path, "rb") as f:
        return f.read()


def read_meta(event_id: str, source_id: str) -> dict:
    """Reads metadata dictionary for a given event_id."""
    client = _get_minio_client()
    if client is not None and _store_mode == "minio":
        try:
            meta_key = f"{source_id}/{event_id}.meta.json"
            response = client.get_object(config.MINIO_BUCKET, meta_key)
            meta_bytes = response.read()
            response.close()
            response.release_conn()
            return json.loads(meta_bytes.decode("utf-8"))
        except Exception as e:
            logger.debug(f"[raw_store] MinIO get meta failed, trying local: {e}")

    # Fallback to local
    _, meta_path = _local_paths(source_id, event_id)
    return json.loads(meta_path.read_text())
