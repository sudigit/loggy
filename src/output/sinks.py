"""
Pluggable output sinks (requirement g: efficient SIEM and data-lake integration).

Enable any combination with ULPF_SINKS=jsonl,elastic,minio,syslog_cef,kafka

  jsonl       append-only JSONL per source per day -> data lake landing zone
              (tools/export_parquet.py turns it into columnar Parquet)
  elastic     Elasticsearch / OpenSearch `_bulk` API, batched in the background
  minio       batched JSONL objects in a MinIO / S3 bucket (next to the raw archive)
  syslog_cef  re-emits every normalized event as CEF over UDP syslog, so ANY
              legacy SIEM (ArcSight, QRadar, Splunk, Sentinel via AMA) can consume it
  kafka       JSON to a Kafka topic (requires the optional kafka-python package)

A sink failure is logged and counted; it never blocks or crashes ingestion.
"""
import io
import json
import logging
import queue
import socket
import threading
import uuid
from datetime import datetime, timezone

from src import config
from src.core import metrics

logger = logging.getLogger("ulpf.sinks")


class Sink:
    name = "base"

    def emit(self, ev: dict):
        raise NotImplementedError

    def close(self):
        pass


class JsonlSink(Sink):
    name = "jsonl"

    def __init__(self):
        self._lock = threading.Lock()
        self._handles = {}  # (source_id, day) -> open file, rotated daily

    def emit(self, ev: dict):
        source_id = ev["metadata"]["source_id"]
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        line = json.dumps(ev, separators=(",", ":")) + "\n"
        with self._lock:
            fh = self._handles.get((source_id, day))
            if fh is None:
                for key in [k for k in self._handles if k[0] == source_id]:
                    self._handles.pop(key).close()
                folder = config.NORMALIZED_DIR / source_id
                folder.mkdir(parents=True, exist_ok=True)
                fh = self._handles[(source_id, day)] = open(folder / f"{day}.jsonl", "a", encoding="utf-8")
            fh.write(line)
            fh.flush()

    def close(self):
        with self._lock:
            for fh in self._handles.values():
                fh.close()
            self._handles.clear()


class _BatchingSink(Sink):
    """Queues events and flushes them from a background thread in batches."""

    def __init__(self, batch_size: int, flush_seconds: float):
        self._q = queue.Queue(maxsize=100_000)
        self._batch_size = batch_size
        self._flush_seconds = flush_seconds
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True, name=f"sink-{self.name}").start()

    def emit(self, ev: dict):
        try:
            self._q.put_nowait(ev)
        except queue.Full:
            metrics.incr(f"sink_{self.name}_dropped")

    def _loop(self):
        while not self._stop.is_set():
            batch = []
            try:
                batch.append(self._q.get(timeout=self._flush_seconds))
                while len(batch) < self._batch_size:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            if batch:
                try:
                    self.flush(batch)
                    metrics.incr(f"sink_{self.name}_sent", len(batch))
                except Exception as e:  # noqa: BLE001
                    metrics.incr(f"sink_{self.name}_errors", len(batch))
                    logger.warning(f"[sink:{self.name}] flush of {len(batch)} events failed: {e}")

    def flush(self, batch: list):
        raise NotImplementedError

    def close(self):
        self._stop.set()


class ElasticSink(_BatchingSink):
    name = "elastic"

    def __init__(self):
        import requests
        self._session = requests.Session()
        super().__init__(config.ELASTIC_BATCH_SIZE, config.ELASTIC_FLUSH_SECONDS)

    def flush(self, batch: list):
        lines = []
        for ev in batch:
            day = ev["time_dt"][:10].replace("-", ".")
            lines.append(json.dumps({"create": {"_index": f"{config.ELASTIC_INDEX}-{day}",
                                                "_id": ev["metadata"]["uid"]}}))
            lines.append(json.dumps({**ev, "@timestamp": ev["time_dt"]}))
        resp = self._session.post(f"{config.ELASTIC_URL}/_bulk", data="\n".join(lines) + "\n",
                                  headers={"Content-Type": "application/x-ndjson"}, timeout=10)
        resp.raise_for_status()


class MinioSink(_BatchingSink):
    """Uploads normalized events to MinIO / S3 as one JSONL object per source per
    batch: <bucket>/<source_id>/<YYYY-MM-DD>/<HHMMSS>-<batch-id>.jsonl"""
    name = "minio"

    def __init__(self):
        import urllib3
        from minio import Minio
        self._client = Minio(
            endpoint=config.MINIO_ENDPOINT,
            access_key=config.MINIO_ACCESS_KEY,
            secret_key=config.MINIO_SECRET_KEY,
            secure=config.MINIO_SECURE,
            http_client=urllib3.PoolManager(timeout=5.0, retries=urllib3.Retry(total=2)),
        )
        if not self._client.bucket_exists(config.MINIO_NORMALIZED_BUCKET):
            self._client.make_bucket(config.MINIO_NORMALIZED_BUCKET)
            logger.info(f"[sink:minio] Created bucket '{config.MINIO_NORMALIZED_BUCKET}'")
        super().__init__(config.MINIO_SINK_BATCH_SIZE, config.MINIO_SINK_FLUSH_SECONDS)

    def flush(self, batch: list):
        by_source = {}
        for ev in batch:
            by_source.setdefault(ev["metadata"]["source_id"], []).append(ev)
        now = datetime.now(timezone.utc)
        for source_id, events in by_source.items():
            body = "".join(json.dumps(ev, separators=(",", ":")) + "\n" for ev in events).encode("utf-8")
            key = f"{source_id}/{now:%Y-%m-%d}/{now:%H%M%S}-{uuid.uuid4().hex[:8]}.jsonl"
            self._client.put_object(
                bucket_name=config.MINIO_NORMALIZED_BUCKET, object_name=key,
                data=io.BytesIO(body), length=len(body), content_type="application/x-ndjson",
            )


def _cef_escape_header(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_ext(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")


def to_cef(ev: dict) -> str:
    """Normalized OCSF event -> CEF line. Always carries the ULPF uid + raw hash
    so a SIEM analyst can pivot back to the untouched original."""
    sev = {0: 0, 1: 1, 2: 3, 3: 5, 4: 7, 5: 9, 6: 10}.get(ev.get("severity_id"), 0)
    src, dst = ev.get("src_endpoint", {}), ev.get("dst_endpoint", {})
    conn = ev.get("connection_info", {})
    md = ev["metadata"]
    ext = {
        "rt": ev["time"], "src": src.get("ip"), "spt": src.get("port"), "dst": dst.get("ip"),
        "dpt": dst.get("port"), "proto": conn.get("protocol_name"), "act": ev.get("disposition"),
        "suser": ev.get("actor", {}).get("user", {}).get("name"),
        "msg": ev.get("finding_info", {}).get("title") or ev.get("message"),
        "cs1Label": "ulpf_uid", "cs1": md["uid"],
        "cs2Label": "raw_sha256", "cs2": md.get("raw_sha256"),
        "cs3Label": "raw_ref", "cs3": md.get("raw_ref"),
        "cs4Label": "source_product", "cs4": f"{md['product'].get('vendor_name')} {md['product'].get('name')}",
    }
    ext_str = " ".join(f"{k}={_cef_escape_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(_cef_escape_header(x) for x in (
        "ULPF", "Universal Log Pre-processing Framework", config.ULPF_SCHEMA_VERSION,
        ev.get("type_uid"), ev.get("type_name"), sev))
    return f"CEF:0|{header}|{ext_str}"


class SyslogCefSink(Sink):
    name = "syslog_cef"

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._addr = (config.SIEM_SYSLOG_HOST, config.SIEM_SYSLOG_PORT)

    def emit(self, ev: dict):
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        msg = f"<134>{ts} ulpf {to_cef(ev)}"
        self._sock.sendto(msg.encode("utf-8")[:65000], self._addr)


class KafkaSink(Sink):
    name = "kafka"

    def __init__(self):
        from kafka import KafkaProducer  # optional dependency
        self._producer = KafkaProducer(
            bootstrap_servers=config.KAFKA_BOOTSTRAP.split(","),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8"),
            linger_ms=50,
        )

    def emit(self, ev: dict):
        self._producer.send(config.KAFKA_TOPIC, key=ev["metadata"]["source_id"], value=ev)


_REGISTRY = {"jsonl": JsonlSink, "elastic": ElasticSink, "minio": MinioSink,
             "syslog_cef": SyslogCefSink, "kafka": KafkaSink}
_active = None
_init_lock = threading.Lock()


def active_sinks() -> list:
    global _active
    if _active is None:
        with _init_lock:
            if _active is None:
                sinks = []
                for name in config.SINKS:
                    cls = _REGISTRY.get(name)
                    if not cls:
                        logger.error(f"[sinks] unknown sink '{name}' (known: {', '.join(_REGISTRY)})")
                        continue
                    try:
                        sinks.append(cls())
                    except Exception as e:  # noqa: BLE001
                        logger.error(f"[sinks] could not start sink '{name}': {e}")
                _active = sinks or [JsonlSink()]
    return _active


def emit(ev: dict):
    for sink in active_sinks():
        try:
            sink.emit(ev)
        except Exception as e:  # noqa: BLE001
            metrics.incr(f"sink_{sink.name}_errors")
            logger.warning(f"[sink:{sink.name}] emit failed: {e}")
