"""
Central configuration for ULPF prototype.
Everything is overridable via environment variables so the same code
runs the same way inside or outside a container (air-gap friendly:
no config is fetched from the network).
"""
import os
from pathlib import Path

BASE_DIR = Path(os.environ.get("ULPF_BASE_DIR", Path(__file__).resolve().parent.parent))
DATA_DIR = Path(os.environ.get("ULPF_DATA_DIR", BASE_DIR / "data"))

RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
INCOMING_DIR = DATA_DIR / "incoming"
DLQ_DB_PATH = DATA_DIR / "dlq.sqlite3"

PARSER_CONFIG_DIR = BASE_DIR / "src" / "parser" / "configs"
PARSER_PROPOSED_DIR = PARSER_CONFIG_DIR / "proposed"

# Ingestion endpoints
SYSLOG_UDP_PORT = int(os.environ.get("ULPF_SYSLOG_UDP_PORT", 5514))
HTTP_API_PORT = int(os.environ.get("ULPF_HTTP_PORT", 8080))
SQUID_LOG_FILE = INCOMING_DIR / "squid_access.log"

# Self-healing thresholds
DLQ_BATCH_THRESHOLD = int(os.environ.get("ULPF_DLQ_THRESHOLD", 3))

# Local LLM (air-gapped). If unreachable, self-heal falls back to a
# heuristic parser-skeleton generator so the demo still works without Ollama.
OLLAMA_URL = os.environ.get("ULPF_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("ULPF_OLLAMA_MODEL", "qwen2.5-coder")

# Durable Buffer (Redis Streams)
# BUFFER_TYPE: "auto" (use Redis if available, else direct), "redis", or "direct"
BUFFER_TYPE = os.environ.get("ULPF_BUFFER_TYPE", "auto")
REDIS_URL = os.environ.get("ULPF_REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = os.environ.get("ULPF_STREAM_NAME", "ulpf:events")
CONSUMER_GROUP = os.environ.get("ULPF_CONSUMER_GROUP", "ulpf:parser:group")
STREAM_WORKER_COUNT = int(os.environ.get("ULPF_STREAM_WORKERS", 2))
STREAM_BATCH_SIZE = int(os.environ.get("ULPF_STREAM_BATCH_SIZE", 50))

# Raw Object Store (MinIO / S3)
# RAW_STORE_TYPE: "auto" (use MinIO if reachable, else local filesystem), "minio", or "local"
RAW_STORE_TYPE = os.environ.get("ULPF_RAW_STORE", "auto")
MINIO_ENDPOINT = os.environ.get("ULPF_MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("ULPF_MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("ULPF_MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.environ.get("ULPF_MINIO_BUCKET", "ulpf-raw-events")
MINIO_SECURE = os.environ.get("ULPF_MINIO_SECURE", "false").lower() == "true"

for d in (RAW_DIR, NORMALIZED_DIR, INCOMING_DIR, PARSER_PROPOSED_DIR):
    d.mkdir(parents=True, exist_ok=True)


