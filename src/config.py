"""
Central configuration for ULPF.

Everything is overridable via environment variables (ULPF_* prefix) so the
same code runs the same way inside or outside a container. A local `.env`
file in the project root is loaded on import if present -- no config is
ever fetched from the network (air-gap friendly).
"""
import os
from pathlib import Path


def _load_dotenv(path: Path):
    """Minimal .env loader (no python-dotenv dependency). Real environment
    variables always win over values in the file."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_load_dotenv(_PROJECT_ROOT / ".env")


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except ValueError:
        return default


def _float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except ValueError:
        return default


def _bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


BASE_DIR = Path(os.environ.get("ULPF_BASE_DIR", _PROJECT_ROOT))
DATA_DIR = Path(os.environ.get("ULPF_DATA_DIR", BASE_DIR / "data"))

RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
INCOMING_DIR = DATA_DIR / "incoming"
DLQ_DB_PATH = DATA_DIR / "dlq.sqlite3"

PARSER_CONFIG_DIR = Path(os.environ.get("ULPF_PARSER_CONFIG_DIR", BASE_DIR / "src" / "parser" / "configs"))
PARSER_PROPOSED_DIR = PARSER_CONFIG_DIR / "proposed"
PARSER_ARCHIVE_DIR = PARSER_CONFIG_DIR / "archive"
SCHEMA_PATH = BASE_DIR / "src" / "schema" / "ulpf_event.schema.json"
REGRESSION_CORPUS_DIR = BASE_DIR / "tests" / "corpus"

# Ingestion endpoints
SYSLOG_UDP_PORT = _int("ULPF_SYSLOG_PORT", _int("ULPF_SYSLOG_UDP_PORT", 5514))
HTTP_API_PORT = _int("ULPF_HTTP_PORT", 8080)
SQUID_LOG_FILE = INCOMING_DIR / "squid_access.log"

# Normalized-event contract
OCSF_VERSION = "1.3.0"
ULPF_SCHEMA_VERSION = "1.0.0"
# Events that fail schema validation go to the DLQ instead of the lake.
SCHEMA_ENFORCE = _bool("ULPF_SCHEMA_ENFORCE", True)
# Networks treated as "internal" by the enrichment stage (comma-separated CIDRs).
INTERNAL_NETWORKS = [n.strip() for n in os.environ.get(
    "ULPF_INTERNAL_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,fc00::/7"
).split(",") if n.strip()]

# ---------------------------------------------------------------------------
# Continuous DLQ self-heal loop (evaluated PER CLUSTER, not across the DLQ)
#   tick        -- how often the background loop wakes up and checks
#   min_samples -- never propose from fewer samples than this (avoids overfit)
#   count       -- propose as soon as a cluster reaches this many samples
#   max_wait    -- ...or once its oldest sample has waited this long (>= min_samples)
#   Re-proposal only happens when NEW samples arrived since the last proposal.
# ---------------------------------------------------------------------------
SELFHEAL_ENABLED = _bool("ULPF_SELFHEAL_ENABLED", True)
DLQ_TICK_SECONDS = _float("ULPF_DLQ_TICK_SECONDS", 5)
DLQ_MIN_SAMPLES = _int("ULPF_DLQ_MIN_SAMPLES", 5)
DLQ_COUNT_THRESHOLD = _int("ULPF_DLQ_COUNT_THRESHOLD", 10)
DLQ_TIME_THRESHOLD = _int("ULPF_DLQ_TIME_THRESHOLD", 30)
DLQ_SAMPLES_FOR_PROPOSAL = _int("ULPF_DLQ_SAMPLES_FOR_PROPOSAL", 25)

# Local LLM (air-gapped). If unreachable, self-heal uses the deterministic
# structure-inference engine (src/selfheal/inference.py) instead.
OLLAMA_URL = os.environ.get("ULPF_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("ULPF_OLLAMA_MODEL", "qwen2.5-coder")
OLLAMA_ENABLED = _bool("ULPF_OLLAMA_ENABLED", True)
OLLAMA_TIMEOUT = _float("ULPF_OLLAMA_TIMEOUT", 30)

# Durable Buffer (Redis Streams)
# BUFFER_TYPE: "auto" (use Redis if available, else direct), "redis", or "direct"
BUFFER_TYPE = os.environ.get("ULPF_BUFFER_TYPE", "auto")
REDIS_URL = os.environ.get("ULPF_REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = os.environ.get("ULPF_STREAM_NAME", "ulpf:events")
CONSUMER_GROUP = os.environ.get("ULPF_CONSUMER_GROUP", "ulpf:parser:group")
STREAM_WORKER_COUNT = _int("ULPF_STREAM_WORKERS", 2)
STREAM_BATCH_SIZE = _int("ULPF_STREAM_BATCH_SIZE", 50)

# Raw Object Store (MinIO / S3)
# RAW_STORE_TYPE: "auto" (MinIO if configured + reachable, else local disk), "minio", or "local".
# Credentials have NO baked-in defaults -- set them in .env / compose.
RAW_STORE_TYPE = os.environ.get("ULPF_RAW_STORE", "auto")
MINIO_ENDPOINT = os.environ.get("ULPF_MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("ULPF_MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("ULPF_MINIO_SECRET_KEY", "")
MINIO_BUCKET = os.environ.get("ULPF_MINIO_BUCKET", "ulpf-raw-events")
MINIO_SECURE = _bool("ULPF_MINIO_SECURE", False)

# Output sinks (comma-separated): jsonl, elastic, syslog_cef, kafka
SINKS = [s.strip() for s in os.environ.get("ULPF_SINKS", "jsonl").split(",") if s.strip()]
ELASTIC_URL = os.environ.get("ULPF_ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.environ.get("ULPF_ELASTIC_INDEX", "ulpf-events")
ELASTIC_BATCH_SIZE = _int("ULPF_ELASTIC_BATCH_SIZE", 500)
ELASTIC_FLUSH_SECONDS = _float("ULPF_ELASTIC_FLUSH_SECONDS", 2)
SIEM_SYSLOG_HOST = os.environ.get("ULPF_SIEM_SYSLOG_HOST", "127.0.0.1")
SIEM_SYSLOG_PORT = _int("ULPF_SIEM_SYSLOG_PORT", 6514)
KAFKA_BOOTSTRAP = os.environ.get("ULPF_KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.environ.get("ULPF_KAFKA_TOPIC", "ulpf.normalized")

# In-memory ring of recent normalized events for the UI / lookups.
RECENT_EVENTS_BUFFER = _int("ULPF_RECENT_EVENTS", 2000)

for d in (RAW_DIR, NORMALIZED_DIR, INCOMING_DIR, PARSER_PROPOSED_DIR, PARSER_ARCHIVE_DIR):
    d.mkdir(parents=True, exist_ok=True)
