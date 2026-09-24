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

for d in (RAW_DIR, NORMALIZED_DIR, INCOMING_DIR, PARSER_PROPOSED_DIR):
    d.mkdir(parents=True, exist_ok=True)
