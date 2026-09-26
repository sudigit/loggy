"""
Test isolation: every test session gets a throw-away data dir AND a copy of
the parser configs, so promotions/rollbacks exercised by tests never touch
the real src/parser/configs. External services are disabled (direct buffer,
local raw store, no Ollama) so the suite is fast and fully offline.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_tmp = Path(tempfile.mkdtemp(prefix="ulpf-test-"))
_cfg = _tmp / "configs"
shutil.copytree(ROOT / "src" / "parser" / "configs", _cfg,
                ignore=shutil.ignore_patterns("proposed", "archive"))

os.environ.update({
    "ULPF_DATA_DIR": str(_tmp / "data"),
    "ULPF_PARSER_CONFIG_DIR": str(_cfg),
    "ULPF_BUFFER_TYPE": "direct",
    "ULPF_RAW_STORE": "local",
    "ULPF_OLLAMA_ENABLED": "false",
    "ULPF_SINKS": "jsonl",
})
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
