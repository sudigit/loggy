"""
Self-healing core service for DLQ analysis, AI proposal generation,
and regression-tested parser promotion.
"""
import importlib.util
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import yaml

# Import config directly to avoid package shadowing issue (src.config vs src/config/)
_project_root = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location("config", _project_root / "src" / "config.py")
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)

from src.dlq import store as dlq_store

# Import config-aware selfheal components
from .config_registry import ConfigRegistry, get_registry
from .dlq_processor import DLQProcessor, get_processor
from .models import ConfigAwarenessReport, ProposalResult

logger = logging.getLogger(__name__)


PROMPT_TEMPLATE = """You are helping onboard a new log source into a security log \
normalization pipeline. Below are {n} raw log samples that failed to parse on \
channel "{channel}". Propose a YAML parser config with this exact shape:

source_id: <short_name>
version: v1
channel: "{channel}"
fingerprint:
  type: contains|regex|json_key
  pattern: <value>
tokenize:
  type: regex|json|kv
  pattern: <regex with named groups, if type=regex>
mapping:
  fields:
    <source_field>: <ocsf.dotted.path>
  values: {{}}
  timestamp:
    source: <field name or ingest_time>
    format: epoch|iso8601

Return ONLY the YAML, no prose.

Samples:
{samples}
"""


def get_pending_summary() -> List[dict]:
    """Returns pending DLQ clusters grouped by channel."""
    grouped = dlq_store.pending_grouped_by_channel()
    summary = []
    for channel, entries in grouped.items():
        summary.append({
            "channel": channel,
            "count": len(entries),
            "sample_snippets": [e["raw_snippet"] for e in entries[:4]],
            "last_error": entries[-1]["error"] if entries else "unknown",
            "entry_ids": [e["id"] for e in entries],
        })
    return summary


def _get_active_model() -> Tuple[Optional[str], Optional[str]]:
    """Checks Ollama for available models and returns (model_name, description)."""
    try:
        resp = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=1.5)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            if models:
                # Prioritize coding models or llama
                for m in models:
                    name = m["name"]
                    if "coder" in name or "code" in name:
                        return name, f"Local Ollama ({name})"
                return models[0]["name"], f"Local Ollama ({models[0]['name']})"
    except Exception:
        pass
    return None, None


def _call_ollama(channel: str, samples: List[str]) -> Tuple[Optional[str], Optional[str]]:
    model_name, tag = _get_active_model()
    if not model_name:
        return None, None

    prompt = PROMPT_TEMPLATE.format(n=len(samples), channel=channel, samples="\n".join(samples[:5]))
    try:
        resp = requests.post(
            f"{config.OLLAMA_URL}/api/generate",
            json={"model": model_name, "prompt": prompt, "stream": False},
            timeout=15,
        )
        resp.raise_for_status()
        raw_resp = resp.json().get("response", "")
        # Clean any markdown code blocks
        clean_yaml = re.sub(r"^```(?:yaml)?\n|```$", "", raw_resp.strip(), flags=re.MULTILINE)
        return clean_yaml, tag
    except Exception:
        return None, None


def _heuristic_skeleton(channel: str, samples: List[str]) -> str:
    """Smart heuristic fallback when local LLM is not installed/reachable."""
    sample = samples[0].strip() if samples else ""
    safe_name = re.sub(r"\W+", "_", channel).strip("_") or "unknown_device"

    # 1. JSON Sniffer
    if sample.startswith("{"):
        try:
            import json
            obj = json.loads(sample)
            fields = {k: f"custom.{k}" for k in list(obj.keys())[:8]}
            first_key = list(obj.keys())[0] if obj else "device"
            return yaml.dump({
                "source_id": safe_name,
                "version": "v1",
                "channel": channel,
                "fingerprint": {"type": "json_key", "key": first_key},
                "tokenize": {"type": "json"},
                "mapping": {
                    "fields": fields,
                    "values": {},
                    "timestamp": {"source": "ingest_time"},
                },
            }, sort_keys=False)
        except Exception:
            pass

    # 2. Cisco ASA Sniffer
    if "%ASA-" in sample:
        return yaml.dump({
            "source_id": "cisco_asa",
            "version": "v1",
            "channel": channel,
            "fingerprint": {"type": "contains", "pattern": "%ASA-"},
            "tokenize": {
                "type": "regex",
                "pattern": r"%ASA-\d+-(?P<code_id>\d+):\s+(?P<disposition>\w+)\s+(?P<proto>\w+)\s+src\s+\w+:(?P<src>[^/]+)/\d+\s+dst\s+\w+:(?P<dst>[^/]+)/\d+",
            },
            "mapping": {
                "fields": {
                    "src": "src_endpoint.ip",
                    "dst": "dst_endpoint.ip",
                    "proto": "connection_info.protocol_name",
                    "disposition": "disposition",
                },
                "values": {
                    "disposition": {"Deny": "Blocked", "Built": "Allowed"},
                },
                "timestamp": {"source": "ingest_time"},
            },
        }, sort_keys=False)

    # 3. FortiGate Key=Value Sniffer
    if "devname=" in sample or "type=" in sample:
        return yaml.dump({
            "source_id": "fortigate",
            "version": "v1",
            "channel": channel,
            "fingerprint": {"type": "contains", "pattern": 'type="traffic"'},
            "tokenize": {"type": "kv", "pair_sep": " ", "kv_sep": "="},
            "mapping": {
                "fields": {
                    "srcip": "src_endpoint.ip",
                    "dstip": "dst_endpoint.ip",
                    "action": "disposition",
                    "proto": "connection_info.protocol_name",
                },
                "values": {
                    "disposition": {"deny": "Blocked", "allow": "Allowed", "close": "Allowed"},
                },
                "timestamp": {"source": "ingest_time"},
            },
        }, sort_keys=False)

    # 4. Generic Key-Value Sniffer
    kv_pairs = re.findall(r"(\w+)=(\S+)", sample)
    fields = {k: f"unmapped.{k}" for k, _ in kv_pairs[:6]} if kv_pairs else {"raw": "unmapped.raw"}
    first_token = sample.split()[0] if sample else "device"
    return yaml.dump({
        "source_id": safe_name,
        "version": "v1",
        "channel": channel,
        "fingerprint": {"type": "contains", "pattern": first_token},
        "tokenize": {"type": "kv", "pair_sep": " ", "kv_sep": "="},
        "mapping": {
            "fields": fields,
            "values": {},
            "timestamp": {"source": "ingest_time"},
        },
    }, sort_keys=False)


def generate_proposal_for_channel(channel: str) -> dict:
    """
    Generate a parser proposal for a given channel with config awareness.
    
    This enhanced version:
    1. Scans ConfigRegistry for similar patterns before generating proposal
    2. Generates the proposal using Ollama or heuristic fallback
    3. Checks for duplicate field mappings after generation
    4. Returns ProposalResult with ConfigAwarenessReport
    
    Args:
        channel: The channel identifier to generate proposal for
        
    Returns:
        Dictionary representation of ProposalResult
    """
    grouped = dlq_store.pending_grouped_by_channel()
    entries = grouped.get(channel, [])
    samples = [e["raw_snippet"] for e in entries]
    
    # Initialize config registry and scan existing parsers
    registry = get_registry()
    try:
        registry.scan_configs()
    except Exception as e:
        logger.warning(f"Failed to scan config registry: {e}")
    
    # Step 1: Find similar parsers before generating proposal
    similar_parsers: List[str] = []
    extends_existing: Optional[str] = None
    
    # Get existing channels to check for similarity
    existing_channels = registry.get_supported_channels()
    if channel in existing_channels:
        # Channel already exists - recommend extending
        similar_parsers = [channel]
        extends_existing = channel
        logger.info(f"Channel '{channel}' already has a parser - recommending extension")
    else:
        # Try to find parsers with similar fingerprint patterns
        # Use channel name as a proxy for pattern matching
        similar_configs = registry.find_similar_fingerprint(channel)
        similar_parsers = [p.source_id for p in similar_configs]
        if similar_parsers:
            extends_existing = similar_parsers[0]
            logger.info(f"Found {len(similar_parsers)} similar parsers for channel '{channel}'")
    
    # Step 2: Generate proposal using existing methods
    proposal_yaml, source_tag = _call_ollama(channel, samples)
    if not proposal_yaml:
        proposal_yaml = _heuristic_skeleton(channel, samples)
        source_tag = "Deterministic Heuristic Pattern Sniffer (Air-Gapped)"
    
    # Step 3: Parse the generated YAML to extract field mappings
    new_mapping: Dict[str, str] = {}
    try:
        parsed_yaml = yaml.safe_load(proposal_yaml)
        if parsed_yaml and isinstance(parsed_yaml, dict):
            mapping_section = parsed_yaml.get("mapping", {})
            if mapping_section and isinstance(mapping_section, dict):
                new_mapping = mapping_section.get("fields", {})
    except Exception as e:
        logger.warning(f"Failed to parse generated YAML for field extraction: {e}")
    
    # Step 4: Check for duplicate field mappings
    duplicate_warnings: List[str] = []
    if new_mapping:
        try:
            duplicate_warnings = registry.get_duplicate_warnings(new_mapping)
        except Exception as e:
            logger.warning(f"Failed to get duplicate warnings: {e}")
    
    # Step 5: Build recommendations
    recommendations: List[str] = []
    
    if extends_existing:
        recommendations.append(
            f"Consider extending existing parser '{extends_existing}' instead of creating new one"
        )
        recommendations.append(
            f"Existing parser handles similar log format - review {extends_existing}_v1.yaml for patterns"
        )
    
    # Add recommendations based on duplicate warnings
    if duplicate_warnings:
        recommendations.append(
            "Review field mappings to avoid conflicts with existing parsers"
        )
    
    # Check if we have enough samples to make a good proposal
    if len(samples) < 3:
        recommendations.append(
            "Consider waiting for more samples before finalizing parser (fewer than 3)"
        )
    
    # Step 6: Build config awareness report
    config_awareness = ConfigAwarenessReport(
        similar_parsers=similar_parsers,
        duplicate_warnings=duplicate_warnings,
        recommendations=recommendations,
        extends_existing=extends_existing
    )
    
    # Generate filename
    safe_name = re.sub(r"\W+", "_", channel).strip("_") or "proposed_device"
    filename = f"{safe_name}_proposed.yaml"
    
    # Save candidate to proposed directory
    out_path = config.PARSER_PROPOSED_DIR / filename
    out_path.write_text(proposal_yaml)
    
    # Create ProposalResult and return as dictionary
    proposal_result = ProposalResult(
        channel=channel,
        filename=filename,
        yaml=proposal_yaml,
        generator=source_tag,
        sample_count=len(samples),
        config_awareness=config_awareness
    )
    
    return proposal_result.to_dict()


def promote_proposal_yaml(filename: str, yaml_content: str) -> Tuple[bool, str]:
    """
    Validates YAML syntax, runs the pytest regression corpus, and if green,
    installs the new parser into the live config directory and reloads the engine.
    """
    # 1. Validate YAML syntax
    try:
        parsed_doc = yaml.safe_load(yaml_content)
        if not isinstance(parsed_doc, dict) or "source_id" not in parsed_doc:
            return False, "Invalid YAML: Missing mandatory 'source_id' key."
    except Exception as e:
        return False, f"YAML Syntax Error: {e}"

    # 2. Write to proposed file
    prop_path = config.PARSER_PROPOSED_DIR / filename
    prop_path.write_text(yaml_content)

    # 3. Run regression test suite (Pytest)
    cmd = [sys.executable, "-m", "pytest", "tests/", "-q"]
    try:
        res = subprocess.run(cmd, cwd=config.BASE_DIR, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            return False, f"Regression tests FAILED! Promotion rejected to prevent breaking existing parsers.\nOutput: {res.stdout or res.stderr}"
    except Exception as e:
        return False, f"Failed executing regression test suite: {e}"

    # 4. Copy to live parser configs
    dest_name = filename.replace("_proposed", "")
    if not dest_name.endswith(".yaml"):
        dest_name += ".yaml"
    dest_path = config.PARSER_CONFIG_DIR / dest_name
    shutil.copy(prop_path, dest_path)

    # 5. Reload running parser engine
    from src.pipeline import get_engine
    engine = get_engine()
    engine.reload()

    # 6. Mark DLQ entries as promoted
    grouped = dlq_store.pending_grouped_by_channel()
    channel = parsed_doc.get("channel")
    if channel and channel in grouped:
        dlq_store.mark_status([e["id"] for e in grouped[channel]], status="promoted")

    return True, f"Regression tests passed (4/4)! Promoted {dest_name} to live registry with zero downtime."
# DLQ Processor Background Scheduler

def start_dlq_processor(
    time_threshold_sec: int = 60,
    count_threshold: int = 20,
    auto_start: bool = True
) -> DLQProcessor:
    """
    Initialize and optionally start the DLQ processor background scheduler.
    
    The DLQ processor monitors the dead letter queue and automatically generates
    parser proposals when either:
    - Time threshold is met (default: 60 seconds since last processing)
    - Count threshold is met (default: 20 pending entries)
    
    Args:
        time_threshold_sec: Time threshold in seconds (default: 60)
        count_threshold: Count threshold for pending entries (default: 20)
        auto_start: If True, immediately process pending entries (default: True)
    
    Returns:
        Initialized DLQProcessor instance
    
    Example:
        >>> processor = start_dlq_processor(time_threshold_sec=30, count_threshold=10)
        >>> # The processor will now run in the background
    """
    processor = get_processor(
        time_threshold_sec=time_threshold_sec,
        count_threshold=count_threshold
    )
    
    if auto_start:
        logger.info("DLQ processor auto-start enabled, processing pending entries...")
        result = processor.process_pending()
        logger.info(
            f"Initial processing complete: {result.channels_processed} channels, "
            f"{result.entries_processed} entries"
        )
    
    return processor


def get_dlq_processor() -> DLQProcessor:
    """
    Get the current DLQProcessor instance.
    
    Returns:
        The singleton DLQProcessor instance
    """
    return get_processor()