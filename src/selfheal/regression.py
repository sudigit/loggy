"""
Regression gate for parser changes.

tests/corpus/ holds known-good raw events for every onboarded source plus an
expectations file. Before ANY parser config goes live (manual or self-heal),
the candidate parser set must still route every corpus line to the same
source with the same OCSF class, and must still reject known garbage. So a
"fix" for one format variant can never silently break another source.
"""
from datetime import datetime, timezone

import yaml

from src import config

_FAKE_UID = "00000000-0000-4000-8000-000000000000"
_FAKE_RAW = {"sha256": "0" * 64, "raw_ref": "local://regression/" + _FAKE_UID, "size_bytes": 0}


def load_corpus() -> list:
    """Returns [(file_name, expectation_dict, [lines])]."""
    exp_path = config.REGRESSION_CORPUS_DIR / "expectations.yaml"
    if not exp_path.exists():
        return []
    expectations = yaml.safe_load(exp_path.read_text(encoding="utf-8")) or {}
    corpus = []
    for fname, exp in expectations.items():
        path = config.REGRESSION_CORPUS_DIR / fname
        if not path.exists():
            continue
        lines = [ln.rstrip("\r\n") for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        corpus.append((fname, exp, lines))
    return corpus


def run(engine) -> dict:
    from src.parser.engine import ParseError

    now = datetime.now(timezone.utc).isoformat()
    total, failures = 0, []
    for fname, exp, lines in load_corpus():
        expected_source = exp.get("source_id")
        for i, line in enumerate(lines, 1):
            total += 1
            where = f"{fname}:{i}"
            try:
                ev, cfg_used = engine.process(line, exp.get("channel", ""), _FAKE_UID, now, raw_info=_FAKE_RAW)
            except ParseError as e:
                if expected_source is not None:
                    failures.append(f"{where} expected {expected_source}, got DLQ ({e})")
                continue
            if expected_source is None:
                failures.append(f"{where} expected DLQ (garbage), but parsed by {cfg_used['source_id']}")
            elif cfg_used["source_id"] != expected_source:
                failures.append(f"{where} expected {expected_source}, but {cfg_used['source_id']} claimed it")
            elif "class_uid" in exp and ev["class_uid"] != exp["class_uid"]:
                failures.append(f"{where} expected class {exp['class_uid']}, got {ev['class_uid']}")
    return {"passed": not failures, "total": total, "failed": len(failures), "failures": failures[:25]}


def run_with(candidate_configs: list, base_configs: list = None) -> dict:
    """Regression-tests the live parser set with `candidate_configs` added
    (replacing any live config with the same source_id)."""
    from src.parser.engine import ParserEngine, _load_all_configs

    base = base_configs if base_configs is not None else _load_all_configs()
    replaced = {c["source_id"] for c in candidate_configs}
    merged = [c for c in base if c["source_id"] not in replaced] + list(candidate_configs)
    return run(ParserEngine(merged))
