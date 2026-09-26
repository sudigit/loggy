"""
Config awareness for self-heal proposals: before a human reviews a proposed
parser, tell them how it relates to what is already live.

  * drift       -- DLQ events that matched an existing parser's fingerprint but
                   failed its tokenizer/schema => the vendor changed format;
                   extend that parser instead of adding an unrelated one
  * overlap     -- existing parsers whose fingerprint also matches these samples
  * conflicts   -- a vendor field name mapped to a DIFFERENT OCSF path elsewhere
                   (inconsistent taxonomy across parsers)
  * replaces    -- the proposal reuses a live source_id (promotion will version it)
"""
from collections import Counter


def _field_index(configs: list) -> dict:
    idx = {}
    for c in configs:
        for src, dest in ((c.get("mapping") or {}).get("fields") or {}).items():
            for d in (dest if isinstance(dest, list) else [dest]):
                idx.setdefault(src, set()).add((d, c["source_id"]))
    return idx


def awareness(proposed: dict, samples: list, parser_ids: list, engine) -> dict:
    live = {c["source_id"]: c for c in engine.configs}
    similar, recommendations, conflicts = [], [], []

    drift_parent = Counter(p for p in parser_ids if p).most_common(1)
    drift_parent = drift_parent[0][0] if drift_parent else None
    if drift_parent:
        similar.append({"source_id": drift_parent,
                        "reason": "Samples matched this parser's fingerprint but failed to parse (format drift)."})
        recommendations.append(
            f"Format drift in '{drift_parent}': the proposal extends it as a variant and keeps its product metadata.")

    for sid, c in live.items():
        if sid == drift_parent:
            continue
        hits = sum(1 for s in samples if engine.fingerprint_matches(s, c["_fingerprint"]))
        if hits:
            similar.append({"source_id": sid,
                            "reason": f"Fingerprint also matches {hits}/{len(samples)} samples."})

    idx = _field_index(list(live.values()))
    for src, dest in ((proposed.get("mapping") or {}).get("fields") or {}).items():
        dests = dest if isinstance(dest, list) else [dest]
        for existing_dest, sid in sorted(idx.get(src, ())):
            if existing_dest not in dests and sid != proposed.get("source_id"):
                conflicts.append(f"'{src}' -> '{dests[0]}' here, but '{existing_dest}' in {sid}")

    if proposed.get("source_id") in live:
        recommendations.append(
            f"'{proposed['source_id']}' is live; promotion archives the current version (rollback available).")
    if conflicts:
        recommendations.append("Review taxonomy conflicts so the same vendor field means the same thing everywhere.")

    return {
        "similar_parsers": similar,
        "conflicts": conflicts[:10],
        "recommendations": recommendations,
        "extends_existing": drift_parent,
    }
