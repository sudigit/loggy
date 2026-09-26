"""
Human-gated promotion of a self-heal proposal from the command line.

    python -m src.selfheal.promote <proposal_id> [--yaml edited.yaml]
    python -m src.selfheal.promote --rollback <source_id>

Promotion re-validates the proposal against its DLQ samples, runs the
regression corpus (every known source must still parse identically), archives
the previous parser version, hot-reloads the engine and replays the
quarantined events from the raw archive.
"""
import argparse
import sys
from pathlib import Path

from src.selfheal import service


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("proposal_id", nargs="?", type=int)
    ap.add_argument("--yaml", help="promote this (hand-edited) YAML instead of the stored proposal")
    ap.add_argument("--rollback", metavar="SOURCE_ID", help="restore the previous version of a parser")
    ap.add_argument("--by", default="cli-operator", help="approver name recorded in the parser header")
    args = ap.parse_args()

    if args.rollback:
        r = service.rollback(args.rollback)
        print(r.get("message") or r.get("error"))
        sys.exit(0 if r["success"] else 1)
    if args.proposal_id is None:
        ap.print_help()
        sys.exit(1)

    yaml_text = Path(args.yaml).read_text(encoding="utf-8") if args.yaml else None
    r = service.promote(args.proposal_id, yaml_text=yaml_text, approved_by=args.by)
    print(r.get("message") if r["success"] else f"REJECTED: {r['error']}")
    sys.exit(0 if r["success"] else 1)


if __name__ == "__main__":
    main()
