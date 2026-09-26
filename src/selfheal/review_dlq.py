"""
One-shot self-heal pass from the command line (the running server does this
continuously in the background -- see src/selfheal/dlq_processor.py).

    python -m src.selfheal.review_dlq            # propose for clusters that meet the thresholds
    python -m src.selfheal.review_dlq --all      # propose for every pending cluster now

It NEVER promotes anything. Review proposals in the console (/selfheal) or
promote from the CLI with:  python -m src.selfheal.promote <proposal_id>
"""
import argparse

from src.dlq import store as dlq_store
from src.selfheal.dlq_processor import get_processor


def run(force_all: bool = False):
    clusters = dlq_store.pending_clusters()
    if not clusters:
        print("No pending DLQ entries. Nothing to review.")
        return
    proc = get_processor()
    for c in clusters:
        d = proc.evaluate(c)
        print(f"[{c['cluster_id']}] {c['label']:<60} {c['count']:>5} pending  state={d['state']}")
    created = proc.tick(force_cluster="*" if force_all else None)
    for p in created:
        v = p["validation"] or {}
        print(f"\nProposal #{p['id']} for {p['cluster_label']}")
        print(f"  file:       src/parser/configs/proposed/{p['filename']}")
        print(f"  generator:  {p['generator']}")
        print(f"  validation: {v.get('parsed')}/{v.get('total')} samples, "
              f"regression {'PASSED' if (v.get('regression') or {}).get('passed') else 'FAILED'}")
        for r in (p["awareness"] or {}).get("recommendations", []):
            print(f"  note:       {r}")
    if not created:
        print("\nNo cluster met the thresholds yet (use --all to force).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="ignore thresholds and propose for every cluster")
    run(ap.parse_args().all)
