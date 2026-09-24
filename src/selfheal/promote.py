"""
Promote a proposed parser config (from src/parser/configs/proposed/) into
the live registry -- but only after:
  1. A human has manually edited/reviewed the file (this script does NOT
     auto-approve anything by itself).
  2. The existing regression test suite still passes, so a "fix" for one
     format variant can't silently break a previously-working one.

Usage:
    python -m src.selfheal.promote src/parser/configs/proposed/udp_5514_proposed.yaml
"""
import shutil
import subprocess
import sys
from pathlib import Path

from src import config


def promote(proposed_path: str):
    src = Path(proposed_path)
    if not src.exists():
        print(f"No such file: {src}")
        sys.exit(1)

    print("Running regression tests against known-good fixtures before promoting...")
    result = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], cwd=config.BASE_DIR)
    if result.returncode != 0:
        print("\nRegression tests FAILED. Refusing to promote -- this proposed config "
              "would have broken previously-working parsing. Fix it and re-run.")
        sys.exit(1)

    dest_name = src.stem.replace("_proposed", "") + ".yaml"
    dest = config.PARSER_CONFIG_DIR / dest_name
    shutil.copy(src, dest)
    print(f"Regression tests passed. Promoted:\n  {src}\n  -> {dest}")
    print("The running pipeline will pick this up on its next config reload.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m src.selfheal.promote <path-to-proposed-yaml>")
        sys.exit(1)
    promote(sys.argv[1])
