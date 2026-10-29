#!/usr/bin/env python3
"""Convenience entry point so the demo can be run without installing the package.

    python3 scripts/run_demo.py            # all offline scenarios
    python3 scripts/run_demo.py 01-legitimate-fix --keep
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from daedalus.demo import main  # noqa: E402  (path must be set up first)

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
