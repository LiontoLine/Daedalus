"""Allow `python -m daedalus ...` as an alias for the `daedalus` console script.

The console script is installed by `pip install -e .`, but the CLI is also useful straight
from a source checkout (and from `scripts/live_check.py`, which boots the service as a real
subprocess). Depending on the installed shim there would tie the check to an editable
install, so the module entry point is provided instead.
"""

from __future__ import annotations

from daedalus.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
