#!/usr/bin/env python3
"""Install this checkout's single terminal command without pip or network access."""

import shlex
from pathlib import Path


def install(project: Path, home: Path) -> Path:
    destination = home / ".local" / "bin" / "daedalus"
    python = project / ".venv" / "bin" / "python"
    if not python.is_file():
        raise RuntimeError("project .venv/bin/python does not exist")
    body = (
        "#!/bin/sh\n"
        + "export PYTHONPATH="
        + shlex.quote(str(project / "src"))
        + '"${PYTHONPATH:+:$PYTHONPATH}"\n'
        + "exec "
        + shlex.quote(str(python))
        + ' -m daedalus "$@"\n'
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if (destination.exists() or destination.is_symlink()) and (
        destination.is_symlink() or "-m daedalus" not in destination.read_text()
    ):
        raise RuntimeError("an unrelated daedalus command already exists; refusing to replace it")
    destination.write_text(body)
    destination.chmod(0o755)
    rc = home / ".zshrc"
    marker = "# Daedalus terminal entry"
    existing = rc.read_text() if rc.exists() else ""
    if marker not in existing:
        with rc.open("a") as output:
            output.write("\n" + marker + '\nexport PATH="$HOME/.local/bin:$PATH"\n')
    return destination


if __name__ == "__main__":
    print(install(Path(__file__).resolve().parents[1], Path.home()))
