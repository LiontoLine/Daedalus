"""Build tiny deterministic wheels for offline integrity tests, never real dependencies."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile


def make_wheel(
    root: Path, name="demo-dep", version="1.0", *, requires=(), extra_files=None
) -> Path:
    dist = name.replace("-", "_")
    prefix = f"{dist}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    metadata += "".join(f"Requires-Dist: {item}\n" for item in requires)
    files = {
        f"{dist}/__init__.py": b"",
        prefix + "/METADATA": metadata.encode(),
        prefix + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    files.update(extra_files or {})
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for file, content in sorted(files.items()):
        hashed = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow([file, "sha256=" + hashed, len(content)])
    writer.writerow([prefix + "/RECORD", "", ""])
    files[prefix + "/RECORD"] = record.getvalue().encode()
    root.mkdir(parents=True, exist_ok=True)
    wheel = root / f"{dist}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file, content in sorted(files.items()):
            archive.writestr(zipfile.ZipInfo(file, date_time=(2000, 1, 1, 0, 0, 0)), content)
    return wheel
