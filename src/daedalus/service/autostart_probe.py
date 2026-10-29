"""Disposable macOS supervisor crash check; never signals the production backend."""

from __future__ import annotations

import json
import os
import signal
import socket
import time
import urllib.request

from daedalus.domain.ids import new_id, utc_now
from daedalus.infrastructure.knowledge import atomic_json
from daedalus.service import autostart


def run_probe(settings):
    root = settings.workspace.root_path / "service-checks" / new_id("launchd_probe")
    root.mkdir(parents=True)
    config = root / "probe.toml"
    workspace = root / "workspace"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config.write_text(
        "[workspace]\nroot = "
        + json.dumps(str(workspace))
        + f'\n[service]\nhost = "127.0.0.1"\nport = {port}\n'
    )
    config.chmod(0o600)
    label = autostart.label_for(config)
    report = {
        "status": "RUNNING",
        "started_at": utc_now(),
        "workspace": str(workspace),
        "production_workspace": str(settings.workspace.root_path),
        "automatic_resume": False,
        "scope": "disposable empty workspace; process hosting only, no model or delivery proof",
    }
    atomic_json(root / "report.json", report)

    def health():
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as response:
            row = json.load(response)
        if row.get("workspace") != str(workspace):
            raise ValueError("probe port belongs to another workspace")
        return row

    def wait_fresh(previous="", limit=75):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            try:
                row = health()
                if row["service_session_id"] != previous:
                    return row
            except (OSError, ValueError):
                pass
            time.sleep(0.25)
        raise TimeoutError("disposable launchd service did not become ready")

    try:
        autostart.install(config, workspace)
        before = wait_fresh()
        report.update(before=before)
        atomic_json(root / "report.json", report)
        controller = json.loads((workspace / ".service/controller.json").read_text())
        # Validate identity against a new response and the fixture controller before signalling.
        current = health()
        if current["process_id"] != controller.get("backend_pid") or current != before:
            raise ValueError("disposable backend identity changed")
        if current["process_id"] == os.getpid():
            raise ValueError("refusing to signal production process")
        os.kill(current["process_id"], signal.SIGKILL)
        report.update(crash_signal_sent=True)
        atomic_json(root / "report.json", report)
        after = wait_fresh(before["service_session_id"])
        report.update(after=after, crash_relaunched=True)
        atomic_json(root / "report.json", report)
        if after["dispatcher"]["active"] or after["dispatcher"]["dispatched"]:
            raise ValueError("unexpected work in disposable workspace")
        from daedalus.service.control import command

        # HTTP may be ready before its supervisor records that same session as running.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            controller = json.loads((workspace / ".service/controller.json").read_text())
            if (
                controller.get("status") == "running"
                and controller.get("backend_pid") == after["process_id"]
                and controller.get("session_id") == after["service_session_id"]
            ):
                break
            time.sleep(0.2)
        else:
            raise TimeoutError("disposable supervisor did not acknowledge its ready session")
        command("stop", config, wait_timeout=30)
        time.sleep(3)
        normal_stop = not autostart.status(config)["running"]
        if not normal_stop:
            raise ValueError("normal stop unexpectedly relaunched")
        report.update(
            status="PASS",
            before=before,
            after=after,
            crash_relaunched=True,
            normal_stop_stayed_stopped=True,
            normal_stop_observation_seconds=3,
        )
    except Exception as error:  # noqa: BLE001 - preserve actual failure, no model dispatch
        report.update(status="FAIL", error_type=type(error).__name__, detail=str(error)[:800])
    finally:
        try:
            autostart.command("bootout", f"gui/{os.getuid()}/{label}")
            autostart.plist_for(config).unlink(missing_ok=True)
            report["cleaned_up"] = True
        except Exception as error:  # noqa: BLE001 - keep label for manual cleanup if OS refuses
            report.update(cleaned_up=False, cleanup_error=type(error).__name__, label=label)
        report["finished_at"] = utc_now()
        atomic_json(root / "report.json", report)
    return report
