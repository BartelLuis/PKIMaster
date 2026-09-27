"""One monitoring cycle against the packaged application's existing state."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import sys

from pkimaster_server import STATE_DIRECTORY, runtime_application

STATUSES = frozenset({"checked", "busy", "failed", "restore_pending"})


def run_once(instance_path: Path = STATE_DIRECTORY):
    from backup import RestoreBusy, restore_pending
    from monitoring import run_monitoring_cycle
    instance_path = Path(instance_path)
    if restore_pending(instance_path):
        return {"status": "restore_pending"}
    try:
        application = runtime_application(instance_path)
    except RestoreBusy:
        return {"status": "restore_pending" if restore_pending(instance_path) else "busy"}
    with application.app_context():
        return run_monitoring_cycle()


def main():
    if len(sys.argv) != 1:
        print('{"status": "invalid_arguments"}')
        return 2
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with redirect_stdout(sink), redirect_stderr(sink):
                result = run_once()
        status = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status, str) or status not in STATUSES:
            raise ValueError("Unexpected monitoring status.")
        summary = {"status": status}
        for field in ("active", "delivered"):
            value = result.get(field)
            if type(value) is int and 0 <= value <= 2**63 - 1:
                summary[field] = value
    except Exception:
        summary = {"status": "failed"}
    print(json.dumps(summary, sort_keys=True))
    return 1 if summary["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
