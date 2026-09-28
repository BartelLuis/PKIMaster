"""One automation cycle against the packaged installation's existing state."""
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import sys

from pkimaster_server import STATE_DIRECTORY, runtime_application

STATUSES = {"checked", "disabled", "busy", "failed", "restore_pending"}


def run_once(instance_path=STATE_DIRECTORY):
    from backup import RestoreBusy, restore_pending
    root = Path(instance_path)
    if restore_pending(root):
        return {"status": "restore_pending"}
    try:
        application = runtime_application(root)
    except RestoreBusy:
        return {"status": "restore_pending" if restore_pending(root) else "busy"}
    with application.app_context():
        from automation import run_automation_cycle
        return run_automation_cycle()


def main():
    if len(sys.argv) != 1:
        print('{"status":"invalid_arguments"}')
        return 2
    try:
        with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink), redirect_stderr(sink):
            result = run_once()
        if not isinstance(result, dict) or result.get("status") not in STATUSES:
            raise ValueError
        summary = {"status": result["status"]}
        for field in ("checked", "failed"):
            if type(result.get(field)) is int and 0 <= result[field] <= 2**63 - 1:
                summary[field] = result[field]
    except Exception:
        summary = {"status": "failed"}
    print(json.dumps(summary, sort_keys=True))
    return int(summary["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
