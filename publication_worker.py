"""Run one publication cycle using the packaged application's existing state."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import sys

from pkimaster_server import STATE_DIRECTORY, runtime_application


STATUSES = frozenset({"disabled", "idle", "busy", "published", "failed", "waiting"})


def run_once(instance_path: Path = STATE_DIRECTORY) -> dict:
    """Dispatch within the same Flask configuration and database as the service."""
    from backup import RestoreBusy, restore_pending
    if restore_pending(Path(instance_path)):
        return {"status": "waiting"}
    try:
        application = runtime_application(Path(instance_path))
    except RestoreBusy:
        return {"status": "busy"}
    with application.app_context():
        from publication import run_publication_cycle

        return run_publication_cycle()


def main() -> int:
    # The package has one state location. Settings and credentials come from the
    # web-managed database; command-line and environment overrides are unsupported.
    if len(sys.argv) != 1:
        print('{"status": "invalid_arguments"}')
        return 2
    try:
        # Third-party diagnostics can include connection details or credentials.
        # The web-managed publication record is the source of detailed status.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with redirect_stdout(sink), redirect_stderr(sink):
                result = run_once()
        status = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status, str) or status not in STATUSES:
            raise ValueError("Unexpected publication status.")
        summary = {"status": status}
        for field in ("generation", "crl_number"):
            value = result.get(field)
            if type(value) is int and 0 <= value <= 2**63 - 1:
                summary[field] = value
    except Exception:
        # Never serialize the exception, traceback, raw result, or provider data.
        summary = {"status": "failed"}
    print(json.dumps(summary, sort_keys=True))
    return 1 if summary["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
