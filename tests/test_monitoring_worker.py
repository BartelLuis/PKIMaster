from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from flask import Flask, has_app_context

from backup import RestoreBusy
import monitoring_worker


class MonitoringWorkerTests(unittest.TestCase):
    def test_dispatch_uses_packaged_state_and_closes_application_context(self):
        application = Flask(__name__)
        with patch("backup.restore_pending", return_value=False):
            with patch.object(monitoring_worker, "runtime_application", return_value=application) as factory:
                with patch("monitoring.run_monitoring_cycle", return_value={"status": "checked", "active": 2}) as cycle:
                    self.assertEqual(monitoring_worker.run_once(), {"status": "checked", "active": 2})
        factory.assert_called_once_with(Path("/var/lib/pkimaster"))
        cycle.assert_called_once_with()
        self.assertFalse(has_app_context())

    def test_restore_pending_prevents_application_initialization(self):
        with patch("backup.restore_pending", return_value=True):
            with patch.object(monitoring_worker, "runtime_application") as factory:
                self.assertEqual(monitoring_worker.run_once(), {"status": "restore_pending"})
        factory.assert_not_called()

    def test_startup_lock_contention_is_normal_busy_work(self):
        with patch("backup.restore_pending", return_value=False):
            with patch.object(monitoring_worker, "runtime_application", side_effect=RestoreBusy("busy")):
                self.assertEqual(monitoring_worker.run_once(), {"status": "busy"})

    def invoke(self, result=None, error=None, arguments=()):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(monitoring_worker, "run_once", return_value=result, side_effect=error) as worker:
            with patch.object(sys, "argv", ["monitoring_worker.py", *arguments]):
                with redirect_stdout(output), redirect_stderr(errors):
                    status = monitoring_worker.main()
        self.assertEqual(errors.getvalue(), "")
        return status, json.loads(output.getvalue()), worker

    def test_cli_emits_only_allowlisted_numeric_summary(self):
        code, result, _ = self.invoke({"status": "checked", "active": 3, "delivered": 2, "token": "SECRET"})
        self.assertEqual((code, result), (0, {"status": "checked", "active": 3, "delivered": 2}))
        code, result, _ = self.invoke({"status": "checked", "active": True, "delivered": "SECRET"})
        self.assertEqual((code, result), (0, {"status": "checked"}))

    def test_cli_failure_and_unknown_results_are_sanitized(self):
        code, result, _ = self.invoke(error=RuntimeError("SECRET"))
        self.assertEqual((code, result), (1, {"status": "failed"}))
        for bad in (None, {"status": "SECRET"}, {"status": []}):
            code, result, _ = self.invoke(bad)
            self.assertEqual((code, result), (1, {"status": "failed"}))

    def test_cli_rejects_state_path_override(self):
        code, result, worker = self.invoke(arguments=("--instance-path", "/tmp/other-pki"))
        self.assertEqual((code, result), (2, {"status": "invalid_arguments"}))
        worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
