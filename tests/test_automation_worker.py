from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from flask import Flask, has_app_context

from backup import RestoreBusy
import automation_worker


class AutomationWorkerTests(unittest.TestCase):
    def test_dispatch_and_restore_gating(self):
        application = Flask(__name__)
        with patch("backup.restore_pending", return_value=False), patch.object(automation_worker, "runtime_application", return_value=application) as factory:
            with patch("automation.run_automation_cycle", return_value={"status": "checked", "checked": 3}) as cycle:
                self.assertEqual(automation_worker.run_once(), {"status": "checked", "checked": 3})
        factory.assert_called_once_with(Path("/var/lib/pkimaster"))
        cycle.assert_called_once_with()
        self.assertFalse(has_app_context())
        with patch("backup.restore_pending", return_value=True), patch.object(automation_worker, "runtime_application") as factory:
            self.assertEqual(automation_worker.run_once(), {"status": "restore_pending"})
            factory.assert_not_called()
        with patch("backup.restore_pending", return_value=False), patch.object(automation_worker, "runtime_application", side_effect=RestoreBusy("busy")):
            self.assertEqual(automation_worker.run_once(), {"status": "busy"})

    def test_cli_redacts_exceptions_and_provider_data(self):
        for result, error, expected in (({"status": "checked", "checked": 2, "secret": "password"}, None, {"status": "checked", "checked": 2}),
                                        (None, RuntimeError("secret"), {"status": "failed"}),
                                        ({"status": []}, None, {"status": "failed"})):
            stream = io.StringIO()
            with patch.object(sys, "argv", ["automation_worker.py"]), redirect_stdout(stream):
                with patch.object(automation_worker, "run_once", return_value=result, side_effect=error):
                    automation_worker.main()
            self.assertEqual(json.loads(stream.getvalue()), expected)


if __name__ == "__main__":
    unittest.main()
