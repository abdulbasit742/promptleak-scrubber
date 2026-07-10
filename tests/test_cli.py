from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from promptleak_scrubber.cli import main


class CliTests(unittest.TestCase):
    def test_scan_command_returns_nonzero_when_findings_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace.log"
            trace_path.write_text("sk-proj-ABCDEFGHIJKLMNOPQRSTuvwx", encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = main(["scan", str(trace_path)])

        self.assertEqual(return_code, 1)
        self.assertIn("openai-api-key", stdout.getvalue())

    def test_scan_command_returns_zero_when_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace.log"
            trace_path.write_text("all clear here", encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = main(["scan", str(trace_path)])

        self.assertEqual(return_code, 0)
        self.assertIn("No findings detected", stdout.getvalue())

    def test_redact_command_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "trace.log"
            output_path = Path(temp_dir) / "sanitized.log"
            input_path.write_text("contact=alice@example.com", encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = main(["redact", str(input_path), "--output", str(output_path)])

        self.assertEqual(return_code, 0)
        self.assertTrue(output_path.exists())
        self.assertNotIn("alice@example.com", output_path.read_text(encoding="utf-8"))
        self.assertIn("Redacted 1 finding", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
