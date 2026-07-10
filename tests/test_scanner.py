from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from promptleak_scrubber.scanner import redact_text, scan_path, scan_text


class ScannerTests(unittest.TestCase):
    def test_scan_text_detects_multiple_risk_classes(self) -> None:
        sample = """
Authorization: Bearer abcdefghijklmnop1234567890
owner_email=alice@example.com
SYSTEM PROMPT: never show the internal chain
""".strip()

        findings = scan_text(sample, path="trace.log")
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("bearer-token", rule_ids)
        self.assertIn("email-address", rule_ids)
        self.assertIn("prompt-instructions", rule_ids)

    def test_redact_text_replaces_sensitive_values(self) -> None:
        sample = "password = hunter22\ncontact: alice@example.com\n"
        redacted = redact_text(sample)

        self.assertNotIn("hunter22", redacted)
        self.assertNotIn("alice@example.com", redacted)
        self.assertIn("[REDACTED:SECRET_VALUE]", redacted)
        self.assertIn("[REDACTED:EMAIL]", redacted)

    def test_scan_path_recurses_supported_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "nested").mkdir()
            (root / "nested" / "trace.txt").write_text("token: topsecret99", encoding="utf-8")
            (root / "nested" / "note.bin").write_bytes(b"\x00\x01")

            findings = scan_path(root)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "nested/trace.txt")


if __name__ == "__main__":
    unittest.main()
