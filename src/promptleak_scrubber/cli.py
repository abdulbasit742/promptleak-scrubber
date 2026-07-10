from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from promptleak_scrubber.scanner import redact_text, scan_path, scan_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptleak-scrubber")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for sensitive trace content")
    scan_parser.add_argument("path", help="Path to a file or directory")
    scan_parser.add_argument("--json", action="store_true", help="Emit findings as JSON")

    redact_parser = subparsers.add_parser("redact", help="Redact a single trace file and write a sanitized copy")
    redact_parser.add_argument("input", help="Path to the source trace file")
    redact_parser.add_argument("--output", required=True, help="Path to write the redacted file")

    return parser


def _print_findings(findings: list[object]) -> None:
    if not findings:
        print("No findings detected.")
        return

    unique_paths = {finding.path for finding in findings}
    print(f"{len(findings)} finding(s) across {len(unique_paths)} file(s)")
    for finding in findings:
        print(
            f"{finding.severity.upper()} {finding.rule_id} {finding.path}:{finding.line}:{finding.column} {finding.preview}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        findings = scan_path(Path(args.path))
        if args.json:
            print(json.dumps([finding.to_dict() for finding in findings], indent=2))
        else:
            _print_findings(findings)
        return 1 if findings else 0

    input_path = Path(args.input)
    if not input_path.is_file():
        parser.error("redact requires a single input file")

    original = input_path.read_text(encoding="utf-8")
    redacted = redact_text(original)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(redacted, encoding="utf-8")

    findings = scan_text(original, path=input_path.name)
    print(f"Redacted {len(findings)} finding(s) into {output_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
