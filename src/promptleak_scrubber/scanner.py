from __future__ import annotations

from pathlib import Path
from typing import Iterable

from promptleak_scrubber.models import Finding
from promptleak_scrubber.patterns import RULES, SUPPORTED_SUFFIXES, mask_preview


def iter_text_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        yield target
        return

    for path in sorted(target.rglob("*")):
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
            yield path


def scan_text(text: str, path: str = "<memory>") -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                findings.append(
                    Finding(
                        path=path,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        line=line_number,
                        column=match.start() + 1,
                        preview=mask_preview(match.group(0)),
                        description=rule.description,
                    )
                )
    return findings


def scan_path(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    base = target if target.is_dir() else target.parent

    for path in iter_text_files(target):
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(base).as_posix() if path != target else path.name
        findings.extend(scan_text(text, path=relative))

    return sorted(findings, key=lambda item: (item.path, item.line, item.column, item.rule_id))


def redact_text(text: str) -> str:
    redacted = text
    for rule in RULES:
        redacted = rule.pattern.sub(rule.redactor, redacted)
    return redacted
