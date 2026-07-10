from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
)

TEXT_SUFFIXES = {".md", ".py", ".toml", ".txt", ".yml", ".yaml", ".json"}
EXCLUDED_PARTS = {".git", "__pycache__", "tests"}


def iter_files(repo_root: Path):
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    hits: list[str] = []

    for path in iter_files(repo_root):
        text = path.read_text(encoding="utf-8")
        for label, pattern in PATTERNS:
            if pattern.search(text):
                hits.append(f"{label}: {path.relative_to(repo_root)}")

    if hits:
        print("Potential committed secrets detected:")
        for hit in hits:
            print(f"- {hit}")
        return 1

    print("Curated secret check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
