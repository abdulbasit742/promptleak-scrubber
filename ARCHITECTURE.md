# Architecture

PromptLeak Scrubber keeps the first release intentionally small and auditable.

## Flow

1. The CLI resolves a target path.
2. The scanner walks supported text files recursively.
3. Each line is evaluated against a curated rule set.
4. Findings are emitted with masked previews so secrets are never reprinted in full.
5. The redaction path applies deterministic replacements and writes a sanitized copy.

## Modules

- `patterns.py` — high-confidence regex rules and redaction callbacks
- `models.py` — immutable finding model and serialization helpers
- `scanner.py` — file walking, text scanning, and redaction logic
- `cli.py` — command-line interface and exit-code behavior
- `scripts/curated_secret_check.py` — repository self-audit guard used by CI

## Safety choices

- Only text-like files are scanned in the initial release.
- Redaction is deterministic and label-based rather than reversible hashing.
- Findings show masked previews instead of raw matches.
- The `redact` command only rewrites explicit target files; it never edits directories in place.

## Known limitations

- Pattern matching is heuristic and may miss custom token formats.
- Structured JSON redaction preserves text safely but does not yet annotate schema-level context.
- Prompt-instruction detection is marker-based, not semantic.
