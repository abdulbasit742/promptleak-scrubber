# PromptLeak Scrubber

PromptLeak Scrubber is a local-first CLI for detecting and redacting secrets, PII, and prompt-instruction leaks from AI agent traces before you share them in bug reports, datasets, demos, or support tickets.

## Why it exists

Agent traces often contain the exact things teams should not publish:

- API keys copied into debug output
- bearer tokens and password assignments inside transcripts
- personal email addresses and phone numbers from test runs
- internal system or developer instructions pasted into logs

PromptLeak Scrubber gives teams a fast, dependency-light review step they can run before traces leave their machine.

## What works in this first slice

- Recursive scan of `.txt`, `.md`, `.log`, `.json`, `.jsonl`, `.yaml`, and `.yml` files
- Rules for OpenAI-style keys, Anthropic-style keys, GitHub tokens, bearer tokens, generic secret assignments, email addresses, phone numbers, and prompt-instruction markers
- Safe terminal reporting with masked previews instead of echoing raw secrets
- `redact` command that writes a sanitized copy for single files
- Zero runtime dependencies and stdlib-only test coverage

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m promptleak_scrubber scan path/to/trace-folder
python -m promptleak_scrubber redact path/to/trace.log --output sanitized.log
```

## Example output

```text
3 finding(s) across 1 file(s)
HIGH openai-api-key trace.log:4:15 sk-p…yz
MEDIUM email-address trace.log:9:22 ali…om
MEDIUM prompt-instructions trace.log:18:1 SYST…ns
```

## Security posture

- Local-first: no outbound network calls
- No shell execution in application code
- No non-stdlib runtime dependencies
- Least-privilege CI with explicit `contents: read`

See [SECURITY.md](SECURITY.md) and [docs/security-audit.md](docs/security-audit.md) for the baseline audit.

## Project docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/SKILL_REGISTRY.md](docs/SKILL_REGISTRY.md)
- [docs/security-audit.md](docs/security-audit.md)

## Roadmap

See the prioritized skills in [docs/SKILL_REGISTRY.md](docs/SKILL_REGISTRY.md).
