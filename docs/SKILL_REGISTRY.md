# Skill Registry

## Completed

- **SKILL-000 — Initial trace scanning vertical slice**
  - Status: done
  - Shipped recursive trace scanning, deterministic redaction, masked CLI reporting, CI, docs, and baseline security audit.

## Backlog

- **SKILL-001 — SARIF export for leak findings**
  - Priority: high
  - Why: lets teams surface trace leaks directly in code scanning and CI review flows.

- **SKILL-002 — Allowlist and expiry-aware suppressions**
  - Priority: high
  - Why: helps teams manage known-safe prompts or fixture data without hiding unsuppressed leaks.

- **SKILL-003 — Structured JSONL redaction summaries**
  - Priority: medium
  - Why: preserves event boundaries for agent traces instead of treating everything as plain text.

- **SKILL-004 — Path and hostname minimization**
  - Priority: medium
  - Why: local developer paths and internal hostnames often leak environment details even when secrets are removed.
