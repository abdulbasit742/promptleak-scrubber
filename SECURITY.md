# Security Policy

## Supported versions

This project currently supports the latest `main` branch.

## Reporting a vulnerability

Please avoid filing public issues for unpatched critical or high-risk leaks. Instead, describe the affected rule path, impact, reproduction conditions, and the smallest safe remediation path.

Do not include live secrets, private traces, or exploit payloads in reports.

## Security principles

- Never print raw secret values in CLI findings.
- Prefer deterministic, local-first behavior over opaque cloud analysis.
- Keep CI permissions minimal.
- Add regression tests for every fixed vulnerability class.
