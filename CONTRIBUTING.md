# Contributing

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
python scripts/curated_secret_check.py
```

## Change policy

- Keep runtime dependencies at zero unless a change is clearly justified.
- Add tests for every new rule or redaction behavior.
- Do not commit live credentials, private datasets, or copied proprietary traces.
- Keep CLI behavior predictable: explicit paths, explicit output files, explicit exit codes.

## Pull requests

- Describe the risk model or user pain being addressed.
- Include validation evidence.
- Update `docs/security-audit.md` when behavior or security scope changes.
- Update `docs/SKILL_REGISTRY.md` when a skill lands or a new one is discovered.
