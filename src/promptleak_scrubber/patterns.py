from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    severity: str
    description: str
    pattern: re.Pattern[str]
    redactor: Callable[[re.Match[str]], str]


def mask_preview(value: str) -> str:
    compact = value.strip().replace("\n", " ")
    if len(compact) <= 4:
        return compact
    if len(compact) <= 8:
        return f"{compact[:2]}…{compact[-1:]}"
    return f"{compact[:4]}…{compact[-2:]}"


def _replace_group(match: re.Match[str], group: str, label: str) -> str:
    return match.group(0).replace(match.group(group), f"[REDACTED:{label}]")


RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="openai-api-key",
        severity="high",
        description="Possible OpenAI-style API key in trace content.",
        pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        redactor=lambda match: "[REDACTED:OPENAI_KEY]",
    ),
    RuleDefinition(
        rule_id="anthropic-api-key",
        severity="high",
        description="Possible Anthropic-style API key in trace content.",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        redactor=lambda match: "[REDACTED:ANTHROPIC_KEY]",
    ),
    RuleDefinition(
        rule_id="github-token",
        severity="high",
        description="Possible GitHub token in trace content.",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        redactor=lambda match: "[REDACTED:GITHUB_TOKEN]",
    ),
    RuleDefinition(
        rule_id="bearer-token",
        severity="high",
        description="Bearer token header found in trace content.",
        pattern=re.compile(r"Authorization:\s*Bearer\s+(?P<token>[A-Za-z0-9._-]{16,})", re.IGNORECASE),
        redactor=lambda match: _replace_group(match, "token", "BEARER_TOKEN"),
    ),
    RuleDefinition(
        rule_id="secret-assignment",
        severity="high",
        description="Secret-like assignment found in trace content.",
        pattern=re.compile(
            r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token)\b\s*[:=]\s*(?P<quote>[\"'])?(?P<value>[^\s,\"']{6,})(?P=quote)?"
        ),
        redactor=lambda match: _replace_group(match, "value", "SECRET_VALUE"),
    ),
    RuleDefinition(
        rule_id="email-address",
        severity="medium",
        description="Email address found in trace content.",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        redactor=lambda match: "[REDACTED:EMAIL]",
    ),
    RuleDefinition(
        rule_id="phone-number",
        severity="medium",
        description="Phone number found in trace content.",
        pattern=re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{8,}\d)(?!\w)"),
        redactor=lambda match: "[REDACTED:PHONE]",
    ),
    RuleDefinition(
        rule_id="prompt-instructions",
        severity="medium",
        description="System or developer instruction marker found in trace content.",
        pattern=re.compile(r"(?im)^.*\b(?:system prompt|developer prompt|assistant instructions|internal instructions)\b.*$"),
        redactor=lambda match: "[REDACTED:PROMPT_INSTRUCTIONS]",
    ),
)

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".log", ".md", ".txt", ".yaml", ".yml"}
