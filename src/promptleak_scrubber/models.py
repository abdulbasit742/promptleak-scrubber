from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Finding:
    path: str
    rule_id: str
    severity: str
    line: int
    column: int
    preview: str
    description: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
