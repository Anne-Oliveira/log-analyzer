"""Achados (findings) produzidos pelos detectores."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any

from log_analyzer.models import LogEntry


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    """Um achado de segurança, com a evidência que o sustenta."""

    rule: str
    severity: Severity
    title: str
    description: str = ""
    ip: str | None = None
    user: str | None = None
    count: int = 0
    first_seen: datetime | None = None  # sempre em UTC
    last_seen: datetime | None = None   # sempre em UTC
    evidence: list[LogEntry] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "title": self.title,
            "description": self.description,
            "ip": self.ip,
            "user": self.user,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "details": self.details,
            "evidence": [
                {"file": e.file, "line_number": e.line_number, "raw": e.raw}
                for e in self.evidence
            ],
        }