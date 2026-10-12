"""Estrutura comum a todos os relatórios."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from log_analyzer.analyzers.stats import LogStats
from log_analyzer.findings import Finding, Severity

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def fmt_dt(moment: datetime | None) -> str:
    """Horário legível em UTC (ou '-' quando não há)."""
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC") if moment else "-"


@dataclass
class ReportData:
    """Tudo o que um relatório precisa saber sobre uma análise."""

    stats: LogStats
    findings: list[Finding] = field(default_factory=list)
    source: str = ""
    log_format: str = ""
    parsed: int = 0
    skipped: int = 0
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.label: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def to_dict(self, top_n: int = 10) -> dict[str, Any]:
        return {
            "meta": {
                "source": self.source,
                "format": self.log_format,
                "generated_at": self.generated_at.isoformat(),
                "entries_parsed": self.parsed,
                "lines_skipped": self.skipped,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.severity_counts(),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats.to_dict(top_n),
        }


class Reporter(ABC):
    """Para criar um formato novo: herde, defina name/extension e implemente render()."""

    name = ""
    extension = ""
    encoding = "utf-8"

    @abstractmethod
    def render(self, data: ReportData) -> str:
        """Gera o relatório como texto."""

    def render_file(self, data: ReportData) -> str:
        """Versão usada ao gravar em arquivo (por padrão, igual a render)."""
        return self.render(data)

    def write(self, data: ReportData, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.render_file(data), encoding=self.encoding)
        return target