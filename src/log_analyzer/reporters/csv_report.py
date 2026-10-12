"""Relatório em CSV: um achado por linha."""
from __future__ import annotations

import csv
import io
from pathlib import Path

from log_analyzer.reporters.base import ReportData, Reporter

COLUMNS = [
    "severity", "rule", "title", "ip", "user", "count",
    "first_seen", "last_seen", "description", "evidence_refs", "sample_evidence",
]

# Texto iniciado por estes caracteres vira fórmula no Excel/Planilhas (CSV injection).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value):
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


class CsvReporter(Reporter):
    name = "csv"
    extension = ".csv"
    encoding = "utf-8-sig"  # o BOM faz o Excel reconhecer os acentos

    def render(self, data: ReportData) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(COLUMNS)
        for finding in data.findings:
            refs = "; ".join(f"{Path(e.file).name}:{e.line_number}" for e in finding.evidence)
            row = [
                finding.severity.label,
                finding.rule,
                finding.title,
                finding.ip or "",
                finding.user or "",
                finding.count,
                finding.first_seen.isoformat() if finding.first_seen else "",
                finding.last_seen.isoformat() if finding.last_seen else "",
                finding.description,
                refs,
                finding.evidence[0].raw if finding.evidence else "",
            ]
            writer.writerow([_safe_cell(value) for value in row])
        return buffer.getvalue()