"""Registro dos relatórios disponíveis."""
from __future__ import annotations

from log_analyzer.reporters.base import ReportData, Reporter
from log_analyzer.reporters.console import ConsoleReporter
from log_analyzer.reporters.csv_report import CsvReporter
from log_analyzer.reporters.html_report import HtmlReporter
from log_analyzer.reporters.json_report import JsonReporter

REPORTERS: dict[str, type[Reporter]] = {
    "console": ConsoleReporter,
    "json": JsonReporter,
    "csv": CsvReporter,
    "html": HtmlReporter,
}

__all__ = ["REPORTERS", "ReportData", "Reporter", "get_reporter"]


def get_reporter(name: str, **kwargs) -> Reporter:
    reporter_class = REPORTERS.get(name)
    if reporter_class is None:
        opcoes = ", ".join(REPORTERS)
        raise ValueError(f"Relatório desconhecido: '{name}'. Opções: {opcoes}")
    return reporter_class(**kwargs)