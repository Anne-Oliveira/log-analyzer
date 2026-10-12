"""Relatório em JSON."""
from __future__ import annotations

import json

from log_analyzer.reporters.base import ReportData, Reporter


class JsonReporter(Reporter):
    name = "json"
    extension = ".json"

    def __init__(self, top_n: int = 10, indent: int = 2) -> None:
        self.top_n = top_n
        self.indent = indent

    def render(self, data: ReportData) -> str:
        return json.dumps(data.to_dict(self.top_n), indent=self.indent, ensure_ascii=False) + "\n"