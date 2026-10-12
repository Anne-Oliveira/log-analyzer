"""Relatório no terminal: texto simples, com cores ANSI quando fizer sentido."""
from __future__ import annotations

import os
import re
import sys
import textwrap
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path

from log_analyzer.findings import Finding
from log_analyzer.reporters.base import ReportData, Reporter, fmt_dt

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_SEVERITY_STYLE = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
}

# Caracteres de controle (inclui ESC e os C1) vindos de logs poderiam manipular o terminal.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value: object) -> str:
    return _CONTROL.sub("·", str(value).replace("\t", " "))


def _bar(value: int, maximum: int, size: int = 30) -> str:
    if maximum <= 0 or value <= 0:
        return ""
    return "█" * max(1, round(value / maximum * size))


def _table(headers: list[str], rows: Iterable[tuple]) -> list[str]:
    cleaned = [[_clean(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in cleaned:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def line(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    return [line(headers), line(["-" * width for width in widths]), *[line(r) for r in cleaned]]


def _pairs(items: Iterable[tuple[object, int]]) -> str:
    return " · ".join(f"{_clean(key)} {value}" for key, value in items)


Paint = Callable[..., str]


class ConsoleReporter(Reporter):
    name = "console"
    extension = ".txt"

    def __init__(self, color: bool | None = None, top_n: int = 10,
                 evidence_shown: int = 3, width: int = 100, max_hours: int = 48) -> None:
        """color: True/False força; None decide sozinho (terminal e sem NO_COLOR)."""
        self.color = color
        self.top_n = top_n
        self.evidence_shown = evidence_shown
        self.width = width
        self.max_hours = max_hours

    def _use_color(self) -> bool:
        if self.color is not None:
            return self.color
        return sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def render(self, data: ReportData) -> str:
        return self._render(data, self._use_color())

    def render_file(self, data: ReportData) -> str:
        return self._render(data, color=False)  # arquivo nunca leva códigos ANSI

    def _render(self, data: ReportData, color: bool) -> str:
        def paint(text: str, *styles: str) -> str:
            if not color or not styles:
                return text
            return "".join(styles) + text + _RESET

        stats = data.stats
        rule = "─" * self.width
        out = [
            paint("LOG ANALYZER — RELATÓRIO", _BOLD),
            rule,
            f"Origem    : {_clean(data.source or '-')}",
            f"Formato   : {_clean(data.log_format or '-')}",
            f"Entradas  : {data.parsed} analisadas, {data.skipped} linhas ignoradas",
            f"Período   : {fmt_dt(stats.first_timestamp)} → {fmt_dt(stats.last_timestamp)}",
            f"Gerado em : {fmt_dt(data.generated_at)}",
            "",
        ]

        counts = data.severity_counts()
        summary = "  ".join(
            paint(f"{label.upper()} {n}", _SEVERITY_STYLE[label] if n else _DIM)
            for label, n in counts.items()
        )
        out += [paint(f"ACHADOS ({len(data.findings)})", _BOLD) + "   " + summary, rule]
        if not data.findings:
            out.append("Nenhum achado.")
            out.append("")
        for index, finding in enumerate(data.findings, start=1):
            out.extend(self._finding_lines(index, finding, paint))

        out += [paint("ESTATÍSTICAS", _BOLD), rule]
        out.append(f"Total de entradas: {stats.total} (sem horário: {stats.without_timestamp})")
        for label, counter in (
            ("Por nível", stats.by_level),
            ("Por evento", stats.by_event),
            ("Por processo", stats.by_process),
        ):
            if counter:
                out.append(f"{label}: {_pairs(counter.most_common(self.top_n))}")
        if stats.by_status:
            out.append(f"Status HTTP: {_pairs(sorted(stats.by_status.items()))}")

        top_ips = stats.top_ips(self.top_n)
        if top_ips:
            out += ["", paint("Top IPs", _BOLD)]
            rows = [(i.ip, str(i.count), fmt_dt(i.first_seen), fmt_dt(i.last_seen)) for i in top_ips]
            out += ["  " + line for line in
                    _table(["IP", "Ocorrências", "Primeira vez", "Última vez"], rows)]

        top_users = stats.top_users(self.top_n)
        if top_users:
            out += ["", paint("Top usuários", _BOLD)]
            out += ["  " + line for line in
                    _table(["Usuário", "Ocorrências"], [(u, str(n)) for u, n in top_users])]

        top_paths = stats.top_paths(self.top_n)
        if top_paths:
            out += ["", paint("Top caminhos", _BOLD)]
            rows = [(path[:60], str(n)) for path, n in top_paths]
            out += ["  " + line for line in _table(["Caminho", "Requisições"], rows)]

        out.extend(self._hours_lines(stats.by_hour, paint))
        return "\n".join(out) + "\n"

    def _finding_lines(self, index: int, finding: Finding, paint: Paint) -> list[str]:
        label = finding.severity.label
        badge = paint(f" {label.upper()} ", _SEVERITY_STYLE[label])
        lines = [
            f"[{index}] {badge} {_clean(finding.rule)}",
            f"    {paint(_clean(finding.title), _BOLD)}",
        ]

        info = []
        if finding.ip:
            info.append(f"IP: {_clean(finding.ip)}")
        if finding.user:
            info.append(f"Usuário: {_clean(finding.user)}")
        info.append(f"Ocorrências: {finding.count}")
        lines.append("    " + "   ".join(info))

        if finding.first_seen:
            lines.append(f"    Período: {fmt_dt(finding.first_seen)} → {fmt_dt(finding.last_seen)}")
        if finding.description:
            lines.append(textwrap.fill(
                _clean(finding.description), width=self.width,
                initial_indent="    ", subsequent_indent="    ",
            ))

        shown = finding.evidence[: self.evidence_shown]
        if shown:
            lines.append(f"    Evidências ({len(shown)} de {len(finding.evidence)}):")
            limit = max(self.width - 8, 20)
            for entry in shown:
                raw = _clean(entry.raw)
                if len(raw) > limit:
                    raw = raw[: limit - 1] + "…"
                origin = f"{_clean(Path(entry.file).name)}:{entry.line_number}"
                lines.append(paint(f"      {origin}  {raw}", _DIM))
        lines.append("")
        return lines

    def _hours_lines(self, by_hour: Counter, paint: Paint) -> list[str]:
        if not by_hour:
            return []
        items = sorted(by_hour.items())
        note = ""
        if len(items) > self.max_hours:
            busiest = sorted(items, key=lambda pair: -pair[1])[: self.max_hours]
            items = sorted(busiest)
            note = f" (mostrando as {self.max_hours} horas mais movimentadas)"
        maximum = max(count for _, count in items)
        lines = ["", paint(f"Atividade por hora (UTC){note}", _BOLD)]
        for hour, count in items:
            lines.append(f"  {hour:%Y-%m-%d %H:00}  {_bar(count, maximum):<30} {count}")
        return lines