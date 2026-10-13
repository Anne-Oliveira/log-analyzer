"""Pipeline completo: arquivos -> parsers -> estatísticas + detectores -> ReportData.

Uso programático:
    from log_analyzer.pipeline import analyze
    dados = analyze("/var/log/auth.log", year=2026)
"""
from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from datetime import tzinfo
from pathlib import Path
from typing import Any

from log_analyzer.analyzers.detectors import DetectionEngine, build_detectors
from log_analyzer.analyzers.stats import StatsCollector
from log_analyzer.config import load_rules
from log_analyzer.detection import detect_format_from_path
from log_analyzer.models import LogEntry
from log_analyzer.ordering import sort_rotated
from log_analyzer.parsers import get_parser
from log_analyzer.parsers.base import BaseParser
from log_analyzer.readers import iter_files, read_lines
from log_analyzer.reporters.base import ReportData


class AnalysisError(Exception):
    """Erro de uso da análise (entrada inválida, formato não detectado...)."""


def _resolve_sources(target: str | Path) -> list[str | Path]:
    if str(target) == "-":
        return ["-"]
    files = sort_rotated(iter_files(target))  # levanta FileNotFoundError se não existir
    if not files:
        raise AnalysisError(f"Nenhum arquivo de log encontrado em: {target}")
    return list(files)


def _pick_format(source: str | Path, requested: str, single: bool) -> str | None:
    if requested != "auto":
        return requested
    if str(source) == "-":
        raise AnalysisError(
            "Ao ler da entrada padrão (stdin) não há como detectar o formato: informe --format."
        )
    try:
        return detect_format_from_path(source)
    except ValueError as exc:
        if single:
            raise AnalysisError(str(exc)) from exc
        print(f"[aviso] ignorando {source}: {exc}", file=sys.stderr)
        return None


def _make_parser(name: str, year: int | None, pattern: str | None,
                 timestamp_format: str | None) -> BaseParser:
    if name == "syslog":
        return get_parser("syslog", year=year)
    if name == "generic":
        if not pattern:
            raise AnalysisError("O formato 'generic' exige uma regex com grupos nomeados (--pattern).")
        try:
            return get_parser("generic", pattern=pattern, timestamp_format=timestamp_format)
        except re.error as exc:
            raise AnalysisError(f"Regex inválida em --pattern: {exc}") from exc
    return get_parser(name)


def analyze(
    target: str | Path,
    *,
    log_format: str = "auto",
    rules: dict[str, dict[str, Any]] | None = None,
    assume_tz: tzinfo | None = None,
    year: int | None = None,
    pattern: str | None = None,
    timestamp_format: str | None = None,
) -> ReportData:
    """Analisa um arquivo, pasta ('-' = stdin) e devolve os dados prontos para relatório."""
    rules = rules if rules is not None else load_rules()
    sources = _resolve_sources(target)

    parsers: list[BaseParser] = []
    formats: list[str] = []

    def entries() -> Iterator[LogEntry]:
        for source in sources:
            name = _pick_format(source, log_format, single=len(sources) == 1)
            if name is None:
                continue
            parser = _make_parser(name, year, pattern, timestamp_format)
            parsers.append(parser)
            if name not in formats:
                formats.append(name)
            yield from parser.parse(read_lines(source))

    engine = DetectionEngine(build_detectors(rules), assume_tz=assume_tz)
    collector = StatsCollector(assume_tz=assume_tz)
    for _ in collector.consume(engine.consume(entries())):  # uma única leitura
        pass

    return ReportData(
        stats=collector.stats,
        findings=engine.findings(),
        source=str(target),
        log_format=", ".join(formats),
        parsed=sum(p.parsed for p in parsers),
        skipped=sum(p.skipped for p in parsers),
    )