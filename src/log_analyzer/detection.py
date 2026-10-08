"""Detecção automática do formato de um log."""
from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
from pathlib import Path

from log_analyzer.parsers import get_parser
from log_analyzer.readers import RawLine, read_lines

SAMPLE_SIZE = 20
MIN_MATCH_RATIO = 0.5
# 'generic' fica de fora: sem a regex do usuário, ele não tem como adivinhar.
AUTO_DETECT_ORDER = ("jsonl", "nginx", "syslog")


def detect_format(lines: Iterable[RawLine], sample_size: int = SAMPLE_SIZE) -> str:
    """Testa cada parser nas primeiras linhas e devolve o que reconhecer mais."""
    sample = list(islice(lines, sample_size))
    if not sample:
        raise ValueError("Não há linhas para detectar o formato.")

    best_name: str | None = None
    best_score = 0.0
    for name in AUTO_DETECT_ORDER:
        parser = get_parser(name)
        hits = sum(1 for line in sample if parser.parse_line(line) is not None)
        score = hits / len(sample)
        if score > best_score:
            best_name, best_score = name, score

    if best_name is None or best_score < MIN_MATCH_RATIO:
        raise ValueError(
            "Não consegui detectar o formato automaticamente. "
            "Informe com --format (ou use 'generic' com uma regex)."
        )
    return best_name


def detect_format_from_path(target: str | Path) -> str:
    return detect_format(read_lines(target))