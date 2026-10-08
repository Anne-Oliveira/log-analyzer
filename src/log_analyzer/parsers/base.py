"""Interface comum de todos os parsers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator

from log_analyzer.models import LogEntry
from log_analyzer.readers import RawLine


class BaseParser(ABC):
    """Um parser converte linhas cruas (RawLine) em LogEntry.

    Para suportar um formato novo: herde desta classe, implemente
    parse_line() e registre em parsers/__init__.py.
    """

    name: str = "base"

    def __init__(self) -> None:
        self.parsed = 0   # linhas convertidas com sucesso
        self.skipped = 0  # linhas que o parser não reconheceu

    @abstractmethod
    def parse_line(self, line: RawLine) -> LogEntry | None:
        """Converte uma linha. Retorna None se o formato não for reconhecido."""

    def parse(self, lines: Iterable[RawLine]) -> Iterator[LogEntry]:
        for line in lines:
            entry = self.parse_line(line)
            if entry is None:
                self.skipped += 1
                continue
            self.parsed += 1
            yield entry