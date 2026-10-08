"""Registro dos parsers disponíveis."""
from __future__ import annotations

from log_analyzer.parsers.base import BaseParser
from log_analyzer.parsers.syslog import SyslogParser

PARSERS: dict[str, type[BaseParser]] = {
    "syslog": SyslogParser,
}


def get_parser(name: str, **kwargs) -> BaseParser:
    parser_class = PARSERS.get(name)
    if parser_class is None:
        opcoes = ", ".join(PARSERS)
        raise ValueError(f"Formato desconhecido: '{name}'. Opções: {opcoes}")
    return parser_class(**kwargs)