"""Registro dos parsers disponíveis."""
from __future__ import annotations

from log_analyzer.parsers.base import BaseParser
from log_analyzer.parsers.generic import GenericParser
from log_analyzer.parsers.jsonl import JsonLinesParser
from log_analyzer.parsers.nginx import NginxParser
from log_analyzer.parsers.syslog import SyslogParser

PARSERS: dict[str, type[BaseParser]] = {
    "syslog": SyslogParser,
    "nginx": NginxParser,
    "jsonl": JsonLinesParser,
    "generic": GenericParser,  # exige o argumento 'pattern'
}


def get_parser(name: str, **kwargs) -> BaseParser:
    parser_class = PARSERS.get(name)
    if parser_class is None:
        opcoes = ", ".join(PARSERS)
        raise ValueError(f"Formato desconhecido: '{name}'. Opções: {opcoes}")
    return parser_class(**kwargs)