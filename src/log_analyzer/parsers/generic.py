"""Parser genérico: você fornece a regex, ele faz o resto."""
from __future__ import annotations

import re
from datetime import datetime

from log_analyzer.models import LogEntry
from log_analyzer.parsers.base import BaseParser
from log_analyzer.readers import RawLine

# Grupos nomeados reconhecidos. Qualquer outro grupo vai para entry.extra.
KNOWN_GROUPS = {"ts", "host", "process", "level", "message", "ip", "user", "event"}


class GenericParser(BaseParser):
    name = "generic"

    def __init__(self, pattern: str, timestamp_format: str | None = None) -> None:
        """
        pattern: regex com grupos nomeados, por exemplo
            r"^(?P<ts>\\S+ \\S+) \\[(?P<level>\\w+)\\] (?P<message>.*)$"
        timestamp_format: formato strptime para o grupo 'ts'
            (se omitido, tenta ISO 8601).
        """
        super().__init__()
        self.regex = re.compile(pattern)
        if not self.regex.groupindex:
            raise ValueError("A regex precisa ter ao menos um grupo nomeado, ex.: (?P<ip>...)")
        self.timestamp_format = timestamp_format

    def _parse_timestamp(self, value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            if self.timestamp_format:
                return datetime.strptime(value, self.timestamp_format)
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def parse_line(self, line: RawLine) -> LogEntry | None:
        match = self.regex.search(line.text)
        if match is None:
            return None

        groups = match.groupdict()
        level = groups.get("level")
        return LogEntry(
            file=line.source,
            line_number=line.number,
            raw=line.text,
            timestamp=self._parse_timestamp(groups.get("ts")),
            host=groups.get("host"),
            process=groups.get("process"),
            level=level.lower() if level else None,
            message=groups.get("message") or line.text,
            ip=groups.get("ip"),
            user=groups.get("user"),
            event=groups.get("event"),
            extra={
                k: v for k, v in groups.items()
                if k not in KNOWN_GROUPS and v is not None
            },
        )