"""Parser de JSON lines (um objeto JSON por linha)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from log_analyzer.models import LogEntry
from log_analyzer.parsers.base import BaseParser
from log_analyzer.readers import RawLine

# Cada campo do LogEntry e os nomes que apps diferentes costumam usar para ele.
# Para suportar um nome novo, basta incluí-lo na tupla (a ordem define a prioridade).
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "time", "ts", "datetime", "date"),
    "level": ("level", "severity", "lvl", "loglevel"),
    "message": ("message", "msg", "text"),
    "host": ("host", "hostname"),
    "process": ("process", "service", "app", "logger", "program"),
    "ip": ("ip", "client_ip", "remote_addr", "remote_ip", "src_ip", "source_ip"),
    "user": ("user", "username", "user_name", "account"),
    "event": ("event", "event_type", "action"),
}


def _as_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value  # epoch em ms ou s
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


class JsonLinesParser(BaseParser):
    name = "jsonl"

    def parse_line(self, line: RawLine) -> LogEntry | None:
        text = line.text.strip()
        if not text.startswith("{"):
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None

        fields: dict[str, Any] = {}
        for target, aliases in FIELD_ALIASES.items():
            for alias in aliases:
                if alias in data:
                    fields[target] = data.pop(alias)
                    break

        level = _as_text(fields.get("level"))
        return LogEntry(
            file=line.source,
            line_number=line.number,
            raw=line.text,
            timestamp=_parse_timestamp(fields.get("timestamp")),
            host=_as_text(fields.get("host")),
            process=_as_text(fields.get("process")),
            level=level.lower() if level else None,
            message=_as_text(fields.get("message")) or "",
            ip=_as_text(fields.get("ip")),
            user=_as_text(fields.get("user")),
            event=_as_text(fields.get("event")),
            extra=data,  # tudo que não foi mapeado fica preservado
        )