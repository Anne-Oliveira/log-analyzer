"""Parser de access log Nginx/Apache (formatos combined e common)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from log_analyzer.models import LogEntry
from log_analyzer.parsers.base import BaseParser
from log_analyzer.parsers.syslog import MONTHS
from log_analyzer.readers import RawLine

_QUOTED = r'(?:[^"\\]|\\.)*'  # texto entre aspas, aceitando \" escapado

ACCESS_LOG = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) "
    r"\[(?P<ts>[^\]]+)\] "
    rf'"(?P<request>{_QUOTED})" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
    rf'(?: "(?P<referer>{_QUOTED})" "(?P<agent>{_QUOTED})")?'
)


def _dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "-", "") else value


def _parse_timestamp(ts: str) -> datetime | None:
    """Formato: 08/Oct/2026:10:00:01 -0300"""
    try:
        date_part, _, tz = ts.partition(" ")
        day, month_name, rest = date_part.split("/")
        year, hour, minute, second = rest.split(":")

        tzinfo = None
        if tz:
            sign = -1 if tz[0] == "-" else 1
            offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
            tzinfo = timezone(offset)

        return datetime(
            int(year), MONTHS[month_name], int(day),
            int(hour), int(minute), int(second), tzinfo=tzinfo,
        )
    except (KeyError, ValueError, IndexError):
        return None


class NginxParser(BaseParser):
    name = "nginx"

    def parse_line(self, line: RawLine) -> LogEntry | None:
        match = ACCESS_LOG.match(line.text)
        if match is None:
            return None

        timestamp = _parse_timestamp(match["ts"])
        if timestamp is None:
            return None

        request = match["request"]
        parts = request.split(" ")
        if len(parts) == 3:
            method, path, protocol = parts
        else:
            # Requisição malformada (comum em scanners e tráfego binário):
            # guardamos o texto cru no path para não perder a evidência.
            method, path, protocol = None, request, None

        status = int(match["status"])
        size = int(match["size"]) if match["size"].isdigit() else 0

        if status >= 500:
            level = "error"
        elif status >= 400:
            level = "warning"
        else:
            level = "info"

        return LogEntry(
            file=line.source,
            line_number=line.number,
            raw=line.text,
            timestamp=timestamp,
            level=level,
            message=request,
            ip=match["ip"],
            user=_dash_to_none(match["user"]),
            event="http_request",
            extra={
                "method": method,
                "path": path,
                "protocol": protocol,
                "status": status,
                "size": size,
                "referer": _dash_to_none(match["referer"]),
                "user_agent": _dash_to_none(match["agent"]),
            },
        )