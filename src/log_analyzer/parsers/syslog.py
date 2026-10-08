"""Parser de syslog / auth.log (formato clássico e ISO 8601)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from log_analyzer.models import LogEntry
from log_analyzer.parsers.base import BaseParser
from log_analyzer.readers import RawLine

# Mapa próprio de meses: strptime("%b") depende do locale do sistema (pt_BR quebraria)
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Parte comum a ambos os formatos: host, processo[pid]: mensagem
_TAIL = (
    r"\s+(?P<host>\S+)"
    r"\s+(?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:"
    r"\s*(?P<message>.*)$"
)

TRADITIONAL = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})" + _TAIL)
ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)" + _TAIL
)

# Tabela de eventos de segurança: (nome do evento, prefixo do processo, regex da mensagem).
# As regras são testadas em ordem e a primeira que casar vence.
# Grupos nomeados "user" e "ip" vão para os campos do LogEntry; o resto vai para extra.
EVENT_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "ssh_failed_login",
        "sshd",
        re.compile(
            r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?"
            r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        "ssh_accepted_login",
        "sshd",
        re.compile(
            r"Accepted (?P<method>\S+) for (?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        "ssh_invalid_user",
        "sshd",
        re.compile(r"Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
    ),
    (
        "sudo_auth_failure",
        "sudo",
        re.compile(r"^(?P<user>\S+)\s*:\s*(?P<attempts>\d+) incorrect password attempts?"),
    ),
    (
        "sudo_command",
        "sudo",
        re.compile(
            r"^(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>.*?)\s*;"
            r"\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
        ),
    ),
]


class SyslogParser(BaseParser):
    name = "syslog"

    def __init__(self, year: int | None = None) -> None:
        """year: ano dos logs no formato clássico (que não traz ano).

        Se None, usa o ano atual, e se a data resultante cair no futuro
        (ex.: log de dezembro lido em janeiro) usa o ano anterior.
        """
        super().__init__()
        self.year = year

    def parse_line(self, line: RawLine) -> LogEntry | None:
        text = line.text
        match = ISO.match(text)
        is_iso = match is not None
        if match is None:
            match = TRADITIONAL.match(text)
        if match is None:
            return None

        timestamp = self._parse_timestamp(match["ts"], is_iso)
        if timestamp is None:
            return None

        entry = LogEntry(
            file=line.source,
            line_number=line.number,
            raw=text,
            timestamp=timestamp,
            host=match["host"],
            process=match["process"],
            message=match["message"],
        )
        if match["pid"]:
            entry.extra["pid"] = int(match["pid"])

        self._apply_event_rules(entry)
        return entry

    def _parse_timestamp(self, ts: str, is_iso: bool) -> datetime | None:
        if is_iso:
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                return None

        try:
            month_name, day, clock = ts.split()
            hour, minute, second = (int(part) for part in clock.split(":"))
            now = datetime.now()
            year = self.year or now.year
            parsed = datetime(year, MONTHS[month_name], int(day), hour, minute, second)
        except (KeyError, ValueError):
            return None

        if self.year is None and parsed > now + timedelta(days=1):
            try:
                parsed = parsed.replace(year=parsed.year - 1)
            except ValueError:  # 29 de fevereiro
                pass
        return parsed

    @staticmethod
    def _apply_event_rules(entry: LogEntry) -> None:
        process = entry.process or ""
        for event, process_prefix, pattern in EVENT_RULES:
            if not process.startswith(process_prefix):
                continue
            match = pattern.search(entry.message)
            if match is None:
                continue

            groups = match.groupdict()
            if "invalid" in groups:
                groups["invalid_user"] = groups.pop("invalid") is not None
            for numeric_field in ("port", "attempts"):
                if groups.get(numeric_field):
                    groups[numeric_field] = int(groups[numeric_field])

            entry.event = event
            entry.user = groups.pop("user", None)
            entry.ip = groups.pop("ip", None)
            entry.extra.update({k: v for k, v in groups.items() if v is not None})
            return