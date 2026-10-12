"""Estatísticas gerais, calculadas em uma única passada pelas entradas."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from typing import Any

from log_analyzer.models import LogEntry
from log_analyzer.timeutils import to_utc


@dataclass
class IpStats:
    """Tudo o que sabemos sobre um IP."""

    ip: str
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    events: Counter[str] = field(default_factory=Counter)
    status_classes: Counter[str] = field(default_factory=Counter)  # "2xx", "4xx"...

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "events": dict(self.events),
            "status_classes": dict(self.status_classes),
        }


@dataclass
class LogStats:
    total: int = 0
    without_timestamp: int = 0
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None

    by_level: Counter[str] = field(default_factory=Counter)
    by_event: Counter[str] = field(default_factory=Counter)
    by_process: Counter[str] = field(default_factory=Counter)
    by_status: Counter[int] = field(default_factory=Counter)
    by_hour: Counter[datetime] = field(default_factory=Counter)  # chave: hora cheia em UTC

    users: Counter[str] = field(default_factory=Counter)
    paths: Counter[str] = field(default_factory=Counter)
    user_agents: Counter[str] = field(default_factory=Counter)
    ips: dict[str, IpStats] = field(default_factory=dict)

    def top_ips(self, n: int = 10) -> list[IpStats]:
        ordered = sorted(self.ips.values(), key=lambda s: (-s.count, s.ip))
        return ordered[:n]

    def top_users(self, n: int = 10) -> list[tuple[str, int]]:
        return self.users.most_common(n)

    def top_paths(self, n: int = 10) -> list[tuple[str, int]]:
        return self.paths.most_common(n)

    def to_dict(self, top_n: int = 10) -> dict[str, Any]:
        """Versão serializável em JSON (usada pelos relatórios)."""
        return {
            "total": self.total,
            "without_timestamp": self.without_timestamp,
            "first_timestamp": self.first_timestamp.isoformat() if self.first_timestamp else None,
            "last_timestamp": self.last_timestamp.isoformat() if self.last_timestamp else None,
            "by_level": dict(self.by_level),
            "by_event": dict(self.by_event),
            "by_process": dict(self.by_process),
            "by_status": {str(k): v for k, v in sorted(self.by_status.items())},
            "by_hour": {k.isoformat(): v for k, v in sorted(self.by_hour.items())},
            "top_ips": [ip.to_dict() for ip in self.top_ips(top_n)],
            "top_users": dict(self.top_users(top_n)),
            "top_paths": dict(self.top_paths(top_n)),
        }


class StatsCollector:
    """Acumula estatísticas entrada por entrada (memória proporcional aos valores distintos)."""

    def __init__(self, assume_tz: tzinfo | None = None) -> None:
        self.stats = LogStats()
        self._assume_tz = assume_tz

    def add(self, entry: LogEntry) -> None:
        s = self.stats
        s.total += 1

        timestamp = to_utc(entry.timestamp, self._assume_tz) if entry.timestamp else None
        if timestamp is None:
            s.without_timestamp += 1
        else:
            if s.first_timestamp is None or timestamp < s.first_timestamp:
                s.first_timestamp = timestamp
            if s.last_timestamp is None or timestamp > s.last_timestamp:
                s.last_timestamp = timestamp
            s.by_hour[timestamp.replace(minute=0, second=0, microsecond=0)] += 1

        if entry.level:
            s.by_level[entry.level] += 1
        if entry.event:
            s.by_event[entry.event] += 1
        if entry.process:
            s.by_process[entry.process] += 1
        if entry.user:
            s.users[entry.user] += 1

        status = entry.extra.get("status")
        if isinstance(status, int):
            s.by_status[status] += 1

        path = entry.extra.get("path")
        if path:
            s.paths[path.split("?", 1)[0]] += 1  # sem query string, para agrupar

        agent = entry.extra.get("user_agent")
        if agent:
            s.user_agents[agent] += 1

        if entry.ip:
            ip_stats = s.ips.setdefault(entry.ip, IpStats(entry.ip))
            ip_stats.count += 1
            if timestamp is not None:
                if ip_stats.first_seen is None or timestamp < ip_stats.first_seen:
                    ip_stats.first_seen = timestamp
                if ip_stats.last_seen is None or timestamp > ip_stats.last_seen:
                    ip_stats.last_seen = timestamp
            if entry.event:
                ip_stats.events[entry.event] += 1
            if isinstance(status, int):
                ip_stats.status_classes[f"{status // 100}xx"] += 1

    def consume(self, entries: Iterable[LogEntry]) -> Iterator[LogEntry]:
        """Coleta e repassa cada entrada, permitindo encadear com outros
        consumidores (detectores) sem ler o arquivo duas vezes."""
        for entry in entries:
            self.add(entry)
            yield entry


def compute_stats(entries: Iterable[LogEntry], assume_tz: tzinfo | None = None) -> LogStats:
    collector = StatsCollector(assume_tz)
    for _ in collector.consume(entries):
        pass
    return collector.stats