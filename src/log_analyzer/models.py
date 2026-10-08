"""Modelo padrão de uma entrada de log.

Todo parser converte linhas brutas em LogEntry, e o restante do sistema
(estatísticas, detectores, relatórios) só conhece este formato.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class LogEntry:
    # Onde a linha está (rastreabilidade: o relatório precisa provar o achado)
    file: str
    line_number: int
    raw: str

    # Campos normalizados (None quando o formato não fornece)
    timestamp: datetime | None = None
    host: str | None = None
    process: str | None = None
    level: str | None = None
    message: str = ""

    # Campos de interesse para segurança
    ip: str | None = None
    user: str | None = None
    event: str | None = None  # ex.: "ssh_failed_login", "sudo_command", "http_request"

    # Qualquer coisa específica do formato (status HTTP, path, método, porta...)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Versão serializável (usada pelos relatórios JSON/CSV)."""
        return {
            "file": self.file,
            "line_number": self.line_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "host": self.host,
            "process": self.process,
            "level": self.level,
            "message": self.message,
            "ip": self.ip,
            "user": self.user,
            "event": self.event,
            "extra": self.extra,
            "raw": self.raw,
        }