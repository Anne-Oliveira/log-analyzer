"""Normalização de horários: tudo vira UTC com fuso explícito."""
from __future__ import annotations

from datetime import datetime, timezone, tzinfo


def to_utc(value: datetime, assume_tz: tzinfo | None = None) -> datetime:
    """Converte qualquer datetime para UTC.

    Horários sem fuso (ex.: syslog clássico) são interpretados em `assume_tz`
    ou, se omitido, no fuso local do sistema. Horários que já têm fuso
    apenas são convertidos.
    """
    if value.tzinfo is None:
        if assume_tz is not None:
            value = value.replace(tzinfo=assume_tz)
        else:
            value = value.astimezone()  # naive -> fuso local do sistema
    return value.astimezone(timezone.utc)