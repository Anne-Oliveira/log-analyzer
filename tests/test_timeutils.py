from datetime import datetime, timedelta, timezone

from log_analyzer.timeutils import to_utc

BRT = timezone(timedelta(hours=-3))
UTC = timezone.utc


def test_naive_usa_o_fuso_informado():
    resultado = to_utc(datetime(2026, 10, 8, 3, 12, 1), assume_tz=BRT)
    assert resultado == datetime(2026, 10, 8, 6, 12, 1, tzinfo=UTC)


def test_aware_e_apenas_convertido():
    resultado = to_utc(datetime(2026, 10, 8, 10, 0, 0, tzinfo=BRT))
    assert resultado == datetime(2026, 10, 8, 13, 0, 0, tzinfo=UTC)


def test_naive_sem_fuso_informado_vira_utc_aware():
    resultado = to_utc(datetime(2026, 10, 8, 3, 0, 0))
    assert resultado.utcoffset() == timedelta(0)