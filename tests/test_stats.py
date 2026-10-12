import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_analyzer.analyzers.stats import StatsCollector, compute_stats
from log_analyzer.models import LogEntry
from log_analyzer.parsers import get_parser
from log_analyzer.readers import read_lines

SAMPLES = Path(__file__).parent / "samples"
BRT = timezone(timedelta(hours=-3))
UTC = timezone.utc


def load(nome, formato, **kwargs):
    parser = get_parser(formato, **kwargs)
    return list(parser.parse(read_lines(SAMPLES / nome)))


def test_stats_do_auth_log():
    entradas = load("auth_sample.log", "syslog", year=2026)
    stats = compute_stats(entradas, assume_tz=BRT)

    assert stats.total == 9
    assert stats.by_event == {"ssh_failed_login": 7, "ssh_accepted_login": 1, "sudo_command": 1}
    assert stats.first_timestamp == datetime(2026, 10, 8, 6, 12, 1, tzinfo=UTC)
    assert stats.last_timestamp == datetime(2026, 10, 8, 12, 15, 44, tzinfo=UTC)
    assert stats.by_hour[datetime(2026, 10, 8, 6, tzinfo=UTC)] == 6
    assert stats.by_hour[datetime(2026, 10, 8, 11, tzinfo=UTC)] == 2
    assert stats.by_hour[datetime(2026, 10, 8, 12, tzinfo=UTC)] == 1

    top = stats.top_ips(2)
    assert [i.ip for i in top] == ["203.0.113.45", "198.51.100.7"]
    assert top[0].count == 6
    assert top[0].events["ssh_failed_login"] == 6
    assert stats.top_users(1) == [("root", 4)]


def test_stats_do_nginx():
    stats = compute_stats(load("nginx_sample.log", "nginx"))

    assert stats.total == 10
    assert stats.by_status == {200: 2, 404: 4, 400: 1, 401: 2, 500: 1}
    assert stats.by_level == {"info": 2, "warning": 7, "error": 1}
    assert stats.first_timestamp == datetime(2026, 10, 8, 13, 0, 1, tzinfo=UTC)
    assert stats.paths["/login"] == 2

    assert stats.top_ips(1)[0].ip == "203.0.113.99"
    scanner = stats.ips["203.0.113.99"]
    assert scanner.count == 5
    assert scanner.status_classes == {"4xx": 5}

    normal = stats.ips["198.51.100.20"]
    assert normal.status_classes == {"2xx": 2, "5xx": 1}


def test_entrada_sem_timestamp_e_contada_a_parte():
    entrada = LogEntry(file="x.log", line_number=1, raw="x", level="info")
    stats = compute_stats([entrada])

    assert stats.total == 1
    assert stats.without_timestamp == 1
    assert stats.first_timestamp is None
    assert not stats.by_hour


def test_mistura_de_timestamps_com_e_sem_fuso():
    # Antes da normalização isso levantava TypeError (naive vs aware).
    mistura = (
        load("auth_sample.log", "syslog", year=2026)
        + load("nginx_sample.log", "nginx")
    )
    stats = compute_stats(mistura, assume_tz=BRT)

    assert stats.total == 19
    assert stats.first_timestamp == datetime(2026, 10, 8, 6, 12, 1, tzinfo=UTC)
    assert stats.last_timestamp == datetime(2026, 10, 8, 14, 0, 0, tzinfo=UTC)


def test_consume_repassa_as_entradas_intactas():
    entradas = load("nginx_sample.log", "nginx")
    collector = StatsCollector()

    repassadas = list(collector.consume(entradas))

    assert repassadas == entradas
    assert collector.stats.total == len(entradas)


def test_to_dict_e_serializavel_em_json():
    stats = compute_stats(load("nginx_sample.log", "nginx"))

    dados = json.loads(json.dumps(stats.to_dict()))

    assert dados["total"] == 10
    assert dados["by_status"]["404"] == 4
    assert dados["top_ips"][0]["ip"] == "203.0.113.99"