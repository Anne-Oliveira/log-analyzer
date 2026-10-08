from datetime import timedelta
from pathlib import Path

import pytest

from log_analyzer.parsers import get_parser
from log_analyzer.parsers.generic import GenericParser
from log_analyzer.parsers.jsonl import JsonLinesParser
from log_analyzer.parsers.nginx import NginxParser
from log_analyzer.readers import RawLine, read_lines

SAMPLES = Path(__file__).parent / "samples"


def nginx(text):
    return NginxParser().parse_line(RawLine("t.log", 1, text))


def jsonl(text):
    return JsonLinesParser().parse_line(RawLine("t.jsonl", 1, text))


# ---------- Nginx / Apache ----------

def test_nginx_requisicao_normal():
    e = nginx('198.51.100.20 - - [08/Oct/2026:10:00:01 -0300] '
              '"GET /static/app.css?v=2 HTTP/1.1" 200 2048 '
              '"https://exemplo.com/" "Mozilla/5.0"')
    assert e.ip == "198.51.100.20"
    assert e.user is None
    assert e.event == "http_request"
    assert e.level == "info"
    assert e.extra["method"] == "GET"
    assert e.extra["path"] == "/static/app.css?v=2"
    assert e.extra["protocol"] == "HTTP/1.1"
    assert e.extra["status"] == 200
    assert e.extra["size"] == 2048
    assert e.extra["referer"] == "https://exemplo.com/"
    assert e.extra["user_agent"] == "Mozilla/5.0"
    assert e.timestamp.hour == 10
    assert e.timestamp.utcoffset() == timedelta(hours=-3)


def test_nginx_status_4xx_vira_warning():
    e = nginx('203.0.113.99 - - [08/Oct/2026:10:05:11 -0300] '
              '"GET /admin HTTP/1.1" 404 153 "-" "Nmap Scripting Engine"')
    assert e.level == "warning"
    assert e.extra["status"] == 404
    assert e.extra["referer"] is None


def test_nginx_tamanho_traco_vira_zero():
    e = nginx('198.51.100.20 - - [08/Oct/2026:10:00:01 -0300] '
              '"GET / HTTP/1.1" 304 - "-" "curl/8.5.0"')
    assert e.extra["size"] == 0


def test_nginx_requisicao_malformada_de_scanner():
    e = nginx(r'203.0.113.9 - - [08/Oct/2026:10:00:00 -0300] '
              r'"\x16\x03\x01" 400 0 "-" "-"')
    assert e is not None
    assert e.extra["method"] is None
    assert e.extra["path"] == r"\x16\x03\x01"
    assert e.extra["status"] == 400


def test_nginx_arquivo_de_exemplo():
    parser = get_parser("nginx")
    entradas = list(parser.parse(read_lines(SAMPLES / "nginx_sample.log")))

    assert len(entradas) == 10
    assert parser.skipped == 0
    assert sum(1 for e in entradas if 400 <= e.extra["status"] < 500) == 7
    assert sum(1 for e in entradas if e.ip == "203.0.113.99") == 5


# ---------- JSON lines ----------

def test_jsonl_com_aliases():
    e = jsonl('{"@timestamp":"2026-10-08T10:01:05-03:00","level":"ERROR",'
              '"service":"api","msg":"token invalid","remote_addr":"203.0.113.77",'
              '"tentativa":3}')
    assert e.level == "error"
    assert e.process == "api"
    assert e.message == "token invalid"
    assert e.ip == "203.0.113.77"
    assert e.timestamp.minute == 1
    assert e.extra == {"tentativa": 3}


def test_jsonl_timestamp_epoch_em_milissegundos():
    e = jsonl('{"ts": 1791460800000, "msg": "x"}')
    assert e.timestamp.year == 2026
    assert e.timestamp.tzinfo is not None


@pytest.mark.parametrize("texto", ["não é json", "[1, 2, 3]", '{"quebrado": ', ""])
def test_jsonl_invalido_retorna_none(texto):
    assert jsonl(texto) is None


def test_jsonl_arquivo_de_exemplo():
    parser = get_parser("jsonl")
    entradas = list(parser.parse(read_lines(SAMPLES / "app_sample.jsonl")))

    assert len(entradas) == 4
    assert parser.skipped == 0
    assert sum(1 for e in entradas if e.event == "login_failed") == 2
    assert sum(1 for e in entradas if e.ip == "203.0.113.77") == 3


# ---------- Genérico ----------

def test_generic_com_regex_customizado():
    parser = GenericParser(
        pattern=r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
                r"user=(?P<user>\w+) ip=(?P<ip>[\d.]+) (?P<message>.*)$",
        timestamp_format="%Y-%m-%d %H:%M:%S",
    )
    e = parser.parse_line(RawLine(
        "t.log", 1, "2026-10-08 10:00:00 [WARN] user=bob ip=203.0.113.5 acesso negado"))

    assert e.level == "warn"
    assert e.user == "bob"
    assert e.ip == "203.0.113.5"
    assert e.message == "acesso negado"
    assert e.timestamp.hour == 10


def test_generic_exige_grupos_nomeados():
    with pytest.raises(ValueError):
        GenericParser(pattern=r"^\d+$")