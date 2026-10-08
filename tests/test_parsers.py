from pathlib import Path

from log_analyzer.parsers import get_parser
from log_analyzer.parsers.syslog import SyslogParser
from log_analyzer.readers import RawLine, read_lines

SAMPLE = Path(__file__).parent / "samples" / "auth_sample.log"

def parse(text: str, year: int = 2026):
    return SyslogParser(year=year).parse_line(RawLine("teste.log", 1, text))


def test_ssh_falha_de_senha():
    e = parse("Oct  8 03:12:01 servidor sshd[1201]: Failed password for root "
              "from 203.0.113.45 port 51234 ssh2")
    assert e.event == "ssh_failed_login"
    assert e.user == "root"
    assert e.ip == "203.0.113.45"
    assert e.extra["port"] == 51234
    assert e.extra["invalid_user"] is False
    assert e.process == "sshd"
    assert e.host == "servidor"
    assert e.timestamp.month == 10 and e.timestamp.hour == 3


def test_ssh_falha_com_usuario_invalido():
    e = parse("Oct  8 03:12:05 servidor sshd[1205]: Failed password for invalid "
              "user admin from 203.0.113.45 port 51240 ssh2")
    assert e.event == "ssh_failed_login"
    assert e.user == "admin"
    assert e.extra["invalid_user"] is True


def test_ssh_login_aceito():
    e = parse("Oct  8 08:45:22 servidor sshd[2201]: Accepted publickey for anne "
              "from 198.51.100.7 port 40022 ssh2")
    assert e.event == "ssh_accepted_login"
    assert e.user == "anne"
    assert e.ip == "198.51.100.7"
    assert e.extra["method"] == "publickey"


def test_sudo_comando():
    e = parse("Oct  8 08:50:10 servidor sudo:     anne : TTY=pts/0 ; PWD=/home/anne ; "
              "USER=root ; COMMAND=/usr/bin/apt update")
    assert e.event == "sudo_command"
    assert e.user == "anne"
    assert e.extra["target_user"] == "root"
    assert e.extra["command"] == "/usr/bin/apt update"


def test_sudo_senha_incorreta():
    e = parse("Oct  8 08:51:00 servidor sudo:     anne : 3 incorrect password attempts ; "
              "TTY=pts/0 ; PWD=/home/anne ; USER=root ; COMMAND=/bin/ls")
    assert e.event == "sudo_auth_failure"
    assert e.extra["attempts"] == 3


def test_formato_iso_com_timezone():
    e = parse("2026-10-08T03:12:01.123456-03:00 servidor sshd[9]: Failed password for "
              "root from 203.0.113.45 port 22 ssh2")
    assert e.event == "ssh_failed_login"
    assert e.timestamp.year == 2026
    assert e.timestamp.tzinfo is not None


def test_linha_sem_evento_conhecido_ainda_vira_entrada():
    e = parse("Oct  8 10:00:00 servidor CRON[77]: pam_unix(cron:session): session opened")
    assert e is not None
    assert e.event is None
    assert e.process == "CRON"


def test_linha_invalida_retorna_none_e_conta_como_ignorada():
    parser = SyslogParser(year=2026)
    resultado = list(parser.parse([RawLine("x.log", 1, "isto não é syslog")]))
    assert resultado == []
    assert parser.skipped == 1


def test_arquivo_de_exemplo_completo():
    parser = get_parser("syslog", year=2026)
    entradas = list(parser.parse(read_lines(SAMPLE)))

    assert len(entradas) == 9
    assert parser.skipped == 0

    falhas = [e for e in entradas if e.event == "ssh_failed_login"]
    assert len(falhas) == 7
    assert sum(1 for e in falhas if e.ip == "203.0.113.45") == 6


def test_formato_desconhecido():
    import pytest

    with pytest.raises(ValueError):
        get_parser("formato_que_nao_existe")