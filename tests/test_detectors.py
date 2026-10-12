import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_analyzer.analyzers.detectors import DetectionEngine, build_detectors
from log_analyzer.analyzers.stats import StatsCollector
from log_analyzer.config import load_rules
from log_analyzer.findings import Severity
from log_analyzer.models import LogEntry
from log_analyzer.parsers import get_parser
from log_analyzer.readers import RawLine, read_lines

SAMPLES = Path(__file__).parent / "samples"
BRT = timezone(timedelta(hours=-3))
UTC = timezone.utc

ACEITO = "Oct  8 03:00:20 srv sshd[1]: Accepted password for root from 203.0.113.45 port 22 ssh2"


def load(nome, formato, **kwargs):
    parser = get_parser(formato, **kwargs)
    return list(parser.parse(read_lines(SAMPLES / nome)))


def syslog(*linhas):
    parser = get_parser("syslog", year=2026)
    return [parser.parse_line(RawLine("t.log", i, linha)) for i, linha in enumerate(linhas, start=1)]


def falha(segundo, minuto=0, ip="203.0.113.45", user="root"):
    return (f"Oct  8 03:{minuto:02d}:{segundo:02d} srv sshd[1]: "
            f"Failed password for {user} from {ip} port 22 ssh2")


def detectar(entradas, rules=None):
    engine = DetectionEngine(build_detectors(rules or load_rules()), assume_tz=BRT)
    for _ in engine.consume(entradas):
        pass
    return engine.findings()


def por_regra(findings, regra):
    return [f for f in findings if f.rule == regra]


# ---------- auth_brute_force ----------

def test_brute_force_ssh_no_log_de_exemplo():
    findings = detectar(load("auth_sample.log", "syslog", year=2026))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "auth_brute_force"
    assert f.ip == "203.0.113.45"
    assert f.count == 6
    assert f.severity == Severity.MEDIUM
    assert f.details["users"] == ["root", "admin", "test"]
    assert [e.line_number for e in f.evidence] == [1, 2, 3, 4, 5, 6]
    assert f.first_seen == datetime(2026, 10, 8, 6, 12, 1, tzinfo=UTC)
    assert f.last_seen == datetime(2026, 10, 8, 6, 12, 11, tzinfo=UTC)
    assert "203.0.113.45" in f.description


def test_abaixo_do_limiar_nao_gera_achado():
    assert detectar(syslog(*[falha(s) for s in range(4)])) == []


def test_pausa_maior_que_a_janela_gera_dois_achados():
    entradas = syslog(*[falha(s) for s in range(5)], *[falha(s, minuto=30) for s in range(5)])
    findings = por_regra(detectar(entradas), "auth_brute_force")

    assert len(findings) == 2
    assert [f.count for f in findings] == [5, 5]


def test_login_aceito_apos_falhas_vira_critico():
    findings = detectar(syslog(*[falha(s) for s in range(5)], ACEITO))

    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.details["success_after_failures"]["user"] == "root"
    assert f.evidence[-1].event == "ssh_accepted_login"
    assert "comprometimento" in f.description


def test_login_aceito_fora_da_janela_nao_escala():
    tarde = "Oct  8 03:10:00 srv sshd[1]: Accepted password for root from 203.0.113.45 port 22 ssh2"
    f = detectar(syslog(*[falha(s) for s in range(5)], tarde))[0]

    assert f.severity == Severity.MEDIUM
    assert "success_after_failures" not in f.details


def test_login_failed_de_aplicacao_json():
    rules = load_rules()
    rules["auth_brute_force"]["threshold"] = 2
    findings = detectar(load("app_sample.jsonl", "jsonl"), rules)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "auth_brute_force"
    assert f.ip == "203.0.113.77"
    assert f.count == 2
    assert f.details["users"] == ["admin"]


# ---------- detectores web ----------

def test_varredura_web_no_nginx_de_exemplo():
    scanner = por_regra(detectar(load("nginx_sample.log", "nginx")), "web_scanner")

    assert len(scanner) == 1
    f = scanner[0]
    assert f.ip == "203.0.113.99"
    assert f.count == 5
    assert f.severity == Severity.MEDIUM
    assert "/.env" in f.details["paths"]
    assert 404 in f.details["status_codes"]
    assert "Nmap Scripting Engine" in f.details["user_agents"]


def test_requisicoes_suspeitas_no_nginx_de_exemplo():
    achados = por_regra(detectar(load("nginx_sample.log", "nginx")), "suspicious_request")

    assert len(achados) == 1
    f = achados[0]
    assert f.ip == "203.0.113.99"
    assert f.count == 5
    razoes = f.details["reasons"]
    assert any(".env" in r for r in razoes)
    assert any("../" in r for r in razoes)
    assert any("nmap" in r.lower() for r in razoes)


def test_falhas_de_autenticacao_http():
    entradas = load("nginx_sample.log", "nginx")
    assert por_regra(detectar(entradas), "http_auth_failures") == []  # padrão: 10 em 300s

    rules = load_rules()
    rules["http_auth_failures"]["threshold"] = 2
    achados = por_regra(detectar(entradas, rules), "http_auth_failures")

    assert len(achados) == 1
    assert achados[0].ip == "192.0.2.15"
    assert achados[0].count == 2
    assert achados[0].severity == Severity.MEDIUM


# ---------- sudo ----------

def test_sudo_falhas_e_comando_sensivel():
    falha_sudo = ("Oct  8 08:51:00 srv sudo:     anne : 3 incorrect password attempts ; "
                  "TTY=pts/0 ; PWD=/home/anne ; USER=root ; COMMAND=/bin/ls")
    sensivel = ("Oct  8 09:00:00 srv sudo:      bob : TTY=pts/1 ; PWD=/tmp ; "
                "USER=root ; COMMAND=/usr/sbin/useradd hacker")
    inofensivo = ("Oct  8 09:05:00 srv sudo:     anne : TTY=pts/0 ; PWD=/home/anne ; "
                  "USER=root ; COMMAND=/usr/bin/apt update")
    findings = detectar(syslog(falha_sudo, sensivel, inofensivo))

    falhas = por_regra(findings, "sudo_failures")
    assert len(falhas) == 1
    assert falhas[0].user == "anne"
    assert falhas[0].count == 3

    comandos = por_regra(findings, "sudo_sensitive_command")
    assert len(comandos) == 1
    assert comandos[0].user == "bob"
    assert "/usr/sbin/useradd hacker" in comandos[0].details["commands"]


# ---------- motor e comportamento geral ----------

def test_entradas_sem_timestamp_sao_ignoradas_pelas_rajadas():
    entradas = [
        LogEntry(file="x.log", line_number=i, raw="x", event="ssh_failed_login",
                 ip="203.0.113.1", user="root")
        for i in range(10)
    ]
    assert detectar(entradas) == []


def test_achados_ordenados_do_mais_grave_para_o_mais_leve():
    critico = syslog(*[falha(s) for s in range(5)], ACEITO)
    findings = detectar(load("nginx_sample.log", "nginx") + critico)

    assert findings[0].severity == Severity.CRITICAL
    severidades = [f.severity for f in findings]
    assert severidades == sorted(severidades, reverse=True)


def test_regra_desabilitada_nao_gera_achados():
    rules = load_rules()
    rules["web_scanner"]["enabled"] = False
    findings = detectar(load("nginx_sample.log", "nginx"), rules)

    assert por_regra(findings, "web_scanner") == []
    assert len(por_regra(findings, "suspicious_request")) == 1


def test_findings_pode_ser_chamado_mais_de_uma_vez():
    engine = DetectionEngine(build_detectors(load_rules()))
    for _ in engine.consume(load("nginx_sample.log", "nginx")):
        pass

    primeira = [(f.rule, f.count) for f in engine.findings()]
    segunda = [(f.rule, f.count) for f in engine.findings()]
    assert primeira == segunda


def test_encadear_detectores_e_estatisticas_numa_unica_leitura():
    entradas = load("nginx_sample.log", "nginx")
    engine = DetectionEngine(build_detectors(load_rules()))
    stats = StatsCollector()

    repassadas = list(stats.consume(engine.consume(entradas)))

    assert repassadas == entradas
    assert stats.stats.total == 10
    assert len(engine.findings()) == 2


def test_finding_to_dict_e_serializavel_em_json():
    findings = detectar(
        load("auth_sample.log", "syslog", year=2026) + load("nginx_sample.log", "nginx")
    )
    dados = json.loads(json.dumps([f.to_dict() for f in findings]))

    assert len(dados) == 3
    assert {d["severity"] for d in dados} <= {"low", "medium", "high", "critical"}
    assert dados[0]["evidence"][0]["raw"]