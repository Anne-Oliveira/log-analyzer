import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_analyzer.findings import Severity
from log_analyzer.pipeline import AnalysisError, analyze

SAMPLES = Path(__file__).parent / "samples"
BRT = timezone(timedelta(hours=-3))
UTC = timezone.utc

ACEITO = "Oct  8 03:00:20 srv sshd[1]: Accepted password for root from 203.0.113.45 port 22 ssh2"


def falha(segundo):
    return (f"Oct  8 03:00:{segundo:02d} srv sshd[1]: "
            "Failed password for root from 203.0.113.45 port 22 ssh2")


def test_nginx_com_deteccao_automatica():
    dados = analyze(SAMPLES / "nginx_sample.log")

    assert dados.log_format == "nginx"
    assert dados.parsed == 10
    assert dados.skipped == 0
    assert len(dados.findings) == 2
    assert dados.source.endswith("nginx_sample.log")


def test_syslog_com_ano_e_fuso():
    dados = analyze(SAMPLES / "auth_sample.log", year=2026, assume_tz=BRT)

    assert dados.log_format == "syslog"
    assert dados.stats.first_timestamp == datetime(2026, 10, 8, 6, 12, 1, tzinfo=UTC)
    assert [f.rule for f in dados.findings] == ["auth_brute_force"]


def test_pasta_com_formatos_misturados(tmp_path):
    for nome in ("auth_sample.log", "nginx_sample.log", "app_sample.jsonl"):
        shutil.copy(SAMPLES / nome, tmp_path / nome)

    dados = analyze(tmp_path, year=2026, assume_tz=BRT)

    assert set(dados.log_format.split(", ")) == {"jsonl", "syslog", "nginx"}
    assert dados.parsed == 23
    assert dados.stats.total == 23
    assert {f.rule for f in dados.findings} == {
        "auth_brute_force", "web_scanner", "suspicious_request",
    }


def test_arquivos_rotacionados_sao_lidos_do_mais_antigo_para_o_atual(tmp_path):
    # Em ordem alfabética o "auth.log" viria antes do "auth.log.1" e o login aceito
    # seria visto ANTES das falhas, perdendo o achado crítico.
    (tmp_path / "auth.log.1").write_text(
        "\n".join(falha(s) for s in range(5)) + "\n", encoding="utf-8")
    (tmp_path / "auth.log").write_text(ACEITO + "\n", encoding="utf-8")

    dados = analyze(tmp_path, year=2026, assume_tz=BRT)

    assert dados.parsed == 6
    assert dados.findings[0].severity == Severity.CRITICAL


def test_stdin_exige_formato():
    with pytest.raises(AnalysisError, match="stdin"):
        analyze("-")


def test_arquivo_sem_formato_reconhecivel(tmp_path):
    arquivo = tmp_path / "lixo.log"
    arquivo.write_text("lixo qualquer\n" * 3, encoding="utf-8")

    with pytest.raises(AnalysisError, match="detectar"):
        analyze(arquivo)


def test_generic_exige_regex_valida(tmp_path):
    arquivo = tmp_path / "app.log"
    arquivo.write_text("qualquer coisa\n", encoding="utf-8")

    with pytest.raises(AnalysisError, match="[Rr]egex"):
        analyze(arquivo, log_format="generic")
    with pytest.raises(AnalysisError, match="[Rr]egex"):
        analyze(arquivo, log_format="generic", pattern="(abc")


def test_formato_generic_com_regex(tmp_path):
    arquivo = tmp_path / "app.log"
    arquivo.write_text(
        "2026-10-08 10:00:00 [WARN] user=bob ip=203.0.113.5 acesso negado\n", encoding="utf-8")

    dados = analyze(
        arquivo, log_format="generic",
        pattern=(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
                 r"user=(?P<user>\w+) ip=(?P<ip>[\d.]+) (?P<message>.*)$"),
        timestamp_format="%Y-%m-%d %H:%M:%S",
    )

    assert dados.log_format == "generic"
    assert dados.parsed == 1
    assert dados.stats.ips["203.0.113.5"].count == 1
    assert dados.stats.by_level == {"warn": 1}


def test_arquivo_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(tmp_path / "nao_existe.log")


def test_pasta_vazia(tmp_path):
    with pytest.raises(AnalysisError, match="Nenhum arquivo"):
        analyze(tmp_path)
        