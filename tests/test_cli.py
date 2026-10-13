import io
import json
import sys
from datetime import timedelta, timezone
from pathlib import Path

import pytest
import yaml

from log_analyzer.cli import CliError, main, parse_reports, parse_timezone
from log_analyzer.config import DEFAULT_RULES

SAMPLES = Path(__file__).parent / "samples"
NGINX = SAMPLES / "nginx_sample.log"
AUTH = SAMPLES / "auth_sample.log"


def test_analyze_mostra_relatorio_no_console(capsys):
    codigo = main(["analyze", str(NGINX), "--no-color"])
    saida = capsys.readouterr()

    assert codigo == 0
    assert "ACHADOS (2)" in saida.out
    assert "203.0.113.99" in saida.out
    assert "Analisadas 10 entradas" in saida.err


def test_varios_relatorios_em_arquivos(tmp_path, capsys):
    codigo = main(["analyze", str(NGINX), "-r", "json,csv,html",
                   "-o", str(tmp_path), "--name", "teste"])
    saida = capsys.readouterr()

    assert codigo == 0
    assert saida.out == ""  # sem console, nada vai para o stdout
    for extensao in (".json", ".csv", ".html"):
        assert (tmp_path / f"teste{extensao}").exists()
    dados = json.loads((tmp_path / "teste.json").read_text(encoding="utf-8"))
    assert dados["summary"]["total_findings"] == 2
    assert "Relatório gravado" in saida.err


def test_report_all(tmp_path, capsys):
    codigo = main(["analyze", str(NGINX), "--report", "all", "-o", str(tmp_path),
                   "--no-color", "-q"])
    saida = capsys.readouterr()

    assert codigo == 0
    assert "ACHADOS (2)" in saida.out
    assert {p.suffix for p in tmp_path.iterdir()} == {".json", ".csv", ".html"}


def test_fail_on_define_o_codigo_de_saida(tmp_path):
    base = ["analyze", str(NGINX), "-r", "json", "-o", str(tmp_path), "-q"]

    assert main(base) == 0                                  # padrão: never
    assert main(base + ["--fail-on", "high"]) == 0          # só há achados medium
    assert main(base + ["--fail-on", "medium"]) == 1


def test_arquivo_inexistente(tmp_path, capsys):
    codigo = main(["analyze", str(tmp_path / "nao_existe.log")])

    assert codigo == 2
    assert "erro:" in capsys.readouterr().err


def test_stdin_com_formato(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(NGINX.read_text(encoding="utf-8")))

    codigo = main(["analyze", "-", "--format", "nginx", "--no-color", "-q"])

    assert codigo == 0
    assert "ACHADOS (2)" in capsys.readouterr().out


def test_stdin_sem_formato_falha(capsys):
    codigo = main(["analyze", "-"])

    assert codigo == 2
    assert "stdin" in capsys.readouterr().err


def test_parse_timezone():
    assert parse_timezone(None) is None
    assert parse_timezone("UTC") is timezone.utc
    assert parse_timezone("-03:00") == timezone(timedelta(hours=-3))
    assert parse_timezone("+0530") == timezone(timedelta(hours=5, minutes=30))
    assert parse_timezone("America/Sao_Paulo").key == "America/Sao_Paulo"
    for invalido in ("Marte/Olimpo", "+25:00", "25:00"):
        with pytest.raises(CliError):
            parse_timezone(invalido)


def test_timezone_fim_a_fim(tmp_path):
    codigo = main(["analyze", str(AUTH), "--year", "2026", "--timezone=-03:00",
                   "-r", "json", "-o", str(tmp_path), "--name", "r", "-q"])

    dados = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert codigo == 0
    assert dados["stats"]["first_timestamp"] == "2026-10-08T06:12:01+00:00"


def test_comando_rules_mostra_os_padroes(capsys):
    codigo = main(["rules"])

    assert codigo == 0
    assert yaml.safe_load(capsys.readouterr().out) == DEFAULT_RULES


def test_comando_rules_com_arquivo(tmp_path, capsys):
    arquivo = tmp_path / "minhas.yaml"
    arquivo.write_text(yaml.safe_dump({"auth_brute_force": {"threshold": 3}}), encoding="utf-8")

    codigo = main(["rules", "--rules", str(arquivo)])

    assert codigo == 0
    assert yaml.safe_load(capsys.readouterr().out)["auth_brute_force"]["threshold"] == 3


def test_regras_invalidas_dao_erro_claro(tmp_path, capsys):
    arquivo = tmp_path / "ruim.yaml"
    arquivo.write_text(yaml.safe_dump({"brute_forse": {"threshold": 3}}), encoding="utf-8")

    codigo = main(["analyze", str(NGINX), "--rules", str(arquivo), "-q"])

    assert codigo == 2
    assert "erro:" in capsys.readouterr().err


def test_parse_reports():
    assert parse_reports(None) == ["console"]
    assert parse_reports(["json,csv"]) == ["json", "csv"]
    assert parse_reports(["json", "html,json"]) == ["json", "html"]  # sem duplicados
    assert parse_reports(["all"]) == ["console", "json", "csv", "html"]
    with pytest.raises(CliError):
        parse_reports(["pdf"])


def test_version(capsys):
    with pytest.raises(SystemExit) as saida:
        main(["--version"])

    assert saida.value.code == 0
    assert "log-analyzer" in capsys.readouterr().out


def test_nada_reconhecido_e_erro(tmp_path, capsys):
    lixo = tmp_path / "lixo.log"
    lixo.write_text("isto não é nginx\n" * 3, encoding="utf-8")

    codigo = main(["analyze", str(lixo), "--format", "nginx", "-q"])

    assert codigo == 2
    assert "nenhuma" in capsys.readouterr().err.lower()