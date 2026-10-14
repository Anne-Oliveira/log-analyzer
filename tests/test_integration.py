"""Testes de ponta a ponta: o comando de verdade, em outro processo, com logs em disco."""
import gzip
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from log_analyzer.cli import main
from log_analyzer.findings import Severity
from log_analyzer.pipeline import analyze

SAMPLES = Path(__file__).parent / "samples"


def executar(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "log_analyzer", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def test_cli_como_processo_gera_todos_os_relatorios(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    for nome in ("auth_sample.log", "nginx_sample.log", "app_sample.jsonl"):
        shutil.copy(SAMPLES / nome, logs / nome)
    saida = tmp_path / "reports"

    resultado = executar(
        "analyze", str(logs), "--year", "2026", "--timezone=-03:00",
        "-r", "all", "-o", str(saida), "--no-color",
    )

    assert resultado.returncode == 0, resultado.stderr
    assert "ACHADOS (3)" in resultado.stdout
    assert "Analisadas 23 entradas" in resultado.stderr
    for extensao in (".json", ".csv", ".html"):
        assert (saida / f"log-analyzer-report{extensao}").exists()

    dados = json.loads((saida / "log-analyzer-report.json").read_text(encoding="utf-8"))
    assert dados["summary"]["total_findings"] == 3
    assert dados["meta"]["lines_skipped"] == 0


def test_cli_como_processo_respeita_fail_on_e_erros(tmp_path):
    arquivo = tmp_path / "acesso.log"
    shutil.copy(SAMPLES / "nginx_sample.log", arquivo)
    base = ("analyze", str(arquivo), "--no-color", "-q")

    assert executar(*base).returncode == 0
    assert executar(*base, "--fail-on", "medium").returncode == 1
    assert executar("analyze", str(tmp_path / "nao_existe.log"), "-q").returncode == 2


def test_ajuda_e_versao_via_python_m():
    ajuda = executar("--help")
    versao = executar("--version")

    assert ajuda.returncode == 0
    assert "analyze" in ajuda.stdout
    assert versao.returncode == 0
    assert "log-analyzer" in versao.stdout


def test_rotacao_com_gz_detecta_login_critico_entre_arquivos(tmp_path):
    def falha(segundo: int) -> str:
        return (f"Oct  8 03:00:{segundo:02d} srv sshd[1]: "
                "Failed password for root from 203.0.113.45 port 22 ssh2")

    logs = tmp_path / "logs"
    logs.mkdir()
    # O mais antigo é o .2.gz, depois o .1, e por último o arquivo atual.
    with gzip.open(logs / "auth.log.2.gz", "wt", encoding="utf-8") as arquivo:
        arquivo.write("\n".join(falha(s) for s in range(0, 3)) + "\n")
    (logs / "auth.log.1").write_text(
        "\n".join(falha(s) for s in range(3, 6)) + "\n", encoding="utf-8")
    (logs / "auth.log").write_text(
        "Oct  8 03:00:20 srv sshd[1]: Accepted password for root from 203.0.113.45 port 22 ssh2\n"
        "Oct  8 03:05:00 srv CRON[77]: pam_unix(cron:session): session opened for user root\n",
        encoding="utf-8",
    )
    saida = tmp_path / "out"

    codigo = main([
        "analyze", str(logs), "--year", "2026", "--timezone=-03:00",
        "-r", "json", "-o", str(saida), "--fail-on", "critical", "-q",
    ])

    assert codigo == 1
    dados = json.loads((saida / "log-analyzer-report.json").read_text(encoding="utf-8"))
    assert dados["meta"]["entries_parsed"] == 8
    achado = dados["findings"][0]
    assert achado["rule"] == "auth_brute_force"
    assert achado["severity"] == "critical"
    assert achado["count"] == 6
    arquivos = {Path(e["file"]).name for e in achado["evidence"]}
    assert arquivos == {"auth.log.2.gz", "auth.log.1", "auth.log"}


def test_volume_grande_e_processado_em_streaming(tmp_path):
    normais = 20_000
    linhas = []
    for i in range(normais):
        horas, resto = divmod(i, 3600)  # uma requisição por segundo
        minutos, segundos = divmod(resto, 60)
        horario = f"08/Oct/2026:{horas:02d}:{minutos:02d}:{segundos:02d} -0300"
        ip = f"198.51.100.{i % 50 + 1}"
        linhas.append(
            f'{ip} - - [{horario}] "GET /pagina/{i % 100} HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
        if i == 10_000:  # um scanner dispara 40 requisições no meio do tráfego normal
            linhas.extend(
                f'203.0.113.200 - - [{horario}] "GET /x{n} HTTP/1.1" 404 153 "-" "curl/8.5.0"'
                for n in range(40)
            )
    arquivo = tmp_path / "access.log"
    arquivo.write_text("\n".join(linhas) + "\n", encoding="utf-8")

    dados = analyze(arquivo)

    assert dados.log_format == "nginx"
    assert dados.parsed == normais + 40
    assert dados.skipped == 0
    assert dados.stats.total == normais + 40
    assert len(dados.stats.ips) == 51

    assert len(dados.findings) == 1
    achado = dados.findings[0]
    assert achado.rule == "web_scanner"
    assert achado.ip == "203.0.113.200"
    assert achado.count == 40
    assert achado.severity == Severity.HIGH
    assert len(achado.evidence) == 10  # evidências limitadas mesmo em ataques grandes