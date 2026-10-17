import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_analyzer.analyzers.detectors import DetectionEngine, build_detectors
from log_analyzer.analyzers.stats import StatsCollector, compute_stats
from log_analyzer.config import load_rules
from log_analyzer.findings import Finding, Severity
from log_analyzer.models import LogEntry
from log_analyzer.parsers import get_parser
from log_analyzer.readers import read_lines
from log_analyzer.reporters import ReportData, get_reporter
from log_analyzer.reporters.console import ConsoleReporter
from log_analyzer.reporters.csv_report import COLUMNS, CsvReporter
from log_analyzer.reporters.html_report import HtmlReporter
from log_analyzer.reporters.json_report import JsonReporter

SAMPLES = Path(__file__).parent / "samples"
BRT = timezone(timedelta(hours=-3))
FIXO = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


def analisar(nome="nginx_sample.log", formato="nginx", **kwargs) -> ReportData:
    parser = get_parser(formato, **kwargs)
    engine = DetectionEngine(build_detectors(load_rules()), assume_tz=BRT)
    collector = StatsCollector(assume_tz=BRT)
    for _ in collector.consume(engine.consume(parser.parse(read_lines(SAMPLES / nome)))):
        pass
    return ReportData(
        stats=collector.stats, findings=engine.findings(), source=nome, log_format=formato,
        parsed=parser.parsed, skipped=parser.skipped, generated_at=FIXO,
    )


def vazio() -> ReportData:
    return ReportData(stats=compute_stats([]), generated_at=FIXO)


# ---------- console ----------

def test_console_sem_cor_tem_o_conteudo_principal():
    saida = ConsoleReporter(color=False).render(analisar())

    assert "ACHADOS (2)" in saida
    assert "ESTATÍSTICAS" in saida
    assert "203.0.113.99" in saida
    assert "MEDIUM" in saida
    assert "\x1b" not in saida


def test_console_com_cor_usa_ansi():
    assert "\x1b[" in ConsoleReporter(color=True).render(analisar())


def test_console_sem_achados():
    saida = ConsoleReporter(color=False).render(vazio())
    assert "Nenhum achado." in saida


def test_console_nunca_grava_ansi_em_arquivo(tmp_path):
    destino = ConsoleReporter(color=True).write(analisar(), tmp_path / "relatorio.txt")
    assert "\x1b" not in destino.read_text(encoding="utf-8")


def test_console_neutraliza_sequencias_de_escape_do_log():
    perigoso = LogEntry(file="x.log", line_number=1, raw="\x1b[2J\x1b]0;pwned\x07 linha")
    achado = Finding(rule="r", severity=Severity.LOW, title="t\x1b[31m", ip="203.0.113.1",
                     count=1, evidence=[perigoso])
    dados = ReportData(stats=compute_stats([]), findings=[achado], generated_at=FIXO)

    saida = ConsoleReporter(color=False).render(dados)

    assert "\x1b" not in saida
    assert "\x07" not in saida


# ---------- json ----------

def test_json_tem_estrutura_completa():
    dados = json.loads(JsonReporter().render(analisar()))

    assert dados["meta"]["source"] == "nginx_sample.log"
    assert dados["meta"]["entries_parsed"] == 10
    assert dados["summary"]["total_findings"] == 2
    assert dados["summary"]["by_severity"]["medium"] == 2
    assert dados["findings"][0]["evidence"]
    assert dados["stats"]["total"] == 10
    assert dados["stats"]["by_status"]["404"] == 4


def test_write_cria_pastas_e_arquivo(tmp_path):
    destino = JsonReporter().write(analisar(), tmp_path / "sub" / "pasta" / "r.json")

    assert destino.exists()
    assert json.loads(destino.read_text(encoding="utf-8"))["summary"]["total_findings"] == 2


# ---------- csv ----------

def test_csv_uma_linha_por_achado():
    leitor = csv.DictReader(io.StringIO(CsvReporter().render(analisar())))
    linhas = list(leitor)

    assert leitor.fieldnames == COLUMNS
    assert len(linhas) == 2
    assert {l["rule"] for l in linhas} == {"web_scanner", "suspicious_request"}
    assert all(l["ip"] == "203.0.113.99" for l in linhas)
    assert all(l["sample_evidence"] for l in linhas)


def test_csv_neutraliza_formulas():
    achado = Finding(rule="x", severity=Severity.LOW, title="=cmd|' /C calc'!A0",
                     description="@SUM(1)", ip="203.0.113.1", count=1)
    dados = ReportData(stats=compute_stats([]), findings=[achado], generated_at=FIXO)

    linha = next(csv.DictReader(io.StringIO(CsvReporter().render(dados))))

    assert linha["title"].startswith("'=")
    assert linha["description"].startswith("'@")


# ---------- html ----------

def test_html_e_autocontido_e_protegido():
    saida = HtmlReporter().render(analisar())

    assert saida.startswith("<!DOCTYPE html>")
    assert "203.0.113.99" in saida
    assert "Content-Security-Policy" in saida
    assert "<script" not in saida
    assert "src=" not in saida


def test_html_escapa_conteudo_malicioso_do_log():
    entrada = LogEntry(file="x.log", line_number=1, raw="<script>alert(1)</script>")
    achado = Finding(rule="r", severity=Severity.HIGH, title="<img src=x onerror=alert(1)>",
                     description="<b>x</b>", ip="203.0.113.1", count=1, evidence=[entrada])
    dados = ReportData(stats=compute_stats([]), findings=[achado], generated_at=FIXO)

    saida = HtmlReporter().render(dados)

    assert "<script>alert(1)</script>" not in saida
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in saida
    assert "<img" not in saida
    assert "<b>x</b>" not in saida


def test_html_sem_achados():
    saida = HtmlReporter().render(vazio())

    assert "Nenhum achado." in saida
    assert saida.startswith("<!DOCTYPE html>")


# ---------- registro ----------

def test_get_reporter_cria_o_relatorio_certo():
    reporter = get_reporter("json", top_n=5)

    assert isinstance(reporter, JsonReporter)
    assert reporter.top_n == 5


def test_relatorio_desconhecido():
    with pytest.raises(ValueError):
        get_reporter("pdf")

def test_html_resumo_em_linguagem_natural():
    assert "Tudo tranquilo por aqui" in HtmlReporter().render(vazio())

    saida = HtmlReporter().render(analisar())
    assert "2 achados</strong> para olhar com atenção" in saida
    assert "médio" in saida  # selos em português no HTML


def test_html_tem_barra_de_severidade_e_tema_escuro():
    saida = HtmlReporter().render(analisar())

    assert 'class="sevbar"' in saida
    assert "prefers-color-scheme:dark" in saida