"""Interface de linha de comando do log-analyzer."""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import timedelta, timezone, tzinfo
from importlib import metadata
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from log_analyzer.config import load_rules
from log_analyzer.findings import Severity
from log_analyzer.parsers import PARSERS
from log_analyzer.pipeline import AnalysisError, analyze
from log_analyzer.reporters import REPORTERS, get_reporter

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_TOP_N_REPORTERS = {"console", "json", "html"}  # os que aceitam top_n
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")

EPILOG = """\
códigos de saída:
  0  análise concluída (e nenhum achado na severidade de --fail-on)
  1  há achados com severidade igual ou acima de --fail-on
  2  erro de uso (arquivo inexistente, formato não reconhecido, regras inválidas...)

exemplos:
  log-analyzer analyze /var/log/auth.log
  log-analyzer analyze logs/ -r html,json -o reports
  log-analyzer analyze access.log --format nginx --fail-on high -q
  sudo cat /var/log/auth.log | log-analyzer analyze - --format syslog
  log-analyzer analyze app.log -f generic --pattern '(?P<ts>\\S+ \\S+) \\[(?P<level>\\w+)\\] (?P<message>.*)'
  log-analyzer rules > minhas_regras.yaml
"""


class CliError(Exception):
    """Erro de uso da linha de comando."""


def _version() -> str:
    try:
        return metadata.version("log-analyzer")
    except metadata.PackageNotFoundError:
        return "desconhecida"


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("deve ser um número inteiro") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("deve ser maior que zero")
    return value


def parse_timezone(value: str | None) -> tzinfo | None:
    """None = fuso local do sistema. Aceita UTC, deslocamento (-03:00) ou nome IANA."""
    if value is None:
        return None
    if value.upper() in ("UTC", "Z"):
        return timezone.utc
    match = _OFFSET.match(value)
    if match:
        sign = -1 if match[1] == "-" else 1
        hours, minutes = int(match[2]), int(match[3])
        if hours > 23 or minutes > 59:
            raise CliError(f"Deslocamento de fuso inválido: '{value}'.")
        return timezone(sign * timedelta(hours=hours, minutes=minutes))
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        raise CliError(
            f"Fuso horário inválido: '{value}'. Exemplos: America/Sao_Paulo, UTC, --timezone=-03:00"
        ) from None


def parse_reports(values: list[str] | None) -> list[str]:
    """Aceita --report json,csv e --report json --report csv; 'all' = todos."""
    names: list[str] = []
    for value in values or ["console"]:
        for item in value.split(","):
            item = item.strip().lower()
            if not item:
                continue
            for name in (list(REPORTERS) if item == "all" else [item]):
                if name not in REPORTERS:
                    raise CliError(
                        f"Relatório desconhecido: '{name}'. Opções: {', '.join(REPORTERS)}, all"
                    )
                if name not in names:
                    names.append(name)
    return names or ["console"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analisador de logs focado em detecção de atividade suspeita.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="comando")

    analyze_cmd = sub.add_parser(
        "analyze",
        help="analisa logs e gera relatórios",
        description="Analisa um arquivo, uma pasta (recursivo, inclui .gz) ou stdin ('-').",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    analyze_cmd.add_argument("target", metavar="CAMINHO", help="arquivo, pasta ou '-' para stdin")
    analyze_cmd.add_argument(
        "-f", "--format", choices=["auto", *PARSERS], default="auto",
        help="formato dos logs (padrão: auto, detecta arquivo por arquivo)",
    )
    analyze_cmd.add_argument("--pattern", metavar="REGEX",
                             help="regex com grupos nomeados (obrigatória com --format generic)")
    analyze_cmd.add_argument("--timestamp-format", metavar="FORMATO",
                             help="formato strptime do grupo 'ts' no modo generic")
    analyze_cmd.add_argument("--year", type=int, metavar="ANO",
                             help="ano dos logs syslog clássicos (que não trazem ano)")
    analyze_cmd.add_argument(
        "--timezone", metavar="FUSO",
        help="fuso dos horários sem fuso, ex.: America/Sao_Paulo, UTC "
             "(para negativos use --timezone=-03:00). Padrão: fuso do sistema",
    )
    analyze_cmd.add_argument("--rules", metavar="ARQUIVO", help="arquivo YAML de regras")
    analyze_cmd.add_argument(
        "-r", "--report", action="append", metavar="FORMATOS",
        help="console, json, csv, html ou all (separe por vírgula ou repita). Padrão: console",
    )
    analyze_cmd.add_argument("-o", "--output", default="reports", metavar="PASTA",
                             help="pasta dos relatórios em arquivo (padrão: reports)")
    analyze_cmd.add_argument("--name", default="log-analyzer-report", metavar="NOME",
                             help="nome-base dos arquivos de relatório")
    analyze_cmd.add_argument(
        "--fail-on", choices=["never", *(s.label for s in Severity)], default="never",
        help="sair com código 1 se houver achado nesta severidade ou acima (padrão: never)",
    )
    analyze_cmd.add_argument("--top", type=positive_int, default=10, metavar="N",
                             help="tamanho dos rankings (padrão: 10)")
    analyze_cmd.add_argument("--no-color", action="store_true", help="desliga as cores no console")
    analyze_cmd.add_argument("-q", "--quiet", action="store_true",
                             help="não mostra o resumo no stderr")

    rules_cmd = sub.add_parser(
        "rules", help="mostra as regras em uso (modelo para o seu rules.yaml)",
    )
    rules_cmd.add_argument("--rules", metavar="ARQUIVO", help="mostra as regras com este YAML aplicado")
    return parser


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    sys.stdout.write(yaml.safe_dump(
        rules, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000,
    ))
    return EXIT_OK


def _cmd_analyze(args: argparse.Namespace) -> int:
    report_names = parse_reports(args.report)
    assume_tz = parse_timezone(args.timezone)
    if Path(args.name).name != args.name:
        raise CliError("--name não pode conter separadores de caminho.")
    rules = load_rules(args.rules)

    data = analyze(
        args.target, log_format=args.format, rules=rules, assume_tz=assume_tz,
        year=args.year, pattern=args.pattern, timestamp_format=args.timestamp_format,
    )
    if data.parsed == 0:
        raise CliError(
            f"nenhuma linha foi reconhecida ({data.skipped} ignoradas). "
            "Confira o formato com --format."
        )

    written: list[Path] = []
    for name in report_names:
        options: dict = {}
        if name in _TOP_N_REPORTERS:
            options["top_n"] = args.top
        if name == "console" and args.no_color:
            options["color"] = False
        reporter = get_reporter(name, **options)
        if name == "console":
            sys.stdout.write(reporter.render(data))
        else:
            written.append(reporter.write(data, Path(args.output) / f"{args.name}{reporter.extension}"))

    if not args.quiet:
        counts = data.severity_counts()
        resumo = ", ".join(f"{n} {label}" for label, n in counts.items() if n) or "nenhum"
        print(
            f"Analisadas {data.parsed} entradas ({data.log_format}); "
            f"{data.skipped} linhas ignoradas; achados: {len(data.findings)} ({resumo}).",
            file=sys.stderr,
        )
        for path in written:
            print(f"Relatório gravado: {path}", file=sys.stderr)

    if args.fail_on != "never":
        limit = Severity[args.fail_on.upper()]
        if any(finding.severity >= limit for finding in data.findings):
            if not args.quiet:
                print(f"Falhando: há achados com severidade {args.fail_on} ou acima.", file=sys.stderr)
            return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "rules":
            return _cmd_rules(args)
        return _cmd_analyze(args)
    except BrokenPipeError:  # ex.: log-analyzer analyze ... | head
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        return EXIT_OK
    except (CliError, AnalysisError, OSError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrompido.", file=sys.stderr)
        return 130