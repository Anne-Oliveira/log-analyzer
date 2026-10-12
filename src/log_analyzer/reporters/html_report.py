"""Relatório HTML: arquivo único, sem recursos externos e com conteúdo escapado."""
from __future__ import annotations

import html
import json
from collections.abc import Iterable
from pathlib import Path

from log_analyzer.findings import Finding, Severity
from log_analyzer.reporters.base import ReportData, Reporter, fmt_dt

_CSS = """
:root{--bg:#f7f7fb;--fg:#1c1b22;--muted:#6b6880;--card:#ffffff;--line:#e3e1ee;--accent:#7c3aed;
--critical:#b91c1c;--high:#dc2626;--medium:#d97706;--low:#0891b2;--bar:#a78bfa}
@media (prefers-color-scheme: dark){:root{--bg:#120d1e;--fg:#ece9f7;--muted:#9d97b8;--card:#1b1530;
--line:#2d2548;--accent:#c084fc;--bar:#a78bfa}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px 64px}
h1{margin:0 0 4px;font-size:26px}
h2{margin:40px 0 12px;font-size:19px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{margin:24px 0 8px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.sub{color:var(--muted);margin:0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.num{font-size:26px;font-weight:700;color:var(--accent)}
.lbl{color:var(--muted);font-size:13px}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 16px}
.pill{border:1px solid var(--line);border-radius:999px;padding:2px 12px;font-size:13px;background:var(--card);text-transform:uppercase}
.badge{display:inline-block;border-radius:6px;padding:1px 8px;margin-right:8px;font-size:12px;font-weight:700;color:#fff;text-transform:uppercase}
.badge.sev-critical{background:var(--critical)}
.badge.sev-high{background:var(--high)}
.badge.sev-medium{background:var(--medium)}
.badge.sev-low{background:var(--low)}
details.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--line);border-radius:8px;margin:10px 0}
details.finding.sev-critical{border-left-color:var(--critical)}
details.finding.sev-high{border-left-color:var(--high)}
details.finding.sev-medium{border-left-color:var(--medium)}
details.finding.sev-low{border-left-color:var(--low)}
summary{cursor:pointer;padding:12px 14px;font-weight:600}
.rule{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted);margin-right:8px;font-weight:400}
.body{padding:0 14px 14px}
.meta{color:var(--muted);margin:0 0 8px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:8px 0;font-size:13px}
dt{color:var(--muted)}
dd{margin:0;word-break:break-word}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--card)}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}
.hour{display:flex;align-items:center;gap:10px;font-size:12px;font-family:ui-monospace,monospace;margin:3px 0}
.hour .h{width:130px;color:var(--muted)}
.track{flex:1;background:var(--card);border-radius:4px;height:12px;overflow:hidden}
.fill{display:block;height:100%;background:var(--bar)}
.empty{color:var(--muted)}
footer{margin-top:48px;color:var(--muted);font-size:12px}
"""


def esc(value: object) -> str:
    """Todo texto vindo de log passa por aqui antes de entrar no HTML."""
    return html.escape(str(value), quote=True)


def _table(headers: list[str], rows: Iterable[tuple]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


class HtmlReporter(Reporter):
    name = "html"
    extension = ".html"

    def __init__(self, top_n: int = 10, max_hours: int = 72,
                 title: str = "Log Analyzer — relatório") -> None:
        self.top_n = top_n
        self.max_hours = max_hours
        self.title = title

    def render(self, data: ReportData) -> str:
        stats = data.stats
        counts = data.severity_counts()

        cards = [
            ("Entradas analisadas", data.parsed),
            ("Linhas ignoradas", data.skipped),
            ("Achados", len(data.findings)),
            ("Críticos + altos", counts["critical"] + counts["high"]),
            ("IPs distintos", len(stats.ips)),
        ]
        cards_html = "".join(
            f'<div class="card"><div class="num">{esc(value)}</div><div class="lbl">{esc(label)}</div></div>'
            for label, value in cards
        )
        pills_html = "".join(
            f'<span class="pill">{esc(label)} <b>{count}</b></span>' for label, count in counts.items()
        )

        if data.findings:
            findings_html = "".join(self._finding(i, f) for i, f in enumerate(data.findings, start=1))
        else:
            findings_html = '<p class="empty">Nenhum achado.</p>'

        title = esc(self.title)
        source = esc(data.source or "-")
        log_format = esc(data.log_format or "-")
        period = f"{esc(fmt_dt(stats.first_timestamp))} → {esc(fmt_dt(stats.last_timestamp))}"
        generated = esc(fmt_dt(data.generated_at))

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{title}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header>
<h1>{title}</h1>
<p class="sub">Origem: <b>{source}</b> · Formato: <b>{log_format}</b> · Período: {period}</p>
</header>
<section class="cards">{cards_html}</section>
<h2>Achados ({len(data.findings)})</h2>
<div class="pills">{pills_html}</div>
{findings_html}
<h2>Estatísticas</h2>
{self._stats(data)}
{self._hours(data)}
<footer>Gerado por log-analyzer em {generated}. Todos os horários estão em UTC.</footer>
</main>
</body>
</html>
"""

    def _finding(self, index: int, finding: Finding) -> str:
        label = esc(finding.severity.label)
        open_attr = " open" if finding.severity >= Severity.HIGH else ""

        meta = []
        if finding.ip:
            meta.append(f"<b>IP</b> {esc(finding.ip)}")
        if finding.user:
            meta.append(f"<b>Usuário</b> {esc(finding.user)}")
        meta.append(f"<b>Ocorrências</b> {finding.count}")
        if finding.first_seen:
            meta.append(f"<b>Período</b> {esc(fmt_dt(finding.first_seen))} → {esc(fmt_dt(finding.last_seen))}")

        details_html = ""
        if finding.details:
            items = []
            for key, value in finding.details.items():
                if isinstance(value, list):
                    text = ", ".join(str(item) for item in value)
                else:
                    text = json.dumps(value, ensure_ascii=False)
                items.append(f"<dt>{esc(key)}</dt><dd>{esc(text)}</dd>")
            details_html = "<dl>" + "".join(items) + "</dl>"

        evidence_html = ""
        if finding.evidence:
            lines = "\n".join(
                esc(f"{Path(e.file).name}:{e.line_number}  {e.raw}") for e in finding.evidence
            )
            evidence_html = f"<h3>Evidências ({len(finding.evidence)})</h3><pre>{lines}</pre>"

        description = f"<p>{esc(finding.description)}</p>" if finding.description else ""
        return (
            f'<details class="finding sev-{label}"{open_attr}>'
            f'<summary><span class="badge sev-{label}">{label}</span>'
            f'<span class="rule">{esc(finding.rule)}</span>{esc(finding.title)}</summary>'
            f'<div class="body"><p class="meta">{" · ".join(meta)}</p>'
            f"{description}{details_html}{evidence_html}</div></details>"
        )

    def _stats(self, data: ReportData) -> str:
        stats = data.stats
        blocks = [_table(
            ["Métrica", "Valor"],
            [("Total de entradas", stats.total), ("Entradas sem horário", stats.without_timestamp)],
        )]
        for heading, counter in (
            ("Por nível", stats.by_level),
            ("Por evento", stats.by_event),
            ("Por processo", stats.by_process),
        ):
            if counter:
                blocks.append(f"<h3>{esc(heading)}</h3>" + _table(
                    ["Item", "Ocorrências"], counter.most_common(self.top_n)))
        if stats.by_status:
            blocks.append("<h3>Status HTTP</h3>" + _table(
                ["Status", "Respostas"], sorted(stats.by_status.items())))

        top_ips = stats.top_ips(self.top_n)
        if top_ips:
            rows = [(i.ip, i.count, fmt_dt(i.first_seen), fmt_dt(i.last_seen)) for i in top_ips]
            blocks.append("<h3>Top IPs</h3>" + _table(
                ["IP", "Ocorrências", "Primeira vez", "Última vez"], rows))
        if stats.users:
            blocks.append("<h3>Top usuários</h3>" + _table(
                ["Usuário", "Ocorrências"], stats.top_users(self.top_n)))
        if stats.paths:
            rows = [(path[:80], n) for path, n in stats.top_paths(self.top_n)]
            blocks.append("<h3>Top caminhos</h3>" + _table(["Caminho", "Requisições"], rows))
        return "".join(blocks)

    def _hours(self, data: ReportData) -> str:
        by_hour = data.stats.by_hour
        if not by_hour:
            return ""
        items = sorted(by_hour.items())
        note = ""
        if len(items) > self.max_hours:
            busiest = sorted(items, key=lambda pair: -pair[1])[: self.max_hours]
            items = sorted(busiest)
            note = f" (as {self.max_hours} horas mais movimentadas)"
        maximum = max(count for _, count in items)
        rows = []
        for hour, count in items:
            percent = max(1, round(count / maximum * 100))
            label = esc(hour.strftime("%Y-%m-%d %H:00"))
            rows.append(
                f'<div class="hour"><span class="h">{label}</span>'
                f'<span class="track"><span class="fill" style="width:{percent}%"></span></span>'
                f'<span class="n">{count}</span></div>'
            )
        return f"<h2>Atividade por hora (UTC){esc(note)}</h2>" + "".join(rows)