"""Relatório HTML: arquivo único, sem recursos externos e com conteúdo escapado."""
from __future__ import annotations

import html
import json
from collections.abc import Iterable
from pathlib import Path

from log_analyzer.findings import Finding, Severity
from log_analyzer.reporters.base import ReportData, Reporter, fmt_dt

# Nomes exibidos no HTML (as classes e o resto do sistema continuam usando os nomes em inglês).
_SEVERITY_PT = {"critical": "crítico", "high": "alto", "medium": "médio", "low": "baixo"}

# Para mudar o visual, o mais simples é mexer nas variáveis de cor do :root (claro e escuro).
_CSS = r"""
:root{
  --bg:#fcf7fb;--paper:#ffffff;--ink:#2b1f3f;--muted:#7b6c91;--line:#eadcf0;--soft:#f6edf9;
  --accent:#7c3aed;--pink:#db2777;--marker:#fbcfe8;
  --code-bg:#241a38;--code-ink:#efe8fb;--code-ln:#f9a8d4;
  --c-critical:#be123c;--c-high:#db2777;--c-medium:#7c3aed;--c-low:#4f5bd5;--on-sev:#ffffff;
  --shadow:0 1px 2px rgba(80,40,120,.06),0 12px 28px -18px rgba(124,58,237,.45);
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Noto Serif",Georgia,serif;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#120d1e;--paper:#1b1530;--ink:#f1ecfb;--muted:#a79bc4;--line:#2d2548;--soft:#241b3e;
    --accent:#c084fc;--pink:#f472b6;--marker:rgba(244,114,182,.28);
    --code-bg:#0d0817;--code-ink:#e9e1f8;--code-ln:#f472b6;
    --c-critical:#fb7185;--c-high:#f472b6;--c-medium:#c084fc;--c-low:#93a3ff;--on-sev:#1a0f2e;
    --shadow:0 12px 28px -18px rgba(0,0,0,.7);
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--sans);border-top:5px solid var(--accent)}
main{max-width:1040px;margin:0 auto;padding:40px 22px 72px}

.sev-critical{--c:var(--c-critical)}
.sev-high{--c:var(--c-high)}
.sev-medium{--c:var(--c-medium)}
.sev-low{--c:var(--c-low)}

.brand{font:600 12px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--pink)}
h1{font:700 clamp(28px,5vw,40px)/1.15 var(--serif);margin:6px 0 18px}
.lead{font:400 clamp(19px,3vw,23px)/1.4 var(--serif);margin:0 0 4px}
.lead strong{font-weight:700;background:linear-gradient(transparent 60%,var(--marker) 60%);padding:0 3px}
.sub{color:var(--muted);margin:0 0 4px}
.source{font:13px var(--mono);color:var(--muted);margin:14px 0 0}
.source b{color:var(--ink);font-weight:600}

.glance{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0;margin:22px 0 0}
.glance li{background:var(--paper);border:1px solid var(--line);border-radius:999px;padding:5px 14px;font-size:13px;color:var(--muted)}
.glance b{color:var(--accent);font-weight:700;margin-right:3px}

.sevbar{display:flex;gap:3px;height:10px;border-radius:999px;overflow:hidden;background:var(--soft);margin:26px 0 12px}
.seg{background:var(--c);min-width:6px}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;list-style:none;padding:0;margin:0;font-size:13px;color:var(--muted)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--c);margin-right:6px}
.legend b{color:var(--ink)}

h2{font:700 25px/1.2 var(--serif);margin:52px 0 16px}
.hl{background:linear-gradient(transparent 62%,var(--marker) 62%);padding:0 4px;margin:0 -4px}

details.finding{background:var(--paper);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:14px;margin:12px 0;box-shadow:var(--shadow)}
summary{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;padding:14px 18px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"";flex:none;width:7px;height:7px;border:solid var(--muted);border-width:0 2px 2px 0;transform:rotate(-45deg);transition:transform .15s}
details[open]>summary::before{transform:rotate(45deg)}
summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:12px}
.badge{font:700 11px var(--sans);letter-spacing:.06em;text-transform:uppercase;padding:3px 10px;border-radius:999px;background:var(--c);color:var(--on-sev)}
.ftitle{flex:1 1 260px;font:600 16px/1.4 var(--sans)}
.rule{font:12px var(--mono);color:var(--muted);background:var(--soft);padding:2px 8px;border-radius:6px}
.body{padding:0 18px 18px 37px}
.desc{margin:0 0 12px}
.chips{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0;margin:0 0 14px}
.chips li{background:var(--soft);border-radius:8px;padding:4px 10px;font-size:13px;word-break:break-word}
.chips li span{color:var(--muted);margin-right:6px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;font-size:13px;margin:0 0 14px}
dt{color:var(--muted);font-family:var(--mono)}
dd{margin:0;word-break:break-word}
h4{font:600 12px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:14px 0 8px}
pre.evidence{margin:0;background:var(--code-bg);color:var(--code-ink);border-radius:10px;padding:14px 16px;overflow-x:auto;font:12.5px/1.65 var(--mono);white-space:pre-wrap;word-break:break-all}
.ln{color:var(--code-ln);margin-right:12px;user-select:none}
.empty{background:var(--paper);border:1px dashed var(--line);border-radius:14px;padding:22px;text-align:center;color:var(--muted)}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.panel{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:var(--shadow);min-width:0}
.panel.wide{grid-column:1/-1}
.panel h3{font:700 17px var(--serif);margin:0 0 10px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;padding:6px 8px;border-bottom:2px solid var(--line)}
td{padding:7px 8px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums;word-break:break-word}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--soft)}

.hours{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:14px 18px;box-shadow:var(--shadow)}
.hour{display:flex;align-items:center;gap:12px;font:12px var(--mono);margin:6px 0}
.hour .h{flex:none;width:128px;color:var(--muted)}
.track{flex:1;height:12px;border-radius:999px;background:var(--soft);overflow:hidden}
.fill{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--accent),var(--pink))}
.hour .n{flex:none;width:44px;text-align:right}

footer{margin-top:56px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}

@media (max-width:560px){
  main{padding:28px 14px 56px}
  .body{padding-left:18px}
  .hour .h{width:108px}
}
@media (prefers-reduced-motion:reduce){summary::before{transition:none}}
@media print{body{border:0}details.finding,.panel{break-inside:avoid;box-shadow:none}}
"""


def esc(value: object) -> str:
    """Todo texto vindo de log passa por aqui antes de entrar no HTML."""
    return html.escape(str(value), quote=True)


def _plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many


def _table(headers: list[str], rows: Iterable[tuple]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _panel(title: str, body: str, wide: bool = False) -> str:
    css = "panel wide" if wide else "panel"
    return f'<section class="{css}"><h3>{esc(title)}</h3>{body}</section>'


class HtmlReporter(Reporter):
    name = "html"
    extension = ".html"

    def __init__(self, top_n: int = 10, max_hours: int = 72,
                 title: str = "Relatório de análise de logs") -> None:
        self.top_n = top_n
        self.max_hours = max_hours
        self.title = title

    def render(self, data: ReportData) -> str:
        stats = data.stats
        counts = data.severity_counts()
        total = len(data.findings)
        serious = counts["critical"] + counts["high"]

        if total == 0:
            analisadas = _plural(data.parsed, "entrada analisada", "entradas analisadas")
            lead = (f"<strong>Tudo tranquilo por aqui:</strong> "
                    f"nenhum achado em {data.parsed} {analisadas}.")
            detail = ""
        else:
            achados = _plural(total, "achado", "achados")
            lead = f"<strong>{total} {achados}</strong> para olhar com atenção."
            if serious:
                detail = f"{serious} {_plural(serious, 'é', 'são')} de severidade alta ou crítica."
            else:
                detail = "Nenhum de severidade alta ou crítica."
        detail_html = f'<p class="sub">{esc(detail)}</p>' if detail else ""

        glance = "".join(
            f"<li><b>{esc(value)}</b> {esc(label)}</li>"
            for value, label in (
                (data.parsed, "entradas analisadas"),
                (data.skipped, "linhas ignoradas"),
                (len(stats.ips), "IPs distintos"),
            )
        )

        segments = "".join(
            f'<span class="seg sev-{label}" style="flex:{count}"></span>'
            for label, count in counts.items() if count
        )
        bar = (f'<div class="sevbar" role="img" aria-label="Distribuição dos achados por severidade">'
               f"{segments}</div>")
        legend = "".join(
            f'<li class="sev-{label}"><i></i>{esc(_SEVERITY_PT[label])} <b>{count}</b></li>'
            for label, count in counts.items()
        )

        if data.findings:
            findings_html = "".join(self._finding(f) for f in data.findings)
        else:
            findings_html = ('<p class="empty">Nenhum achado. '
                             "Nenhuma das regras foi disparada por estes logs.</p>")

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
<div class="brand">log-analyzer</div>
<h1>{title}</h1>
<p class="lead">{lead}</p>
{detail_html}
<p class="source">origem <b>{source}</b> · formato <b>{log_format}</b> · período <b>{period}</b></p>
<ul class="glance">{glance}</ul>
{bar}
<ul class="legend">{legend}</ul>
</header>
<h2><span class="hl">Achados ({total})</span></h2>
{findings_html}
<h2><span class="hl">Estatísticas</span></h2>
{self._stats(data)}
{self._hours(data)}
<footer>Gerado por log-analyzer em {generated} · todos os horários em UTC</footer>
</main>
</body>
</html>
"""

    def _finding(self, finding: Finding) -> str:
        label = finding.severity.label
        open_attr = " open" if finding.severity >= Severity.HIGH else ""

        chips: list[tuple[str, object]] = []
        if finding.ip:
            chips.append(("IP", finding.ip))
        if finding.user:
            chips.append(("Usuário", finding.user))
        chips.append(("Ocorrências", finding.count))
        if finding.first_seen:
            chips.append(
                ("Período", f"{fmt_dt(finding.first_seen)} → {fmt_dt(finding.last_seen)}")
            )
        chips_html = "".join(f"<li><span>{esc(k)}</span>{esc(v)}</li>" for k, v in chips)

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
                f'<span class="line"><span class="ln">{esc(Path(e.file).name)}:{e.line_number}</span>'
                f"{esc(e.raw)}</span>"
                for e in finding.evidence
            )
            evidence_html = (f"<h4>Evidências ({len(finding.evidence)})</h4>"
                             f'<pre class="evidence">{lines}</pre>')

        description = f'<p class="desc">{esc(finding.description)}</p>' if finding.description else ""
        return (
            f'<details class="finding sev-{label}"{open_attr}>'
            f'<summary><span class="badge sev-{label}">{esc(_SEVERITY_PT[label])}</span>'
            f'<span class="ftitle">{esc(finding.title)}</span>'
            f'<span class="rule">{esc(finding.rule)}</span></summary>'
            f'<div class="body">{description}<ul class="chips">{chips_html}</ul>'
            f"{details_html}{evidence_html}</div></details>"
        )

    def _stats(self, data: ReportData) -> str:
        stats = data.stats
        panels = [_panel("Visão geral", _table(
            ["Métrica", "Valor"],
            [("Total de entradas", stats.total), ("Entradas sem horário", stats.without_timestamp)],
        ))]
        for heading, counter in (
            ("Por nível", stats.by_level),
            ("Por evento", stats.by_event),
            ("Por processo", stats.by_process),
        ):
            if counter:
                panels.append(_panel(heading, _table(
                    ["Item", "Ocorrências"], counter.most_common(self.top_n))))
        if stats.by_status:
            panels.append(_panel("Status HTTP", _table(
                ["Status", "Respostas"], sorted(stats.by_status.items()))))

        top_ips = stats.top_ips(self.top_n)
        if top_ips:
            ip_rows = [(i.ip, i.count, fmt_dt(i.first_seen), fmt_dt(i.last_seen)) for i in top_ips]
            panels.append(_panel("Top IPs", _table(
                ["IP", "Ocorrências", "Primeira vez", "Última vez"], ip_rows), wide=True))
        if stats.users:
            panels.append(_panel("Top usuários", _table(
                ["Usuário", "Ocorrências"], stats.top_users(self.top_n))))
        if stats.paths:
            path_rows = [(path[:80], n) for path, n in stats.top_paths(self.top_n)]
            panels.append(_panel("Top caminhos", _table(
                ["Caminho", "Requisições"], path_rows), wide=True))
        return '<div class="grid">' + "".join(panels) + "</div>"

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
        return (f'<h2><span class="hl">Atividade por hora (UTC){esc(note)}</span></h2>'
                f'<div class="hours">{"".join(rows)}</div>')