# log-analyzer

[![CI](https://github.com/Anne-Oliveira/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Anne-Oliveira/log-analyzer/actions/workflows/ci.yml)

Analisador de logs em Python focado em **detecção de atividade suspeita**: brute force de SSH
e de login, varreduras web, requisições de ataque e uso suspeito de `sudo`. Ele lê os logs,
normaliza tudo para um formato único, aplica regras configuráveis e gera relatórios com a
**evidência original** (arquivo e linha) de cada achado.

## Recursos

- **Entrada flexível:** arquivo, pasta (recursivo), `.gz` e stdin. A leitura é em streaming, então
  logs enormes não estouram a memória.
- **Logs rotacionados em ordem cronológica:** `auth.log.2.gz` → `auth.log.1` → `auth.log`.
- **Formatos:** syslog/`auth.log` (SSH, sudo), access log Nginx/Apache, JSON lines e qualquer
  formato via regex. O formato é detectado automaticamente, arquivo por arquivo.
- **Detectores com severidade** (low, medium, high, critical), regras editáveis em YAML.
- **Relatórios:** console (com cores), JSON, CSV e HTML (arquivo único, sem dependências externas).
- **Automação:** códigos de saída (`--fail-on`) e uso como biblioteca Python.

## Instalação

Requer Python 3.11 ou superior. A única dependência de execução é o PyYAML.

```bash
git clone git@github.com:Anne-Oliveira/log-analyzer.git
cd log-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
log-analyzer --version
```

## Uso rápido

```bash
# Relatório no terminal (o formato é detectado sozinho)
log-analyzer analyze /var/log/auth.log --year 2026

# Uma pasta inteira, com relatórios em HTML e JSON
log-analyzer analyze logs/ -r html,json -o reports

# Todos os formatos de relatório
log-analyzer analyze access.log -r all

# Falhar (código 1) se houver achado de severidade alta ou acima
log-analyzer analyze access.log --fail-on high -q

# Ler da entrada padrão (o formato é obrigatório)
sudo cat /var/log/auth.log | log-analyzer analyze - --format syslog

# Logs do systemd
journalctl -t sshd -t sudo --no-pager -o short-iso | log-analyzer analyze - --format syslog

# Formato próprio, via regex com grupos nomeados
log-analyzer analyze app.log -f generic \
  --pattern '(?P<ts>\S+ \S+) \[(?P<level>\w+)\] (?P<message>.*)' \
  --timestamp-format '%Y-%m-%d %H:%M:%S'
```

Os relatórios em arquivo vão para `reports/` (mude com `-o`) e o console vai para a tela.

## Opções do comando `analyze`

| Opção | Descrição |
|---|---|
| `CAMINHO` | Arquivo, pasta ou `-` (stdin) |
| `-f, --format` | `auto` (padrão), `syslog`, `nginx`, `jsonl` ou `generic` |
| `--pattern`, `--timestamp-format` | Regex e formato de data para `--format generic` |
| `--year` | Ano dos logs syslog clássicos (que não trazem ano). Padrão: ano atual |
| `--timezone` | Fuso dos horários sem fuso: `America/Sao_Paulo`, `UTC`. Para negativos use `--timezone=-03:00` |
| `--rules` | Arquivo YAML de regras |
| `-r, --report` | `console`, `json`, `csv`, `html` ou `all` (separe por vírgula ou repita a opção) |
| `-o, --output`, `--name` | Pasta (padrão `reports`) e nome-base dos arquivos de relatório |
| `--fail-on` | `never` (padrão), `low`, `medium`, `high` ou `critical` |
| `--top` | Tamanho dos rankings (padrão 10) |
| `--no-color`, `-q` | Desliga cores / esconde o resumo no stderr |

Outro comando: `log-analyzer rules` imprime as regras em uso, como modelo para o seu YAML.

## Códigos de saída

| Código | Significado |
|---|---|
| `0` | Análise concluída (e nenhum achado na severidade de `--fail-on`) |
| `1` | Há achados com severidade igual ou acima de `--fail-on` |
| `2` | Erro de uso: arquivo inexistente, formato não reconhecido, regras inválidas, nenhuma linha reconhecida |

## Detectores

| Regra | O que detecta | Padrão |
|---|---|---|
| `auth_brute_force` | Falhas de login repetidas (SSH ou eventos `login_failed` de apps). Login bem-sucedido logo depois eleva a **critical** (possível comprometimento) | 5 falhas em 300 s |
| `web_scanner` | Muitos erros 400/403/404 do mesmo IP | 5 em 60 s |
| `http_auth_failures` | Muitos 401 em caminhos de login | 10 em 300 s |
| `suspicious_request` | Caminhos de ataque (`../`, `/etc/passwd`, `.env`, `.git`, SQLi/XSS) e user-agents de scanners (nmap, sqlmap...) | 3 acertos |
| `sudo_failures`, `sudo_sensitive_command` | Senhas erradas no sudo e comandos sensíveis (shell, `useradd`, `chmod 777`, `curl \| sh`...) | 3 tentativas |

Severidade: **medium** ao atingir o limiar, **high** quando a contagem passa de `high_count` e
**critical** quando houve acesso bem-sucedido após as falhas.

## Configurando as regras

Todos os limites e padrões ficam em YAML. O que você não escrever usa o valor padrão, e erros
de digitação em seções ou opções são rejeitados com mensagem clara.

```bash
log-analyzer rules > minhas_regras.yaml        # ponto de partida
log-analyzer analyze auth.log --rules minhas_regras.yaml
```

```yaml
auth_brute_force:
  threshold: 3          # 3 falhas ...
  window_seconds: 120   # ... em 2 minutos
web_scanner:
  enabled: false        # desliga a regra
```

O arquivo `config/rules.yaml` do repositório documenta cada opção.

## Uso como biblioteca

```python
from log_analyzer.pipeline import analyze
from log_analyzer.reporters import get_reporter

dados = analyze("/var/log/auth.log", year=2026)
for achado in dados.findings:
    print(achado.severity.label, achado.rule, achado.ip, achado.count)

get_reporter("html").write(dados, "reports/auth.html")
```

## Como estender

**Novo formato de log.** Crie `src/log_analyzer/parsers/meu_formato.py`:

```python
from log_analyzer.models import LogEntry
from log_analyzer.parsers.base import BaseParser
from log_analyzer.readers import RawLine


class MeuParser(BaseParser):
    name = "meu_formato"

    def parse_line(self, line: RawLine) -> LogEntry | None:
        if not line.text.startswith("MEU|"):
            return None  # linha não reconhecida (conta como "ignorada")
        return LogEntry(file=line.source, line_number=line.number, raw=line.text,
                        message=line.text[4:])
```

Registre-o em `PARSERS` (`parsers/__init__.py`) e, para a detecção automática, em
`AUTO_DETECT_ORDER` (`detection.py`). Preencha `ip`, `user` e `event` quando o formato
fornecer: é com eles que os detectores trabalham.

**Nova regra.** Para "N eventos do mesmo IP em T segundos", herde de `BurstDetector` e implemente
`matches()` e `new_finding()`. Para contagens totais, herde de `Detector`. Depois adicione os
padrões em `DEFAULT_RULES` e `config/rules.yaml` (um teste garante que os dois fiquem iguais) e
conecte em `build_detectors()`.

**Novo relatório.** Herde de `Reporter`, defina `name`, `extension` e `render()`, e registre em
`REPORTERS`.

## Desenvolvimento

```bash
pip install -e ".[dev]"
python -m pytest        # testes
ruff check .            # lint
mypy                    # tipos
```

## Estrutura

```
src/log_analyzer/
├── cli.py            # linha de comando
├── pipeline.py       # analyze(): leitura -> parsers -> estatísticas + detectores
├── readers.py        # arquivo, pasta, .gz, stdin (streaming)
├── ordering.py       # ordem cronológica de logs rotacionados
├── detection.py      # detecção automática de formato
├── models.py         # LogEntry
├── findings.py       # Finding e Severity
├── config.py         # carga e validação das regras
├── timeutils.py      # normalização para UTC
├── parsers/          # syslog, nginx, jsonl, generic
├── analyzers/        # stats.py e detectors.py
└── reporters/        # console, json, csv, html
config/rules.yaml     # regras de detecção documentadas
tests/                # testes unitários e de integração
```

## Limitações conhecidas

- Os detectores assumem linhas em **ordem cronológica** dentro de cada arquivo. A CLI ordena
  logs rotacionados, mas arquivos sem esse padrão de nome são lidos em ordem alfabética.
- A detecção automática olha as primeiras 20 linhas de cada arquivo. Com stdin, informe `--format`.
- O syslog clássico não traz ano nem fuso: use `--year` e `--timezone` quando forem diferentes
  do ano atual e do fuso do sistema.
- A ferramenta é de análise passiva: ela não bloqueia IPs nem altera nada no sistema.

## Segurança e privacidade

- Linhas de log são tratadas como **entrada não confiável**: o HTML escapa todo o conteúdo e
  declara uma Content-Security-Policy, o CSV neutraliza fórmulas (`=`, `+`, `-`, `@`) e o console
  remove caracteres de controle.
- Logs contêm dados pessoais (IPs, usuários). **Não commite logs reais.** Os exemplos deste
  repositório usam as faixas reservadas para documentação (RFC 5737).

## Licença

MIT. Veja o arquivo [LICENSE](LICENSE).