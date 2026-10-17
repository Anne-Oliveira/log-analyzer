# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/), com
versionamento semântico.

## [1.0.0] - 2026-10-12

### Adicionado
- Leitura em streaming de arquivo, pasta (recursivo), `.gz` e stdin.
- Ordenação cronológica de logs rotacionados (`auth.log.2.gz` → `auth.log`).
- Parsers de syslog/`auth.log`, access log Nginx/Apache, JSON lines e genérico por regex,
  com detecção automática de formato por arquivo.
- Normalização de horários para UTC (`--timezone`, `--year`).
- Estatísticas (por nível, evento, status, hora, IP, usuário e caminho).
- Detectores: brute force de login, varredura web, falhas de autenticação HTTP, requisições
  suspeitas e uso suspeito de `sudo`, com severidade e evidências.
- Regras configuráveis em YAML, com validação.
- Relatórios em console, JSON, CSV e HTML, protegidos contra conteúdo malicioso nos logs.
- CLI (`analyze`, `rules`) com códigos de saída para automação (`--fail-on`).
- Testes unitários e de integração, lint (ruff), tipos (mypy) e CI no GitHub Actions.