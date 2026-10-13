"""Detectores de atividade suspeita.

Cada detector recebe as entradas uma a uma (feed) e, no fim, devolve seus
achados (finalize). O DetectionEngine conecta tudo e normaliza os horários.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
from urllib.parse import unquote_plus

from log_analyzer.findings import Finding, Severity
from log_analyzer.models import LogEntry
from log_analyzer.timeutils import to_utc

MAX_LISTED = 10  # itens distintos guardados em details (caminhos, usuários...)
_FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


def _remember(details: dict[str, Any], key: str, value: Any, limit: int = MAX_LISTED) -> None:
    """Acrescenta um valor distinto a uma lista em details (ignora vazios)."""
    if value is None or value == "":
        return
    items = details.setdefault(key, [])
    if value not in items and len(items) < limit:
        items.append(value)


def _fmt(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "?"


@dataclass
class _Accumulator:
    """Acumula ocorrências sem janela de tempo (usado por detectores de total)."""

    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[LogEntry] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, entry: LogEntry, ts: datetime | None, max_evidence: int,
            note: str | None = None, amount: int = 1) -> None:
        self.count += amount
        if ts is not None:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts
        if len(self.evidence) < max_evidence:
            self.evidence.append(entry)
        if note and note not in self.notes and len(self.notes) < MAX_LISTED:
            self.notes.append(note)


class Detector(ABC):
    rule = ""

    def __init__(self, max_evidence: int = 10) -> None:
        self.max_evidence = max_evidence

    @abstractmethod
    def feed(self, entry: LogEntry, ts: datetime | None) -> None:
        """Processa uma entrada. ts é o horário em UTC (None se a entrada não tem)."""

    @abstractmethod
    def finalize(self) -> list[Finding]:
        """Devolve os achados. Pode ser chamado mais de uma vez."""

    def _add_evidence(self, finding: Finding, entry: LogEntry) -> None:
        if len(finding.evidence) < self.max_evidence:
            finding.evidence.append(entry)


# ---------------------------------------------------------------------------
# Rajadas em janela deslizante
# ---------------------------------------------------------------------------

@dataclass
class _BurstState:
    recent: deque[tuple[datetime, LogEntry]]
    last_ts: datetime | None = None
    finding: Finding | None = None


class BurstDetector(Detector):
    """Base dos detectores do tipo 'N eventos do mesmo IP em T segundos'.

    Uma rajada vira UM achado: enquanto os eventos continuam chegando dentro da
    janela, o mesmo achado é estendido (contagem, último horário, evidências).
    Passada uma pausa maior que a janela, a próxima rajada gera outro achado.
    """

    def __init__(self, threshold: int, window_seconds: int, high_count: int,
                 max_evidence: int = 10) -> None:
        super().__init__(max_evidence)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.window = timedelta(seconds=window_seconds)
        self.high_count = high_count
        self._states: dict[str, _BurstState] = {}
        self._closed: list[Finding] = []

    # --- ganchos que as subclasses implementam ---------------------------
    def group_key(self, entry: LogEntry) -> str | None:
        return entry.ip

    @abstractmethod
    def matches(self, entry: LogEntry) -> bool:
        """A entrada conta para a rajada?"""

    @abstractmethod
    def new_finding(self, key: str) -> Finding:
        """Cria o achado quando o limiar é atingido."""

    def track(self, finding: Finding, entry: LogEntry) -> None:
        """Atualiza details do achado com os dados da entrada."""

    def severity_for(self, finding: Finding) -> Severity:
        return Severity.HIGH if finding.count >= self.high_count else Severity.MEDIUM

    def describe(self, finding: Finding) -> str:
        return ""

    def on_other(self, entry: LogEntry, ts: datetime, key: str) -> None:
        """Chamado para entradas do mesmo IP que NÃO contam para a rajada."""

    # --- lógica comum -----------------------------------------------------
    def feed(self, entry: LogEntry, ts: datetime | None) -> None:
        if ts is None:
            return  # sem horário não há como medir janela
        key = self.group_key(entry)
        if key is None:
            return
        if not self.matches(entry):
            self.on_other(entry, ts, key)
            return

        state = self._states.get(key)
        if state is None:
            # maxlen=threshold limita a memória mesmo em ataques com milhões de linhas
            state = self._states[key] = _BurstState(recent=deque(maxlen=self.threshold))

            if (state.finding is not None and state.last_ts is not None
                and ts - state.last_ts > self.window):
                    self._closed.append(state.finding)  # a rajada anterior terminou
                    state.finding = None

        while state.recent and ts - state.recent[0][0] > self.window:
            state.recent.popleft()
        state.recent.append((ts, entry))
        state.last_ts = ts

        if state.finding is None:
            if len(state.recent) >= self.threshold:
                finding = self.new_finding(key)
                finding.count = len(state.recent)
                finding.first_seen = state.recent[0][0]
                finding.last_seen = ts
                for _, recent_entry in state.recent:
                    self._add_evidence(finding, recent_entry)
                    self.track(finding, recent_entry)
                finding.severity = self.severity_for(finding)
                state.finding = finding
        else:
            finding = state.finding
            finding.count += 1
            finding.last_seen = ts
            self._add_evidence(finding, entry)
            self.track(finding, entry)
            finding.severity = self.severity_for(finding)

    def finalize(self) -> list[Finding]:
        open_findings = [s.finding for s in self._states.values() if s.finding is not None]
        result = self._closed + open_findings
        for finding in result:
            finding.description = self.describe(finding)
        return result


class AuthBruteForceDetector(BurstDetector):
    rule = "auth_brute_force"

    def __init__(self, events: Iterable[str], success_events: Iterable[str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.events = frozenset(events)
        self.success_events = frozenset(success_events)

    def matches(self, entry: LogEntry) -> bool:
        return entry.event in self.events

    def new_finding(self, key: str) -> Finding:
        return Finding(
            rule=self.rule,
            severity=Severity.MEDIUM,
            title=f"Possível brute force de login a partir de {key}",
            ip=key,
        )

    def track(self, finding: Finding, entry: LogEntry) -> None:
        _remember(finding.details, "users", entry.user)

    def severity_for(self, finding: Finding) -> Severity:
        if "success_after_failures" in finding.details:
            return Severity.CRITICAL
        return super().severity_for(finding)

    def on_other(self, entry: LogEntry, ts: datetime, key: str) -> None:
        if entry.event not in self.success_events:
            return
        state = self._states.get(key)
        if (state is None or state.finding is None or state.last_ts is None
                or ts - state.last_ts > self.window):
            return
        finding = state.finding
        finding.details["success_after_failures"] = {"user": entry.user, "at": ts.isoformat()}
        finding.severity = Severity.CRITICAL
        finding.evidence.append(entry)  # a linha do login bem-sucedido sempre entra

    def describe(self, finding: Finding) -> str:
        text = (
            f"{finding.count} falhas de login de {finding.ip} "
            f"(limite: {self.threshold} em {self.window_seconds}s), "
            f"entre {_fmt(finding.first_seen)} e {_fmt(finding.last_seen)} UTC."
        )
        users = finding.details.get("users")
        if users:
            text += f" Usuários alvo: {', '.join(users)}."
        success = finding.details.get("success_after_failures")
        if success:
            text += (
                f" ATENÇÃO: houve login bem-sucedido (usuário {success['user']}) logo após "
                "as falhas: possível comprometimento da conta."
            )
        return text


class WebScannerDetector(BurstDetector):
    rule = "web_scanner"

    def __init__(self, status_codes: Iterable[int], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.status_codes = frozenset(status_codes)

    def matches(self, entry: LogEntry) -> bool:
        return entry.event == "http_request" and entry.extra.get("status") in self.status_codes

    def new_finding(self, key: str) -> Finding:
        return Finding(
            rule=self.rule,
            severity=Severity.MEDIUM,
            title=f"Possível varredura web a partir de {key}",
            ip=key,
        )

    def track(self, finding: Finding, entry: LogEntry) -> None:
        path = entry.extra.get("path")
        _remember(finding.details, "paths", str(path)[:120] if path else None)
        _remember(finding.details, "status_codes", entry.extra.get("status"))
        _remember(finding.details, "user_agents", entry.extra.get("user_agent"))

    def describe(self, finding: Finding) -> str:
        text = (
            f"{finding.count} respostas de erro para {finding.ip} "
            f"(limite: {self.threshold} em {self.window_seconds}s), "
            f"entre {_fmt(finding.first_seen)} e {_fmt(finding.last_seen)} UTC."
        )
        paths = finding.details.get("paths")
        if paths:
            text += f" Caminhos testados: {', '.join(paths)}."
        return text


class HttpAuthFailureDetector(BurstDetector):
    rule = "http_auth_failures"

    def __init__(self, status_codes: Iterable[int], login_paths: Iterable[str],
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.status_codes = frozenset(status_codes)
        self.login_paths = tuple(p.lower() for p in login_paths)

    def matches(self, entry: LogEntry) -> bool:
        if entry.event != "http_request" or entry.extra.get("status") not in self.status_codes:
            return False
        if not self.login_paths:
            return True  # sem filtro de caminho: qualquer 401 conta
        path = str(entry.extra.get("path") or "").split("?", 1)[0].lower()
        return path.startswith(self.login_paths)

    def new_finding(self, key: str) -> Finding:
        return Finding(
            rule=self.rule,
            severity=Severity.MEDIUM,
            title=f"Falhas repetidas de autenticação HTTP a partir de {key}",
            ip=key,
        )

    def track(self, finding: Finding, entry: LogEntry) -> None:
        path = str(entry.extra.get("path") or "").split("?", 1)[0]
        _remember(finding.details, "paths", path[:120] if path else None)
        _remember(finding.details, "users", entry.user)

    def describe(self, finding: Finding) -> str:
        text = (
            f"{finding.count} respostas de falha de autenticação para {finding.ip} "
            f"(limite: {self.threshold} em {self.window_seconds}s), "
            f"entre {_fmt(finding.first_seen)} e {_fmt(finding.last_seen)} UTC."
        )
        paths = finding.details.get("paths")
        if paths:
            text += f" Caminhos: {', '.join(paths)}."
        return text


# ---------------------------------------------------------------------------
# Detectores por total (sem janela)
# ---------------------------------------------------------------------------

class SuspiciousRequestDetector(Detector):
    """Requisições com caminhos de ataque ou user-agents de scanners conhecidos."""

    rule = "suspicious_request"

    def __init__(self, min_hits: int, high_count: int, path_patterns: Iterable[str],
                 user_agent_patterns: Iterable[str], max_evidence: int = 10) -> None:
        super().__init__(max_evidence)
        self.min_hits = min_hits
        self.high_count = high_count
        self._path_regexes = [re.compile(p, re.IGNORECASE) for p in path_patterns]
        self._agent_regexes = [re.compile(p, re.IGNORECASE) for p in user_agent_patterns]
        self._by_ip: dict[str, _Accumulator] = {}

    def _reason(self, entry: LogEntry) -> str | None:
        path = unquote_plus(str(entry.extra.get("path") or ""))
        for regex in self._path_regexes:
            found = regex.search(path)
            if found:
                return f"caminho: {found.group(0)[:60]}"
        agent = str(entry.extra.get("user_agent") or "")
        for regex in self._agent_regexes:
            found = regex.search(agent)
            if found:
                return f"user-agent: {found.group(0)[:60]}"
        return None

    def feed(self, entry: LogEntry, ts: datetime | None) -> None:
        if entry.event != "http_request" or not entry.ip:
            return
        reason = self._reason(entry)
        if reason is None:
            return
        self._by_ip.setdefault(entry.ip, _Accumulator()).add(
            entry, ts, self.max_evidence, note=reason
        )

    def finalize(self) -> list[Finding]:
        findings = []
        for ip, acc in self._by_ip.items():
            if acc.count < self.min_hits:
                continue
            severity = Severity.HIGH if acc.count >= self.high_count else Severity.MEDIUM
            findings.append(Finding(
                rule=self.rule,
                severity=severity,
                title=f"Requisições suspeitas a partir de {ip}",
                description=(
                    f"{acc.count} requisições suspeitas de {ip} "
                    f"(mínimo: {self.min_hits}). Motivos: {'; '.join(acc.notes)}."
                ),
                ip=ip,
                count=acc.count,
                first_seen=acc.first_seen,
                last_seen=acc.last_seen,
                evidence=list(acc.evidence),
                details={"reasons": list(acc.notes)},
            ))
        return findings


class SudoActivityDetector(Detector):
    """Senhas erradas no sudo e comandos sensíveis executados via sudo."""

    rule = "sudo"

    def __init__(self, min_failed_attempts: int, sensitive_commands: Iterable[str],
                 max_evidence: int = 10) -> None:
        super().__init__(max_evidence)
        self.min_failed_attempts = min_failed_attempts
        self._sensitive = [re.compile(p) for p in sensitive_commands]
        self._failures: dict[str, _Accumulator] = {}
        self._commands: dict[str, _Accumulator] = {}

    def feed(self, entry: LogEntry, ts: datetime | None) -> None:
        user = entry.user or "(desconhecido)"
        if entry.event == "sudo_auth_failure":
            attempts = entry.extra.get("attempts")
            amount = attempts if isinstance(attempts, int) else 1
            self._failures.setdefault(user, _Accumulator()).add(
                entry, ts, self.max_evidence, amount=amount
            )
        elif entry.event == "sudo_command":
            command = str(entry.extra.get("command") or "")
            if any(regex.search(command) for regex in self._sensitive):
                self._commands.setdefault(user, _Accumulator()).add(
                    entry, ts, self.max_evidence, note=command[:200]
                )

    def finalize(self) -> list[Finding]:
        findings = []
        for user, acc in self._failures.items():
            if acc.count < self.min_failed_attempts:
                continue
            findings.append(Finding(
                rule="sudo_failures",
                severity=Severity.MEDIUM,
                title=f"Senhas incorretas no sudo para o usuário {user}",
                description=(
                    f"{acc.count} tentativas de sudo com senha incorreta do usuário {user} "
                    f"(mínimo: {self.min_failed_attempts})."
                ),
                user=user,
                count=acc.count,
                first_seen=acc.first_seen,
                last_seen=acc.last_seen,
                evidence=list(acc.evidence),
            ))
        for user, acc in self._commands.items():
            findings.append(Finding(
                rule="sudo_sensitive_command",
                severity=Severity.MEDIUM,
                title=f"Comando sensível via sudo por {user}",
                description=(
                    f"{acc.count} comando(s) sensível(is) executado(s) via sudo por {user}: "
                    f"{'; '.join(acc.notes)}."
                ),
                user=user,
                count=acc.count,
                first_seen=acc.first_seen,
                last_seen=acc.last_seen,
                evidence=list(acc.evidence),
                details={"commands": list(acc.notes)},
            ))
        return findings


# ---------------------------------------------------------------------------
# Montagem a partir das regras + motor
# ---------------------------------------------------------------------------

def build_detectors(rules: dict[str, dict[str, Any]]) -> list[Detector]:
    """Cria os detectores habilitados a partir das regras (ver config.load_rules)."""
    max_evidence = rules["general"]["max_evidence"]
    detectors: list[Detector] = []

    cfg = rules["auth_brute_force"]
    if cfg["enabled"]:
        detectors.append(AuthBruteForceDetector(
            events=cfg["events"], success_events=cfg["success_events"],
            threshold=cfg["threshold"], window_seconds=cfg["window_seconds"],
            high_count=cfg["high_count"], max_evidence=max_evidence,
        ))

    cfg = rules["web_scanner"]
    if cfg["enabled"]:
        detectors.append(WebScannerDetector(
            status_codes=cfg["status_codes"],
            threshold=cfg["threshold"], window_seconds=cfg["window_seconds"],
            high_count=cfg["high_count"], max_evidence=max_evidence,
        ))

    cfg = rules["http_auth_failures"]
    if cfg["enabled"]:
        detectors.append(HttpAuthFailureDetector(
            status_codes=cfg["status_codes"], login_paths=cfg["login_paths"],
            threshold=cfg["threshold"], window_seconds=cfg["window_seconds"],
            high_count=cfg["high_count"], max_evidence=max_evidence,
        ))

    cfg = rules["suspicious_request"]
    if cfg["enabled"]:
        detectors.append(SuspiciousRequestDetector(
            min_hits=cfg["min_hits"], high_count=cfg["high_count"],
            path_patterns=cfg["path_patterns"],
            user_agent_patterns=cfg["user_agent_patterns"],
            max_evidence=max_evidence,
        ))

    cfg = rules["sudo"]
    if cfg["enabled"]:
        detectors.append(SudoActivityDetector(
            min_failed_attempts=cfg["min_failed_attempts"],
            sensitive_commands=cfg["sensitive_commands"],
            max_evidence=max_evidence,
        ))

    return detectors


def _sort_key(finding: Finding) -> tuple:
    return (
        -int(finding.severity),
        finding.first_seen or _FAR_FUTURE,
        finding.rule,
        finding.ip or "",
        finding.user or "",
    )


class DetectionEngine:
    """Alimenta os detectores e reúne os achados, do mais grave ao mais leve."""

    def __init__(self, detectors: list[Detector], assume_tz: tzinfo | None = None) -> None:
        self.detectors = detectors
        self._assume_tz = assume_tz

    def consume(self, entries: Iterable[LogEntry]) -> Iterator[LogEntry]:
        """Alimenta os detectores e repassa cada entrada (encadeável com o StatsCollector)."""
        for entry in entries:
            ts = to_utc(entry.timestamp, self._assume_tz) if entry.timestamp else None
            for detector in self.detectors:
                detector.feed(entry, ts)
            yield entry

    def findings(self) -> list[Finding]:
        result = [f for detector in self.detectors for f in detector.finalize()]
        result.sort(key=_sort_key)
        return result