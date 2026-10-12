"""Carregamento e validação das regras de detecção."""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml

# Estes valores valem quando nenhum arquivo é informado, e o config/rules.yaml
# distribuído com o projeto é uma cópia comentada deles (há um teste garantindo isso).
DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "general": {
        "max_evidence": 10,
    },
    "auth_brute_force": {
        "enabled": True,
        "threshold": 5,
        "window_seconds": 300,
        "high_count": 20,
        "events": ["ssh_failed_login", "login_failed"],
        "success_events": ["ssh_accepted_login"],
    },
    "web_scanner": {
        "enabled": True,
        "threshold": 5,
        "window_seconds": 60,
        "high_count": 30,
        "status_codes": [400, 403, 404],
    },
    "http_auth_failures": {
        "enabled": True,
        "threshold": 10,
        "window_seconds": 300,
        "high_count": 50,
        "status_codes": [401],
        "login_paths": ["/login", "/signin", "/auth", "/admin", "/wp-login.php", "/xmlrpc.php"],
    },
    "suspicious_request": {
        "enabled": True,
        "min_hits": 3,
        "high_count": 10,
        "path_patterns": [
            r"\.\./",
            r"/etc/(passwd|shadow)",
            r"/\.env\b",
            r"/\.git(/|$)",
            r"wp-login\.php|wp-admin|xmlrpc\.php",
            r"phpmyadmin",
            r"union\s+select|<script|sleep\(\d+\)|or\s+1=1",
            r"cgi-bin|vendor/phpunit|/actuator|/\.aws|/\.ssh",
        ],
        "user_agent_patterns": [
            "nmap", "sqlmap", "nikto", "masscan", "wpscan", "dirbuster", "gobuster",
            "nuclei", "zgrab",
        ],
    },
    "sudo": {
        "enabled": True,
        "min_failed_attempts": 3,
        "sensitive_commands": [
            r"(^|/)(ba|z|da)?sh(\s|$)",
            r"chmod\s+(-\w+\s+)*[0-7]*777|chmod\s+\S*\+s",
            r"\b(useradd|adduser|usermod|userdel|passwd)\b",
            r"/etc/(sudoers|shadow|passwd)|visudo",
            r"(curl|wget)\s.*\|\s*(ba)?sh",
            r"\b(nc|ncat|netcat)\s",
        ],
    },
}

_INT_KEYS = frozenset(
    {"threshold", "window_seconds", "high_count", "min_hits", "min_failed_attempts", "max_evidence"}
)
_INT_LIST_KEYS = frozenset({"status_codes"})
_STR_LIST_KEYS = frozenset(
    {"events", "success_events", "login_paths", "path_patterns",
     "user_agent_patterns", "sensitive_commands"}
)
_REGEX_LIST_KEYS = frozenset({"path_patterns", "user_agent_patterns", "sensitive_commands"})


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def load_rules(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Devolve as regras: padrões + o que o arquivo YAML sobrescrever."""
    rules = copy.deepcopy(DEFAULT_RULES)
    if path is not None:
        _merge(rules, _read_yaml(Path(path)))
    validate_rules(rules)
    return rules


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo de regras não encontrado: {path}")
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("O arquivo de regras deve ser um mapa de seções (regra: opções).")
    return data


def _merge(rules: dict[str, dict[str, Any]], user: dict[str, Any]) -> None:
    for section, options in user.items():
        if section not in rules:
            raise ValueError(
                f"Seção desconhecida nas regras: '{section}'. Válidas: {', '.join(rules)}"
            )
        if options is None:
            continue
        if not isinstance(options, dict):
            raise ValueError(f"A seção '{section}' deve ser um mapa de opções.")
        for key in options:
            if key not in rules[section]:
                raise ValueError(
                    f"Opção desconhecida em '{section}': '{key}'. "
                    f"Válidas: {', '.join(rules[section])}"
                )
        rules[section].update(options)


def validate_rules(rules: dict[str, dict[str, Any]]) -> None:
    for section, options in rules.items():
        for key, value in options.items():
            where = f"{section}.{key}"
            if key == "enabled":
                if not isinstance(value, bool):
                    raise ValueError(f"{where} deve ser true ou false.")
            elif key in _INT_KEYS:
                if not _is_int(value) or value <= 0:
                    raise ValueError(f"{where} deve ser um número inteiro positivo.")
            elif key in _INT_LIST_KEYS:
                if not isinstance(value, list) or not all(_is_int(v) for v in value):
                    raise ValueError(f"{where} deve ser uma lista de números inteiros.")
            elif key in _STR_LIST_KEYS:
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise ValueError(f"{where} deve ser uma lista de textos.")
                if key in _REGEX_LIST_KEYS:
                    for pattern in value:
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            raise ValueError(f"{where}: regex inválida '{pattern}': {exc}") from exc