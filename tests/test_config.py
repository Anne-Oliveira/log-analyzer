from pathlib import Path

import pytest
import yaml

from log_analyzer.config import DEFAULT_RULES, load_rules

ROOT = Path(__file__).parent.parent


def escrever(tmp_path, dados) -> Path:
    arquivo = tmp_path / "rules.yaml"
    arquivo.write_text(yaml.safe_dump(dados), encoding="utf-8")
    return arquivo


def test_regras_padrao_sao_carregadas_e_independentes():
    regras = load_rules()
    assert regras == DEFAULT_RULES

    regras["web_scanner"]["threshold"] = 99  # não pode contaminar os padrões
    assert DEFAULT_RULES["web_scanner"]["threshold"] == 5


def test_rules_yaml_distribuido_equivale_aos_padroes():
    assert load_rules(ROOT / "config" / "rules.yaml") == DEFAULT_RULES


def test_yaml_parcial_sobrescreve_so_o_informado(tmp_path):
    arquivo = escrever(tmp_path, {
        "auth_brute_force": {"threshold": 3, "events": ["ssh_failed_login"]},
    })
    regras = load_rules(arquivo)

    assert regras["auth_brute_force"]["threshold"] == 3
    assert regras["auth_brute_force"]["events"] == ["ssh_failed_login"]  # lista substitui
    assert regras["auth_brute_force"]["window_seconds"] == 300          # padrão mantido
    assert regras["web_scanner"] == DEFAULT_RULES["web_scanner"]


def test_yaml_vazio_usa_padroes(tmp_path):
    arquivo = tmp_path / "rules.yaml"
    arquivo.write_text("", encoding="utf-8")
    assert load_rules(arquivo) == DEFAULT_RULES


def test_arquivo_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nao_existe.yaml")


def test_secao_desconhecida(tmp_path):
    with pytest.raises(ValueError, match="Seção desconhecida"):
        load_rules(escrever(tmp_path, {"brute_forse": {"threshold": 3}}))


def test_opcao_desconhecida(tmp_path):
    with pytest.raises(ValueError, match="Opção desconhecida"):
        load_rules(escrever(tmp_path, {"auth_brute_force": {"treshold": 3}}))


def test_regex_invalida(tmp_path):
    arquivo = escrever(tmp_path, {"suspicious_request": {"path_patterns": ["(abc"]}})
    with pytest.raises(ValueError, match="regex inválida"):
        load_rules(arquivo)


@pytest.mark.parametrize("valor", [0, -1, "5", True])
def test_numero_invalido(tmp_path, valor):
    arquivo = escrever(tmp_path, {"auth_brute_force": {"threshold": valor}})
    with pytest.raises(ValueError, match="inteiro positivo"):
        load_rules(arquivo)


def test_enabled_precisa_ser_booleano(tmp_path):
    arquivo = escrever(tmp_path, {"web_scanner": {"enabled": "sim"}})
    with pytest.raises(ValueError, match="true ou false"):
        load_rules(arquivo)