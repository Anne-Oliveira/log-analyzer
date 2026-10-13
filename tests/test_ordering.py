from pathlib import Path

from log_analyzer.ordering import sort_rotated


def nomes(paths):
    return [Path(p).name for p in paths]


def test_rotacao_numerica_do_mais_antigo_para_o_atual():
    ordenados = sort_rotated(["auth.log", "auth.log.1", "auth.log.10", "auth.log.2.gz"])
    assert nomes(ordenados) == ["auth.log.10", "auth.log.2.gz", "auth.log.1", "auth.log"]


def test_rotacao_por_data():
    ordenados = sort_rotated(["access.log", "access.log-20261008", "access.log-20261007"])
    assert nomes(ordenados) == ["access.log-20261007", "access.log-20261008", "access.log"]


def test_arquivos_diferentes_ficam_agrupados():
    ordenados = sort_rotated(["b.log", "a.log.1", "a.log"])
    assert nomes(ordenados) == ["a.log.1", "a.log", "b.log"]