import gzip

import pytest

from log_analyzer.models import LogEntry
from log_analyzer.readers import read_lines


def test_le_arquivo_simples_e_ignora_linhas_vazias(tmp_path):
    arquivo = tmp_path / "app.log"
    arquivo.write_text("primeira\n\nsegunda\n", encoding="utf-8")

    linhas = list(read_lines(arquivo))

    assert [l.text for l in linhas] == ["primeira", "segunda"]
    assert [l.number for l in linhas] == [1, 3]  # numeração real do arquivo


def test_le_arquivo_gz(tmp_path):
    arquivo = tmp_path / "auth.log.2.gz"
    with gzip.open(arquivo, "wt", encoding="utf-8") as f:
        f.write("linha comprimida\n")

    assert [l.text for l in read_lines(arquivo)] == ["linha comprimida"]


def test_le_pasta_recursivamente(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.log").write_text("a\n", encoding="utf-8")
    (tmp_path / "sub" / "b.log").write_text("b\n", encoding="utf-8")

    assert sorted(l.text for l in read_lines(tmp_path)) == ["a", "b"]


def test_arquivo_inexistente_levanta_erro(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(read_lines(tmp_path / "nao_existe.log"))


def test_bytes_invalidos_nao_derrubam_a_leitura(tmp_path):
    arquivo = tmp_path / "sujo.log"
    arquivo.write_bytes(b"ok\n\xff\xfe quebrado\n")

    assert len(list(read_lines(arquivo))) == 2


def test_log_entry_to_dict():
    entry = LogEntry(file="x.log", line_number=1, raw="linha")
    dados = entry.to_dict()

    assert dados["timestamp"] is None
    assert dados["raw"] == "linha"