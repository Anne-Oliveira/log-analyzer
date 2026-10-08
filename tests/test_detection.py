from pathlib import Path

import pytest

from log_analyzer.detection import detect_format, detect_format_from_path
from log_analyzer.readers import RawLine

SAMPLES = Path(__file__).parent / "samples"


@pytest.mark.parametrize("arquivo, esperado", [
    ("auth_sample.log", "syslog"),
    ("nginx_sample.log", "nginx"),
    ("app_sample.jsonl", "jsonl"),
])
def test_detecta_formato_dos_exemplos(arquivo, esperado):
    assert detect_format_from_path(SAMPLES / arquivo) == esperado


def test_texto_sem_formato_conhecido_levanta_erro():
    linhas = [RawLine("x.log", i, "lixo qualquer") for i in range(1, 6)]
    with pytest.raises(ValueError):
        detect_format(linhas)


def test_sem_linhas_levanta_erro():
    with pytest.raises(ValueError):
        detect_format([])