"""Ordenação cronológica de arquivos de log rotacionados."""
from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

# Reconhece: auth.log, auth.log.1, auth.log.2.gz (numerado) e access.log-20261008 (por data)
_ROTATION = re.compile(r"^(?P<base>.+?)(?:[.-](?P<num>\d+))?(?:\.gz)?$")
_DATE_OFFSET = 10**10  # datas (8 dígitos) sempre antes dos números de rotação


def rotation_key(path: str | Path) -> tuple[str, str, int]:
    """Chave de ordenação: agrupa por pasta e nome-base, do mais antigo ao mais novo.

    Rotação numerada: quanto MAIOR o número, mais antigo o arquivo (auth.log.2 < auth.log.1).
    Rotação por data: quanto MAIOR a data, mais novo. O arquivo sem sufixo é o atual (último).
    """
    p = Path(path)
    match = _ROTATION.match(p.name)
    if match is None:  # não ocorre com nomes reais de arquivo, mas satisfaz o type checker
        return (str(p.parent), p.name, 0)
    base, num = match["base"], match["num"]
    if num is None:
        rank = 0
    elif len(num) == 8:
        rank = int(num) - _DATE_OFFSET
    else:
        rank = -int(num)
    return (str(p.parent), base, rank)


def sort_rotated(paths: Iterable[str | Path]) -> list[Path]:
    return sorted((Path(p) for p in paths), key=rotation_key)