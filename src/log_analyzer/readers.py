"""Leitura de logs: arquivo, pasta, .gz e stdin, sempre em streaming."""
from __future__ import annotations

import gzip
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import IO, NamedTuple

# Extensões que claramente não são log em texto (evita ler lixo em pastas)
SKIP_SUFFIXES = {".zip", ".bz2", ".xz", ".tar", ".png", ".jpg", ".pdf"}


class RawLine(NamedTuple):
    """Uma linha crua e de onde ela veio."""

    source: str
    number: int
    text: str


def _open_text(path: Path) -> IO[str]:
    # errors="replace": um byte inválido não pode derrubar a análise inteira
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_files(target: str | Path, recursive: bool = True) -> Iterator[Path]:
    """Resolve um arquivo ou pasta na lista de arquivos a ler (ordem estável)."""
    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(f"Caminho não encontrado: {path}")

    if path.is_file():
        yield path
        return

    pattern = "**/*" if recursive else "*"
    for candidate in sorted(path.glob(pattern)):
        if candidate.is_file() and candidate.suffix not in SKIP_SUFFIXES:
            yield candidate


def read_lines(target: str | Path) -> Iterator[RawLine]:
    """Gera as linhas não vazias de um arquivo, pasta ou stdin ('-')."""
    if str(target) == "-":
        for number, line in enumerate(sys.stdin, start=1):
            text = line.rstrip("\r\n")
            if text.strip():
                yield RawLine("<stdin>", number, text)
        return

    for path in iter_files(target):
        try:
            with _open_text(path) as handle:
                for number, line in enumerate(handle, start=1):
                    text = line.rstrip("\r\n")
                    if text.strip():
                        yield RawLine(str(path), number, text)
        except PermissionError:
            # Ex.: /var/log/auth.log exige sudo ou o grupo "adm"
            print(f"[aviso] sem permissão para ler {path} (tente sudo)", file=sys.stderr)
        except (OSError, EOFError) as exc:
            print(f"[aviso] não foi possível ler {path}: {exc}", file=sys.stderr)