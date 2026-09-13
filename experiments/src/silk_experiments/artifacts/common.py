from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_new(source: Path, target: Path, *, immutable: bool = False) -> None:
    if target.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {target}")
    if immutable:
        try:
            os.link(source, target)
            return
        except FileExistsError:
            raise
        except OSError:
            pass  # Cross-volume or filesystem without hard links.
    shutil.copy2(source, target)


def write_text_new(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as handle:
        handle.write(value)


def write_json_new(path: Path, value: object) -> None:
    write_text_new(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
