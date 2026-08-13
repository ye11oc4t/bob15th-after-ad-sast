from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from bob15_sast.jsonio import write_json


def test_write_json_replaces_regular_file_atomically(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    output.write_text("old", encoding="utf-8")
    write_json(output, {"safe": True})
    assert json.loads(output.read_text(encoding="utf-8")) == {"safe": True}


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics are POSIX-specific")
def test_write_json_refuses_symlink_destination(tmp_path: Path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("preserve", encoding="utf-8")
    output = tmp_path / "result.json"
    output.symlink_to(victim)

    with pytest.raises(ValueError, match="symlink"):
        write_json(output, {"overwrite": True})

    assert victim.read_text(encoding="utf-8") == "preserve"
