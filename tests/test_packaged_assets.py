from importlib.resources import files
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_packaged_assets_match_canonical_public_fixtures() -> None:
    data = files("bob15_sast.data")
    assert data.joinpath("sample.sarif").read_bytes() == (
        ROOT / "fixtures" / "sarif" / "sample.sarif"
    ).read_bytes()
    assert data.joinpath("python-command-injection.yml").read_bytes() == (
        ROOT / "rules" / "semgrep" / "python-command-injection.yml"
    ).read_bytes()
