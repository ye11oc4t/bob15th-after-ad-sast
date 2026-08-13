from pathlib import Path

import pytest

from bob15_sast.evidence import build_bundle, safe_source_path, write_bundle


def test_safe_source_path_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe repository path"):
        safe_source_path(tmp_path, "../secret.txt")


def test_bundle_contains_redacted_excerpt(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(
        "safe = True\napi_key = 'should-not-leak'\nrun(user_input)\n", encoding="utf-8"
    )
    output = build_bundle(
        tmp_path / "bundles",
        {
            "id": "SYN-001",
            "secret": "hidden",
            "location": {"path": "app.py", "start_line": 3},
        },
        source_root=source,
    )
    assert (output / "finding.json").is_file()
    trace = (output / "trace.md").read_text(encoding="utf-8")
    assert "should-not-leak" not in trace
    assert "<REDACTED>" in trace


def test_trace_uses_a_fence_longer_than_untrusted_content(tmp_path: Path) -> None:
    bundle = write_bundle(
        tmp_path,
        {"id": "SYN-002"},
        [
            {
                "id": "EV-002",
                "kind": "source",
                "location": "app.py:1",
                "content": "```\n![remote](https://example.invalid/track)",
            }
        ],
    )
    trace = (bundle / "trace.md").read_text(encoding="utf-8")
    assert "````text" in trace


def test_trace_location_cannot_break_inline_code(tmp_path: Path) -> None:
    bundle = write_bundle(
        tmp_path,
        {"id": "SYN-003"},
        [
            {
                "id": "EV-003",
                "kind": "source",
                "location": "app.py:1\n![remote](https://example.invalid/track)",
                "content": "safe",
            }
        ],
    )
    trace = (bundle / "trace.md").read_text(encoding="utf-8")
    assert "\n![remote]" not in trace
