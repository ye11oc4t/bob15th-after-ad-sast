import json
import os
from pathlib import Path

import pytest

from bob15_sast.evidence import build_bundle, safe_source_path, source_excerpt, write_bundle


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


def test_bundle_allowlists_finding_fields(tmp_path: Path) -> None:
    bundle = build_bundle(
        tmp_path,
        {
            "id": "SYN-004",
            "service": "demo",
            "secret_blob": "must-not-survive",
            "properties": {"match": "must-not-survive"},
            "snippet": "must-not-survive",
            "location": {"path": "app.py", "line": 1, "snippet": "hidden"},
        },
    )
    finding = json.loads((bundle / "finding.json").read_text(encoding="utf-8"))
    rendered = json.dumps(finding)
    assert "must-not-survive" not in rendered
    assert "snippet" not in rendered
    assert "properties" not in rendered


def test_trace_rejects_unsafe_evidence_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="safe single-line"):
        write_bundle(
            tmp_path,
            {"id": "SYN-005"},
            [
                {
                    "id": "EV-X\n![remote](https://example.invalid/track)",
                    "kind": "source",
                    "content": "safe",
                }
            ],
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is POSIX-only")
def test_source_excerpt_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "source.fifo"
    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="not a regular file"):
        source_excerpt(tmp_path, fifo.name, 1)


@pytest.mark.skipif(os.name != "posix", reason="no-follow traversal is POSIX-only")
def test_source_excerpt_rejects_repository_symlinks(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "app.py").write_text("safe\n", encoding="utf-8")
    (tmp_path / "linked").symlink_to(actual, target_is_directory=True)

    with pytest.raises(OSError):
        source_excerpt(tmp_path, "linked/app.py", 1)


def test_bundle_tolerates_untrusted_non_list_shapes(tmp_path: Path) -> None:
    bundle = write_bundle(
        tmp_path,
        {
            "id": "SYN-006",
            "findings": {"not": "a-list"},
            "location": "not-an-object",
        },
        [],
    )
    finding = json.loads((bundle / "finding.json").read_text(encoding="utf-8"))
    assert finding["findings"] == []
    assert finding["location"] is None


def test_bundle_drops_nested_values_from_scalar_and_list_fields(tmp_path: Path) -> None:
    marker = "NESTED-VALUE-MUST-NOT-LEAK"
    bundle = write_bundle(
        tmp_path,
        {
            "id": "SYN-007",
            "service": {"value": marker},
            "severity": [marker],
            "tools": ["semgrep", {"value": marker}],
            "rule_ids": [{"value": marker}, "local.rule"],
            "cwes": [True, {"value": marker}, "CWE-78"],
            "location": {"path": {"value": marker}, "line": {"value": marker}},
            "requires_human_confirmation": {"value": marker},
            "findings": [
                {
                    "fingerprint": "sha256:" + "a" * 64,
                    "service": {"value": marker},
                    "tool": "semgrep",
                    "rule_id": {"value": marker},
                    "severity": "high",
                    "cwes": [{"value": marker}, "CWE-78"],
                    "suppressed": {"value": marker},
                    "baseline_state": {"value": marker},
                    "locations": [
                        {
                            "path": "src/app.py",
                            "line": {"value": marker},
                            "column": True,
                            "snippet": marker,
                        }
                    ],
                    "code_flows": [
                        {
                            "message": marker,
                            "steps": [
                                {
                                    "location": {"path": "src/app.py", "line": 7},
                                    "execution_order": {"value": marker},
                                    "kinds": ["source", {"value": marker}],
                                    "message": marker,
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        [],
    )

    finding = json.loads((bundle / "finding.json").read_text(encoding="utf-8"))
    rendered = json.dumps(finding)
    assert marker not in rendered
    assert finding["tools"] == ["semgrep"]
    assert finding["rule_ids"] == ["local.rule"]
    assert finding["cwes"] == ["CWE-78"]
    assert finding["location"] is None
    raw = finding["findings"][0]
    assert "service" not in raw
    assert "rule_id" not in raw
    assert "suppressed" not in raw
    assert "baseline_state" not in raw
    assert raw["locations"] == [{"path": "src/app.py"}]
    assert raw["code_flows"][0]["steps"][0] == {
        "location": {"path": "src/app.py", "line": 7},
        "kinds": ["source"],
    }


@pytest.mark.parametrize("field", ["kind", "location", "content"])
def test_bundle_rejects_nested_evidence_scalar_fields(
    tmp_path: Path, field: str
) -> None:
    evidence: dict[str, object] = {
        "id": "EV-008",
        "kind": "source",
        "location": "src/app.py:1",
        "content": "safe",
    }
    evidence[field] = {"secret": "NESTED-VALUE-MUST-NOT-LEAK"}
    output = tmp_path / field

    with pytest.raises(TypeError, match=rf"evidence {field} must be a string"):
        write_bundle(output, {"id": "SYN-008"}, [evidence])  # type: ignore[list-item]

    assert not output.exists()


@pytest.mark.parametrize(
    "finding",
    [
        {"id": {"nested": "value"}},
        {"id": "../escape"},
        {"id": "A" * 201},
        {"fingerprint": "sha256/escape"},
    ],
)
def test_bundle_rejects_unsafe_finding_identifiers(
    tmp_path: Path, finding: dict[str, object]
) -> None:
    with pytest.raises((TypeError, ValueError), match=r"finding (?:id|fingerprint)"):
        write_bundle(tmp_path / "output", finding, [])  # type: ignore[arg-type]

    assert not (tmp_path / "output").exists()


def test_bundle_bounds_public_strings_lists_and_evidence(tmp_path: Path) -> None:
    bundle = write_bundle(
        tmp_path,
        {
            "id": "SYN-009",
            "service": "s" * 2_001,
            "tools": [f"tool-{index}" for index in range(100)],
        },
        [
            {
                "id": "EV-009",
                "kind": "k" * 500,
                "location": "l" * 10_000,
                "content": "c" * 100_000,
            }
        ],
    )

    finding = json.loads((bundle / "finding.json").read_text(encoding="utf-8"))
    evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))[0]
    assert len(finding["service"]) == 500
    assert len(finding["tools"]) == 32
    assert len(evidence["kind"]) == 100
    assert len(evidence["location"]) == 2_000
    assert len(evidence["content"]) == 24_000
