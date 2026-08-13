from __future__ import annotations

import unittest

from bob15_sast.grouping import are_duplicates, cross_tool_groups, group_findings
from bob15_sast.models import Finding, Location, Severity


def _finding(
    *,
    tool: str,
    rule: str,
    cwes: list[str],
    path: str = "src/Sample.java",
    line: int = 40,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        service="demo-service",
        tool=tool,
        rule_id=rule,
        message=f"reported by {tool}",
        severity=severity,
        cwes=cwes,
        locations=[Location(path=path, line=line)],
    )


class FindingGroupingTests(unittest.TestCase):
    def test_groups_exact_cross_tool_duplicates(self) -> None:
        semgrep = _finding(tool="Semgrep", rule="command-injection", cwes=["CWE-78"])
        codeql = _finding(
            tool="CodeQL",
            rule="java/command-line-injection",
            cwes=["CWE-078"],
            severity=Severity.CRITICAL,
        )
        trivy = _finding(
            tool="Trivy",
            rule="synthetic-dependency-rule",
            cwes=["CWE-20"],
            path="pom.xml",
            line=1,
        )

        groups = group_findings([trivy, codeql, semgrep])

        self.assertEqual(len(groups), 2)
        command_group = next(
            group for group in groups if group.sink.path.endswith("Sample.java")
        )
        self.assertEqual(command_group.count, 2)
        self.assertEqual(command_group.tools, ["CodeQL", "Semgrep"])
        self.assertEqual(
            command_group.rule_ids,
            ["command-injection", "java/command-line-injection"],
        )
        self.assertEqual(command_group.severity, Severity.CRITICAL)
        self.assertTrue(command_group.is_cross_tool)
        self.assertEqual(cross_tool_groups([trivy, codeql, semgrep]), [command_group])

    def test_overlapping_cwe_sets_group_at_same_sink(self) -> None:
        broad = _finding(tool="Semgrep", rule="shell", cwes=["CWE-78", "CWE-88"])
        narrow = _finding(tool="CodeQL", rule="cmd", cwes=["CWE-78"])

        self.assertNotEqual(broad.fingerprint, narrow.fingerprint)
        self.assertTrue(are_duplicates(broad, narrow))
        grouped = group_findings([broad, narrow])
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].cwes, ["CWE-78", "CWE-88"])

    def test_does_not_merge_different_cwe_or_line(self) -> None:
        command = _finding(tool="Semgrep", rule="cmd", cwes=["CWE-78"])
        xss = _finding(tool="Semgrep", rule="xss", cwes=["CWE-79"])
        other_line = _finding(tool="CodeQL", rule="cmd", cwes=["CWE-78"], line=41)

        self.assertFalse(are_duplicates(command, xss))
        self.assertFalse(are_duplicates(command, other_line))
        self.assertEqual(len(group_findings([command, xss, other_line])), 3)

    def test_grouping_is_order_independent(self) -> None:
        first = _finding(tool="Semgrep", rule="cmd", cwes=["CWE-78"])
        second = _finding(tool="CodeQL", rule="cmd2", cwes=["CWE-78"])
        forward = group_findings([first, second])
        reverse = group_findings([second, first])
        self.assertEqual(
            [group.model_dump() for group in forward],
            [group.model_dump() for group in reverse],
        )

    def test_does_not_merge_distinct_same_tool_rules(self) -> None:
        first = _finding(tool="Trivy", rule="SYN-0001", cwes=["CWE-20"])
        second = _finding(tool="Trivy", rule="SYN-0002", cwes=["CWE-20"])
        groups = group_findings([first, second])
        self.assertEqual(len(groups), 2)
        self.assertEqual(len({group.fingerprint for group in groups}), 2)

    def test_does_not_merge_through_transitive_cwe_bridge(self) -> None:
        command = _finding(tool="A", rule="command", cwes=["CWE-78"])
        bridge = _finding(tool="B", rule="bridge", cwes=["CWE-78", "CWE-79"])
        xss = _finding(tool="C", rule="xss", cwes=["CWE-79"])
        groups = group_findings([command, bridge, xss])
        self.assertEqual(len(groups), 2)
        self.assertEqual(sorted(group.count for group in groups), [1, 2])

    def test_does_not_merge_findings_without_locations(self) -> None:
        first = Finding(
            service="demo-service",
            tool="A",
            rule_id="one",
            message="first",
        )
        second = Finding(
            service="demo-service",
            tool="B",
            rule_id="two",
            message="second",
        )
        groups = group_findings([first, second])
        self.assertEqual(len(groups), 2)
        self.assertNotEqual(groups[0].fingerprint, groups[1].fingerprint)

    def test_identical_locationless_duplicates_have_one_unique_group(self) -> None:
        first = Finding(
            service="demo-service",
            tool="A",
            rule_id="one",
            message="same",
        )
        second = first.model_copy(deep=True)
        groups = group_findings([first, second])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].count, 2)
        self.assertEqual(len({group.fingerprint for group in groups}), len(groups))

    def test_conflicting_cross_tool_groups_have_unique_fingerprints(self) -> None:
        findings = [
            _finding(tool="X", rule="r1", cwes=["CWE-20"]),
            _finding(tool="Y", rule="r1", cwes=["CWE-20"]),
            _finding(tool="X", rule="r2", cwes=["CWE-20"]),
            _finding(tool="Y", rule="r2", cwes=["CWE-20"]),
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)
        self.assertEqual(len({group.fingerprint for group in groups}), len(groups))

    def test_group_signature_delimiters_cannot_collide(self) -> None:
        findings = [
            _finding(tool="X", rule="a", cwes=["CWE-20"]),
            _finding(tool="Y", rule="b,y:c", cwes=["CWE-20"]),
            _finding(tool="X", rule="a,y:b", cwes=["CWE-20"]),
            _finding(tool="Y", rule="c", cwes=["CWE-20"]),
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)
        self.assertEqual(len({group.fingerprint for group in groups}), 2)

    def test_locationless_nul_delimiters_cannot_merge(self) -> None:
        findings = [
            Finding(
                service="demo",
                tool="a",
                rule_id="b\0c",
                message="same",
            ),
            Finding(
                service="demo",
                tool="a\0b",
                rule_id="c",
                message="same",
            ),
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)
        self.assertEqual(len({group.fingerprint for group in groups}), 2)

    def test_external_paths_are_not_treated_as_one_concrete_sink(self) -> None:
        findings = [
            _finding(tool="Semgrep", rule="one", cwes=["CWE-78"], path="<external-path>"),
            _finding(tool="CodeQL", rule="two", cwes=["CWE-78"], path="<external-path>"),
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)
        self.assertEqual(len({group.fingerprint for group in groups}), 2)

    def test_long_identity_material_remains_distinct(self) -> None:
        prefix = "x" * 3_000
        first = Finding(
            service="demo",
            tool="scanner",
            rule_id="rule",
            message=prefix + "-one",
        )
        second = first.model_copy(update={"message": prefix + "-two"})
        groups = group_findings([first, second])
        self.assertEqual(len(groups), 2)
        self.assertEqual(len({group.fingerprint for group in groups}), 2)


if __name__ == "__main__":
    unittest.main()
