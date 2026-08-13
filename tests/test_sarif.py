from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from bob15_sast.models import Severity
from bob15_sast.sarif import (
    SarifParseError,
    extract_cwes,
    load_sarif,
    normalize_artifact_path,
    normalize_sarif,
)


def _physical(uri: str | None, line: int, *, index: int | None = None) -> dict:
    artifact: dict = {}
    if uri is not None:
        artifact["uri"] = uri
    if index is not None:
        artifact["index"] = index
    return {
        "physicalLocation": {
            "artifactLocation": artifact,
            "region": {
                "startLine": line,
                "startColumn": 3,
                "snippet": {"text": "dangerous(input);"},
            },
        }
    }


def _document_with_result(result: dict, **run_fields: object) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Synthetic Scanner", "rules": []}},
                "results": [result],
                **run_fields,
            }
        ],
    }


class SarifNormalizationTests(unittest.TestCase):
    def test_normalizes_semgrep_codeql_and_trivy(self) -> None:
        semgrep_rule = {
            "id": "java.lang.security.audit.command-injection",
            "name": "command-injection",
            "shortDescription": {"text": "CWE-78 command injection"},
            "properties": {"impact": "HIGH", "tags": ["security", "CWE-078"]},
        }
        codeql_rule = {
            "id": "java/command-line-injection",
            "name": "CommandLineInjection",
            "properties": {
                "security-severity": "9.8",
                "tags": ["external/cwe/cwe-078", "security"],
            },
        }
        trivy_rule = {
            "id": "synthetic-dependency-rule",
            "shortDescription": {"text": "Synthetic dependency issue (CWE-20)"},
            "properties": {"tags": ["vulnerability", "HIGH"]},
        }
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep OSS", "rules": [semgrep_rule]}},
                    "results": [
                        {
                            "ruleId": semgrep_rule["id"],
                            "level": "error",
                            "message": {"text": "User input reaches Runtime.exec"},
                            "locations": [_physical("src/main/java/Sample.java", 40)],
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": _physical(
                                                        "src/main/java/Sample.java", 12
                                                    ),
                                                    "executionOrder": 0,
                                                    "kinds": ["source"],
                                                },
                                                {
                                                    "location": _physical(
                                                        "src/main/java/Sample.java", 40
                                                    ),
                                                    "executionOrder": 1,
                                                    "kinds": ["sink"],
                                                },
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                },
                {
                    "tool": {"driver": {"name": "CodeQL", "rules": [codeql_rule]}},
                    "results": [
                        {
                            "ruleId": codeql_rule["id"],
                            "level": "warning",
                            "message": {"markdown": "A command is built from input"},
                            "locations": [_physical("src/main/java/Sample.java", 40)],
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": _physical(
                                                        "src/main/java/Sample.java", 8
                                                    )
                                                },
                                                {
                                                    "location": _physical(
                                                        "src/main/java/Sample.java", 40
                                                    )
                                                },
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                },
                {
                    "tool": {"driver": {"name": "Trivy", "rules": [trivy_rule]}},
                    "artifacts": [{"location": {"uri": "pom.xml"}}],
                    "results": [
                        {
                            "ruleId": trivy_rule["id"],
                            "message": {"text": "Vulnerable dependency"},
                            "locations": [_physical(None, 1, index=0)],
                        }
                    ],
                },
            ],
        }

        findings = normalize_sarif(document, "demo-service")

        self.assertEqual(len(findings), 3)
        semgrep, codeql, trivy = findings
        self.assertEqual(semgrep.tool, "Semgrep OSS")
        self.assertEqual(semgrep.severity, Severity.HIGH)
        self.assertEqual(semgrep.cwes, ["CWE-78"])
        self.assertEqual(semgrep.sink.path, "src/main/java/Sample.java")
        self.assertEqual(semgrep.sink.line, 40)
        self.assertEqual(len(semgrep.code_flows[0].steps), 2)

        self.assertEqual(codeql.severity, Severity.CRITICAL)
        self.assertEqual(codeql.cwes, ["CWE-78"])
        self.assertEqual(codeql.fingerprint, semgrep.fingerprint)

        self.assertEqual(trivy.tool, "Trivy")
        self.assertEqual(trivy.severity, Severity.HIGH)
        self.assertEqual(trivy.cwes, ["CWE-20"])
        self.assertEqual(trivy.sink.path, "pom.xml")

    def test_resolves_base_uri_and_removes_ephemeral_root(self) -> None:
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep", "rules": [{"id": "x"}]}},
                    "originalUriBaseIds": {
                        "%SRCROOT%": {"uri": "file:///tmp/build/demo-service/"}
                    },
                    "results": [
                        {
                            "ruleId": "x",
                            "message": {"text": "test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/App.java",
                                            "uriBaseId": "%SRCROOT%",
                                        },
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        finding = normalize_sarif(document, "demo-service")[0]
        self.assertEqual(finding.sink.path, "src/App.java")
        self.assertEqual(
            finding.sink.original_uri,
            "file:///tmp/build/demo-service/src/App.java",
        )

    def test_helpers_handle_scanner_variation(self) -> None:
        self.assertEqual(
            extract_cwes(
                ["external/cwe/cwe-079", "CWE 89"],
                {"taxonomy": "CWE_020"},
            ),
            ["CWE-20", "CWE-79", "CWE-89"],
        )
        self.assertEqual(
            normalize_artifact_path(
                "file:///workspace/random/demo-service/src/Foo.java",
                service="demo-service",
            ),
            "src/Foo.java",
        )
        self.assertEqual(
            normalize_artifact_path(
                r"C:\repo\demo-service\src\Foo.java",
                service="demo-service",
            ),
            "src/Foo.java",
        )

    def test_rejects_non_sarif_object(self) -> None:
        with self.assertRaises(SarifParseError):
            normalize_sarif({}, "edu")

    def test_cyclic_and_overdeep_base_ids_do_not_recurse(self) -> None:
        result = {
            "ruleId": "synthetic.rule",
            "locations": [_physical("src/sample.py", 4)],
        }
        cyclic = _document_with_result(
            result,
            originalUriBaseIds={
                "A": {"uri": "a/", "uriBaseId": "B"},
                "B": {"uri": "b/", "uriBaseId": "A"},
            },
        )
        cyclic["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uriBaseId"] = "A"
        finding = normalize_sarif(cyclic, "sample-service")[0]
        self.assertEqual(finding.sink.path, "src/sample.py")

        bases = {
            f"B{index}": {
                "uri": f"segment-{index}/",
                "uriBaseId": f"B{index + 1}",
            }
            for index in range(70)
        }
        bases["B69"] = {"uri": "last/"}
        overdeep = _document_with_result(result, originalUriBaseIds=bases)
        overdeep["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uriBaseId"] = "B0"
        finding = normalize_sarif(overdeep, "sample-service")[0]
        self.assertEqual(finding.sink.path, "src/sample.py")

    def test_parent_traversal_is_replaced_with_safe_marker(self) -> None:
        for uri in (
            "../../outside.txt",
            "%2e%2e/%2e%2e/outside.txt",
            "%252e%252e/%252e%252e/outside.txt",
        ):
            with self.subTest(uri=uri):
                path = normalize_artifact_path(uri, service="sample-service")
                self.assertEqual(path, "<unsafe-path>")
                self.assertNotIn("..", path)

        document = _document_with_result(
            {
                "ruleId": "synthetic.rule",
                "locations": [_physical("../outside.txt", 2)],
            },
            originalUriBaseIds={"ROOT": {"uri": "file:///tmp/project/"}},
        )
        artifact = document["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]
        artifact["uriBaseId"] = "ROOT"
        finding = normalize_sarif(document, "sample-service")[0]
        self.assertEqual(finding.sink.path, "<unsafe-path>")

    def test_malformed_coordinates_are_local_and_kinds_string_is_atomic(self) -> None:
        location = _physical("src/sample.py", 3)
        region = location["physicalLocation"]["region"]
        region.update(
            {
                "startLine": "not-a-line",
                "startColumn": {"unexpected": True},
                "endLine": -2,
                "endColumn": "9",
            }
        )
        result = {
            "ruleId": "synthetic.rule",
            "locations": [location],
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": location,
                                    "executionOrder": "4",
                                    "nestingLevel": "invalid",
                                    "kinds": "sink",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
        finding = normalize_sarif(_document_with_result(result), "sample-service")[0]
        parsed = finding.locations[0]
        self.assertEqual(parsed.line, 1)
        self.assertIsNone(parsed.column)
        self.assertIsNone(parsed.end_line)
        self.assertEqual(parsed.end_column, 9)
        step = finding.code_flows[0].steps[0]
        self.assertEqual(step.execution_order, 4)
        self.assertIsNone(step.nesting_level)
        self.assertEqual(step.kinds, ["sink"])

    def test_resource_limits_raise_clear_parse_errors(self) -> None:
        basic = {"ruleId": "synthetic.rule"}
        with (
            patch("bob15_sast.sarif.MAX_RESULTS", 1),
            self.assertRaisesRegex(SarifParseError, "results limit"),
        ):
            document = _document_with_result(basic)
            document["runs"][0]["results"].append(basic)
            normalize_sarif(document, "sample-service")

        with (
            patch("bob15_sast.sarif.MAX_CODE_FLOWS", 0),
            self.assertRaisesRegex(SarifParseError, "code flows limit"),
        ):
            result = {**basic, "codeFlows": [{"threadFlows": []}]}
            normalize_sarif(_document_with_result(result), "sample-service")

        with (
            patch("bob15_sast.sarif.MAX_TRACE_STEPS", 0),
            self.assertRaisesRegex(SarifParseError, "trace steps limit"),
        ):
            result = {
                **basic,
                "codeFlows": [
                    {"threadFlows": [{"locations": [{"location": {}}]}]}
                ],
            }
            normalize_sarif(_document_with_result(result), "sample-service")

        with (
            patch("bob15_sast.sarif.MAX_SARIF_BYTES", 8),
            self.assertRaisesRegex(SarifParseError, "input size limit"),
        ):
            load_sarif(io.StringIO('{"runs": []}'), service="sample-service")

    def test_non_finding_results_are_skipped_and_suppressions_are_preserved(self) -> None:
        skipped = {"ruleId": "synthetic.pass", "kind": "pass"}
        retained = {
            "ruleId": "synthetic.review",
            "kind": "review",
            "suppressions": [{"kind": "inSource"}],
        }
        document = _document_with_result(skipped)
        document["runs"][0]["results"].append(retained)

        findings = normalize_sarif(document, "sample-service")

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].properties["sarif_suppressions"],
            [{"kind": "inSource"}],
        )


if __name__ == "__main__":
    unittest.main()
