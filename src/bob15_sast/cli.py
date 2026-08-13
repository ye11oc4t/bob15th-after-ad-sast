"""Command-line interface for the evidence-grounded SAST prototype."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from importlib.resources import as_file, files
from pathlib import Path
from typing import Annotated, Any

import typer

from .adapters import CodeQLAdapter, SemgrepAdapter, TrivyAdapter
from .ai import AIProviderUnavailable, MockTriageProvider, OpenAITriageProvider, TriageProvider
from .jsonio import write_json
from .pipeline import (
    DEFAULT_MAX_AI_GROUPS,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_GROUPS,
    load_findings,
    public_finding,
    run_pipeline,
)
from .redaction import redact, redact_text
from .sarif import SarifParseError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Evidence-grounded AI-assisted SAST for authorized local code.",
)

_CONSOLE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _console_text(value: object) -> str:
    return _CONSOLE_CONTROL.sub("", redact_text(str(value))).replace("\r", " ")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _asset(name: str) -> Any:
    return files("bob15_sast.data").joinpath(name)


def _provider(name: str, model: str | None) -> TriageProvider | None:
    normalized = name.casefold()
    if normalized == "none":
        return None
    if normalized == "mock":
        return MockTriageProvider()
    if normalized == "openai":
        return OpenAITriageProvider(model=model)
    raise typer.BadParameter("AI provider must be one of: none, mock, openai")


def _print_result(result_directory: Path, findings: int, groups: int, assessments: int) -> None:
    typer.echo(f"run directory: {_console_text(result_directory)}")
    typer.echo(f"findings: {findings}")
    typer.echo(f"root-cause groups: {groups}")
    typer.echo(f"AI hypotheses: {assessments}")
    typer.echo("human review: pending_review")


@app.command()
def doctor() -> None:
    """Check optional local scanner and AI configuration without exposing secrets."""

    version = sys.version_info
    typer.echo(f"python: {version.major}.{version.minor}.{version.micro}")
    for scanner in ("semgrep", "codeql", "trivy"):
        availability = "available" if shutil.which(scanner) else "not installed (optional)"
        typer.echo(f"{scanner}: {availability}")
    typer.echo(
        "openai: configured"
        if os.environ.get("OPENAI_API_KEY")
        else "openai: not configured (optional)"
    )
    typer.echo("default network behavior: no target access")


@app.command()
def ingest(
    sarif: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    service: Annotated[str, typer.Option("--service", "-s")] = "synthetic",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    repo_root: Annotated[Path | None, typer.Option("--repo-root")] = None,
) -> None:
    """Normalize a SARIF file and emit redacted JSON findings."""

    try:
        findings = load_findings([sarif], service=service, repo_root=repo_root)
    except (OSError, ValueError, SarifParseError) as error:
        typer.echo(f"ingest failed: {_console_text(error)}", err=True)
        raise typer.Exit(code=2) from error
    payload = redact([public_finding(item) for item in findings])
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        write_json(output, payload)
        typer.echo(f"wrote {len(findings)} findings to {_console_text(output)}")


@app.command()
def demo(
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("artifacts/demo"),
    ai: Annotated[str, typer.Option("--ai")] = "mock",
    model: Annotated[str | None, typer.Option("--model")] = None,
    max_ai_groups: Annotated[int, typer.Option("--max-ai-groups", min=0)] = (
        DEFAULT_MAX_AI_GROUPS
    ),
    max_findings: Annotated[int, typer.Option("--max-findings", min=0)] = (
        DEFAULT_MAX_FINDINGS
    ),
    max_groups: Annotated[int, typer.Option("--max-groups", min=0)] = DEFAULT_MAX_GROUPS,
) -> None:
    """Run the full pipeline using only the repository's synthetic SARIF fixture."""

    try:
        with as_file(_asset("sample.sarif")) as fixture:
            result = run_pipeline(
                [fixture],
                service="synthetic",
                output_root=output,
                provider=_provider(ai, model),
                max_ai_groups=max_ai_groups,
                max_findings=max_findings,
                max_groups=max_groups,
            )
    except (AIProviderUnavailable, OSError, ValueError, SarifParseError) as error:
        typer.echo(f"demo failed: {_console_text(error)}", err=True)
        raise typer.Exit(code=2) from error
    _print_result(
        result.run_directory,
        result.finding_count,
        result.group_count,
        result.assessment_count,
    )


@app.command()
def analyze(
    target: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)],
    scanner: Annotated[list[str] | None, typer.Option("--scanner")] = None,
    service: Annotated[str | None, typer.Option("--service", "-s")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    ai: Annotated[str, typer.Option("--ai")] = "none",
    model: Annotated[str | None, typer.Option("--model")] = None,
    codeql_language: Annotated[str | None, typer.Option("--codeql-language")] = None,
    semgrep_config: Annotated[Path | None, typer.Option("--semgrep-config")] = None,
    trivy_cache_dir: Annotated[
        Path | None,
        typer.Option(
            "--trivy-cache-dir",
            exists=True,
            file_okay=False,
            readable=True,
            writable=True,
        ),
    ] = None,
    include_source: Annotated[bool, typer.Option("--include-source")] = False,
    max_ai_groups: Annotated[int, typer.Option("--max-ai-groups", min=0)] = (
        DEFAULT_MAX_AI_GROUPS
    ),
    max_findings: Annotated[int, typer.Option("--max-findings", min=0)] = (
        DEFAULT_MAX_FINDINGS
    ),
    max_groups: Annotated[int, typer.Option("--max-groups", min=0)] = DEFAULT_MAX_GROUPS,
) -> None:
    """Run selected local scanners, then normalize and triage their SARIF output."""

    if os.name != "posix":
        typer.echo(
            "analysis failed: local scanner execution currently requires POSIX "
            "process-group termination; use ingest for externally generated SARIF",
            err=True,
        )
        raise typer.Exit(code=2)
    target = target.resolve()
    resolved_output = output.expanduser().resolve() if output is not None else None
    if resolved_output is not None and (
        resolved_output == target or resolved_output.is_relative_to(target)
    ):
        raise typer.BadParameter("--output must be outside the untrusted target tree")
    selected = tuple(dict.fromkeys(name.casefold() for name in (scanner or ["semgrep"])))
    unknown = sorted(set(selected) - {"semgrep", "codeql", "trivy"})
    if unknown:
        raise typer.BadParameter(f"unknown scanner(s): {', '.join(unknown)}")
    if "codeql" in selected and codeql_language is None:
        raise typer.BadParameter("--codeql-language is required with --scanner codeql")
    if "trivy" in selected:
        if trivy_cache_dir is None:
            raise typer.BadParameter(
                "--trivy-cache-dir is required with --scanner trivy; pre-populate "
                "the cache outside the target before an offline scan"
            )
        trivy_cache_dir = trivy_cache_dir.expanduser().resolve()
        if trivy_cache_dir == target or trivy_cache_dir.is_relative_to(target):
            raise typer.BadParameter(
                "--trivy-cache-dir must be outside the untrusted target tree"
            )
    if resolved_output is None:
        resolved_output = Path(tempfile.mkdtemp(prefix="bob15-sast-artifacts-"))

    try:
        provider = _provider(ai, model)
        if ai.casefold() == "openai" and include_source:
            typer.echo(
                "notice: redacted source excerpts will be sent to the configured "
                "OpenAI API provider",
                err=True,
            )
        with tempfile.TemporaryDirectory(prefix="bob15-sast-") as temporary_name:
            temporary = Path(temporary_name)
            sarif_paths: list[Path] = []
            for name in selected:
                result_path = temporary / f"{name}.sarif"
                if name == "semgrep":
                    if semgrep_config is None:
                        with as_file(_asset("python-command-injection.yml")) as config:
                            execution = SemgrepAdapter(configs=(config,)).scan(
                                target, result_path
                            )
                    else:
                        execution = SemgrepAdapter(configs=(semgrep_config,)).scan(
                            target, result_path
                        )
                elif name == "codeql":
                    execution = CodeQLAdapter(
                        language=codeql_language or "",
                        database_path=temporary / "codeql-db",
                    ).scan(target, result_path)
                else:
                    execution = TrivyAdapter(cache_dir=trivy_cache_dir).scan(
                        target, result_path
                    )

                if not execution.succeeded or not execution.output_path.is_file():
                    detail = _console_text(execution.result.stderr.strip()) or (
                        "scanner returned no SARIF"
                    )
                    raise RuntimeError(f"{name} failed: {detail[:500]}")
                sarif_paths.append(execution.output_path)

            pipeline_result = run_pipeline(
                sarif_paths,
                service=service or target.name,
                output_root=resolved_output,
                source_root=target,
                repo_root=target,
                provider=provider,
                include_source_evidence=include_source,
                max_ai_groups=max_ai_groups,
                max_findings=max_findings,
                max_groups=max_groups,
            )
    except (
        AIProviderUnavailable,
        FileNotFoundError,
        OSError,
        RuntimeError,
        SarifParseError,
        ValueError,
    ) as error:
        typer.echo(f"analysis failed: {_console_text(error)}", err=True)
        raise typer.Exit(code=2) from error

    _print_result(
        pipeline_result.run_directory,
        pipeline_result.finding_count,
        pipeline_result.group_count,
        pipeline_result.assessment_count,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
