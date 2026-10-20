from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from .dataset import audit_evidence, load_cases, load_gold_labels
from .metrics import evaluate_traces
from .reporting import write_report_artifacts
from .schemas import CyberBenchCase
from .tracing import JsonlTraceStore
from .verifier import extract_claims, route_from_checks, run_deterministic_checks


app = typer.Typer(no_args_is_help=True)


@app.command("validate-data")
def validate_data(
    data_dir: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    split: Annotated[str, typer.Option()] = "development",
) -> None:
    """Validate one non-test split and print its evidence audit."""
    if split == "test":
        raise typer.BadParameter("The locked test split is not available here.")
    cases = load_cases(data_dir, split)
    typer.echo(json.dumps(audit_evidence(cases), indent=2, sort_keys=True))


@app.command("verify-case")
def verify_case(
    case_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Run deterministic checks for one case file."""
    case = CyberBenchCase.model_validate_json(case_file.read_text(encoding="utf-8"))
    claims = extract_claims(case)
    checks = run_deterministic_checks(case, claims)
    decision = route_from_checks(checks)
    result = {
        "scenario_id": case.scenario_id,
        "claims": [claim.model_dump(mode="json") for claim in claims],
        "checks": [check.model_dump(mode="json") for check in checks],
        "decision": decision.model_dump(mode="json"),
    }
    typer.echo(json.dumps(result, indent=2, sort_keys=True))


@app.command("evaluate")
def evaluate(
    trace_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    label_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output_dir: Annotated[Path, typer.Option()] = Path("reports"),
) -> None:
    """Evaluate saved traces against a local label file."""
    traces = JsonlTraceStore(trace_file).read_all()
    labels = load_gold_labels(label_file=label_file)
    metrics = evaluate_traces(traces, labels)
    write_report_artifacts(metrics, output_dir)
    typer.echo(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    app()
