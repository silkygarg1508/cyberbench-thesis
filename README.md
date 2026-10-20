# CyberBench Verifier Core

This repository contains the deterministic verification and evaluation components used in
the CyberBench study. It is designed for local inspection, testing and reproducible metric
calculation.

## Included

- Versioned data contracts for cases, evidence, checks, routes and traces.
- Dataset loading with a locked test split.
- Deterministic checks for evidence completeness, provenance, freshness, recorded execution,
  policy, claim values and evidence conflicts.
- Four-way routing: `Accept`, `Retry`, `Reject` and `Human Review`.
- Trace storage, metric calculation and report generation.
- Standalone tests that use synthetic example data.

## Excluded

The public package does not contain credentials, local paths, experimental artefacts,
private datasets or generated review files.

## Requirements

- Python 3.11 or later

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```

## Run the tests

```powershell
pytest
```

## Verify the included example

```powershell
cyberbench-verifier verify-case examples\sample_case.json
```

## Validate a local CyberBench directory

The dataset is not included. Set its local path before running:

```powershell
$env:CYBERBENCH_DATA_DIR = "C:\path\to\CyberBench_v1"
cyberbench-verifier validate-data --split development
```

The locked test split is unavailable through this public validation command.

## Evaluate saved traces

```powershell
cyberbench-verifier evaluate `
  path\to\traces.jsonl `
  path\to\labels.csv `
  --output-dir reports
```

## Repository structure

```text
src/cyberbench_verifier/
  cli.py          Command-line interface
  dataset.py      Dataset loading and evidence audit
  metrics.py      Routing and verifier metrics
  reporting.py    CSV and chart output
  schemas.py      Versioned data contracts
  tracing.py      Append-only trace storage
  verifier.py     Deterministic checks and routing
tests/            Standalone regression tests
examples/         Synthetic example case
```
