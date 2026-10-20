from __future__ import annotations

import csv
import json
import os
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from dotenv import load_dotenv

from .schemas import CyberBenchCase, GoldLabel


DEFAULT_DATA_DIR = Path("data") / "CyberBench"
LOCKED_SPLIT = "test"


def resolve_data_dir(value: str | Path | None = None) -> Path:
    load_dotenv()
    path = Path(value or os.getenv("CYBERBENCH_DATA_DIR", DEFAULT_DATA_DIR))
    if not path.exists():
        raise FileNotFoundError(
            f"CyberBench directory does not exist: {path}. "
            "Set CYBERBENCH_DATA_DIR or pass --data-dir."
        )
    return path


def input_file(data_dir: Path, split: str) -> Path:
    if split not in {"development", "validation", "test"}:
        raise ValueError(f"Unsupported split: {split}")
    return data_dir / f"CyberBench_v1_inputs_{split}.jsonl"


def iter_cases(
    data_dir: str | Path | None = None,
    split: str = "development",
    *,
    allow_locked_test: bool = False,
) -> Iterator[CyberBenchCase]:
    if split == LOCKED_SPLIT and not allow_locked_test:
        raise PermissionError(
            "The test split is locked. Use development/validation while building, "
            "or explicitly pass allow_locked_test=True for the final frozen run."
        )
    path = input_file(resolve_data_dir(data_dir), split)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield CyberBenchCase.model_validate_json(line)
            except Exception as exc:
                raise ValueError(f"Invalid CyberBench record at {path}:{line_number}") from exc


def load_cases(
    data_dir: str | Path | None = None,
    split: str = "development",
    *,
    limit: int | None = None,
    scenario_ids: set[str] | None = None,
    allow_locked_test: bool = False,
) -> list[CyberBenchCase]:
    selected: list[CyberBenchCase] = []
    for case in iter_cases(
        data_dir,
        split,
        allow_locked_test=allow_locked_test,
    ):
        if scenario_ids and case.scenario_id not in scenario_ids:
            continue
        selected.append(case)
        if limit is not None and len(selected) >= limit:
            break
    return selected


def load_gold_labels(
    data_dir: str | Path | None = None,
    label_file: str | Path | None = None,
) -> dict[str, GoldLabel]:
    path = (
        Path(label_file)
        if label_file is not None
        else resolve_data_dir(data_dir) / "CyberBench_v1_gold.csv"
    )
    with path.open(encoding="utf-8-sig", newline="") as handle:
        labels = [GoldLabel.model_validate(row) for row in csv.DictReader(handle)]
    return {label.scenario_id: label for label in labels}


def audit_evidence(cases: Iterable[CyberBenchCase]) -> dict[str, object]:
    records = list(cases)
    items = [
        item
        for case in records
        for item in case.agent_input.evidence_pack.evidence_items
    ]
    missing_required = 0
    for case in records:
        pack = case.agent_input.evidence_pack
        available = {
            field
            for item in pack.evidence_items
            if item.source_type != "unverified_claim"
            for field in item.fields
        }
        if set(pack.evaluation_context.required_fields) - available:
            missing_required += 1
    return {
        "cases": len(records),
        "cases_with_evidence": sum(
            bool(case.agent_input.evidence_pack.evidence_items) for case in records
        ),
        "evidence_items": len(items),
        "items_per_case": dict(
            Counter(
                len(case.agent_input.evidence_pack.evidence_items) for case in records
            )
        ),
        "source_types": dict(Counter(item.source_type for item in items)),
        "missing_required_field_cases": missing_required,
        "missing_evidence_ids": sum(not item.evidence_id for item in items),
        "duplicate_evidence_ids": len(items)
        - len({item.evidence_id for item in items}),
        "missing_source_records": sum(not item.source_record_id for item in items),
        "missing_source_urls": sum(not item.source_urls for item in items),
    }


def write_case_snapshot(cases: Iterable[CyberBenchCase], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for case in cases:
            handle.write(
                json.dumps(case.model_dump(mode="json"), sort_keys=True) + "\n"
            )
