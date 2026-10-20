from __future__ import annotations

from collections import defaultdict
from statistics import median

from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from .schemas import Condition, GoldLabel, Route, RunTrace


ROUTE_ORDER = [
    Route.ACCEPT.value,
    Route.RETRY.value,
    Route.REJECT.value,
    Route.HUMAN_REVIEW.value,
]


def _safe_mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def evaluate_traces(
    traces: list[RunTrace],
    labels: dict[str, GoldLabel],
) -> dict[str, object]:
    grouped: dict[Condition, list[RunTrace]] = defaultdict(list)
    for trace in traces:
        if trace.scenario_id not in labels:
            raise KeyError(f"No gold label for {trace.scenario_id}")
        grouped[trace.condition].append(trace)

    result: dict[str, object] = {"conditions": {}}
    for condition, condition_traces in grouped.items():
        expected = [
            labels[trace.scenario_id].expected_route.value
            for trace in condition_traces
        ]
        predicted = [trace.predicted_route.value for trace in condition_traces]
        should_not_accept = [
            index
            for index, route in enumerate(expected)
            if route != Route.ACCEPT.value
        ]
        should_accept = [
            index
            for index, route in enumerate(expected)
            if route == Route.ACCEPT.value
        ]
        false_accepts = sum(
            predicted[index] == Route.ACCEPT.value for index in should_not_accept
        )
        false_rejections = sum(
            predicted[index] != Route.ACCEPT.value for index in should_accept
        )
        gold_defect = [
            labels[trace.scenario_id].gold_defect_type.strip().casefold() != "none"
            for trace in condition_traces
        ]
        predicted_defect = [
            any(not check.passed for check in trace.checks)
            for trace in condition_traces
        ]
        latencies = [trace.latency_ms for trace in condition_traces]
        tokens = [trace.usage.total_tokens for trace in condition_traces]
        result["conditions"][condition.value] = {
            "cases": len(condition_traces),
            "routing_accuracy": accuracy_score(expected, predicted),
            "macro_f1": f1_score(
                expected,
                predicted,
                labels=ROUTE_ORDER,
                average="macro",
                zero_division=0,
            ),
            "false_acceptance_rate": (
                false_accepts / len(should_not_accept) if should_not_accept else 0.0
            ),
            "false_rejection_rate": (
                false_rejections / len(should_accept) if should_accept else 0.0
            ),
            "verifier_precision": precision_score(
                gold_defect, predicted_defect, zero_division=0
            ),
            "verifier_recall": recall_score(
                gold_defect, predicted_defect, zero_division=0
            ),
            "verifier_f1": f1_score(
                gold_defect, predicted_defect, zero_division=0
            ),
            "average_latency_ms": _safe_mean(latencies),
            "median_latency_ms": median(latencies) if latencies else 0.0,
            "average_tokens": _safe_mean(tokens),
            "retry_rate": sum(
                trace.predicted_route == Route.RETRY for trace in condition_traces
            )
            / len(condition_traces),
            "confusion_matrix": confusion_matrix(
                expected,
                predicted,
                labels=ROUTE_ORDER,
            ).tolist(),
            "route_order": ROUTE_ORDER,
        }

    baseline = result["conditions"].get(Condition.MAS_UNVERIFIED.value)
    if baseline:
        baseline_latency = baseline["average_latency_ms"]
        baseline_tokens = baseline["average_tokens"]
        for condition_result in result["conditions"].values():
            condition_result["latency_overhead_percent_vs_b2"] = (
                100
                * (condition_result["average_latency_ms"] - baseline_latency)
                / baseline_latency
                if baseline_latency
                else 0.0
            )
            condition_result["token_overhead_percent_vs_b2"] = (
                100
                * (condition_result["average_tokens"] - baseline_tokens)
                / baseline_tokens
                if baseline_tokens
                else 0.0
            )
    return result
