from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


QUALITY_METRICS = [
    "routing_accuracy",
    "macro_f1",
    "false_acceptance_rate",
    "false_rejection_rate",
]


def write_report_artifacts(metrics: dict[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    conditions = metrics["conditions"]
    rows = []
    for condition, values in conditions.items():
        row = {"condition": condition}
        row.update(
            {
                key: value
                for key, value in values.items()
                if not isinstance(value, list)
            }
        )
        rows.append(row)
    frame = pd.DataFrame(rows).sort_values("condition")
    frame.to_csv(output_dir / "condition-metrics.csv", index=False)

    if frame.empty:
        return

    quality = frame.set_index("condition")[QUALITY_METRICS]
    axis = quality.plot(
        kind="bar",
        figsize=(9, 5),
        color=["white", "0.75", "0.45", "0.15"],
        edgecolor="black",
    )
    axis.set_ylabel("Rate")
    axis.set_ylim(0, 1)
    axis.set_title("Routing quality and safety errors by condition")
    axis.grid(axis="y", linestyle=":", color="0.7")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(output_dir / "quality-and-safety.png", dpi=200)
    plt.close()

    efficiency = frame.set_index("condition")[
        ["average_latency_ms", "average_tokens"]
    ]
    figure, axes = plt.subplots(1, 2, figsize=(9, 4))
    efficiency["average_latency_ms"].plot(
        kind="bar",
        ax=axes[0],
        color="white",
        edgecolor="black",
        hatch="//",
    )
    efficiency["average_tokens"].plot(
        kind="bar",
        ax=axes[1],
        color="white",
        edgecolor="black",
        hatch="..",
    )
    axes[0].set_title("Average latency")
    axes[0].set_ylabel("Milliseconds")
    axes[1].set_title("Average token use")
    for axis in axes:
        axis.tick_params(axis="x", rotation=0)
        axis.grid(axis="y", linestyle=":", color="0.7")
    plt.tight_layout()
    plt.savefig(output_dir / "efficiency.png", dpi=200)
    plt.close()

    (output_dir / "metrics-pretty.json").write_text(
        json.dumps(metrics, indent=2) + "\n",
        encoding="utf-8",
    )
