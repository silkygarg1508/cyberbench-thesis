from __future__ import annotations

import json
from pathlib import Path

from .schemas import RunTrace


class JsonlTraceStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, trace: RunTrace) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                json.dumps(trace.model_dump(mode="json"), sort_keys=True) + "\n"
            )

    def read_all(self) -> list[RunTrace]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as handle:
            return [
                RunTrace.model_validate_json(line)
                for line in handle
                if line.strip()
            ]

