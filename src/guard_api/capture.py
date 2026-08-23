"""Opt-in capture of every scanned text plus its verdict, as JSONL.

One record per scanned text, appended to `<dir>/YYYY-MM-DD.jsonl`. The
point is a replayable test bed of real traffic: `scripts/replay.py` re-scores
a capture file under different chunk/threshold settings and diffs the
verdicts. Text reaching the sidecar has already been Presidio-masked, but it
is still real mail — the directory is gitignored and capture is off unless
GUARD_CAPTURE_DIR is set.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("guard_api")


def record_for(
    text: str,
    result: Any,
    *,
    call_id: str | None,
    text_index: int,
    threshold: float,
    config: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the JSON record for one scanned text. `result` is a RiskResult."""
    now = now or datetime.now(UTC)
    data = asdict(result)
    return {
        "ts": now.isoformat(timespec="seconds"),
        "call_id": call_id,
        "text_index": text_index,
        "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
        "len": len(text),
        "threshold": threshold,
        "blocked": result.blocks(threshold),
        "score": data["score"],
        "rescore": data["rescore"] if data["rescored"] else None,
        "chunk_index": data["chunk_index"],
        "chunk_count": data["chunk_count"],
        "chunk_scores": list(data.get("chunk_scores") or ()),
        "config": config,
        "label": None,  # ground truth, filled in later by hand / replay tooling
        "text": text,
    }


class Capture:
    """Append-only JSONL writer, one file per UTC day. Never raises into the
    request path: a full disk or bad mount logs an error and the scan still
    returns its verdict."""

    def __init__(self, directory: str | Path, config: dict[str, Any]) -> None:
        self.directory = Path(directory)
        self.config = config
        self.directory.mkdir(parents=True, exist_ok=True)

    def path_for(self, now: datetime) -> Path:
        return self.directory / f"{now:%Y-%m-%d}.jsonl"

    def write(
        self,
        text: str,
        result: Any,
        *,
        call_id: str | None,
        text_index: int,
        threshold: float,
    ) -> None:
        now = datetime.now(UTC)
        record = record_for(
            text,
            result,
            call_id=call_id,
            text_index=text_index,
            threshold=threshold,
            config=self.config,
            now=now,
        )
        try:
            with self.path_for(now).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("capture write failed (%s): %s", self.path_for(now), exc)


def read_records(path: str | Path) -> list[dict[str, Any]]:
    """Load a capture file (used by scripts/replay.py and tests)."""
    with Path(path).open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
