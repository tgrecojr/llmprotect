"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    model_id: str
    model_revision: str | None
    trust_remote_code: bool
    threshold: float
    chunk_chars: int
    chunk_overlap: int
    # When True, a BLOCKED response names the offending chunk and includes a
    # short excerpt of it. The text has already been through Presidio masking
    # by the time it reaches the sidecar, and the excerpt only lands in the
    # guard log and the LiteLLM error message / spend log. On by default;
    # set GUARD_BLOCK_DETAIL=0 to keep prompt excerpts out of those places.
    block_detail: bool = True
    # How far (chars) a chunk start may move back to land on a blank line /
    # line break / sentence end / whitespace instead of mid-word. 0 = fixed
    # windows exactly as before.
    chunk_snap: int = 200
    # A hit scoring in [threshold, threshold + margin) is re-scored inside a
    # wider window before it may block. 0 (default) = never re-score; the
    # wider window dilutes real attacks (docs/guardrails.md), so this is an
    # experiment knob, not a fix.
    margin: float = 0.0
    # Root log level for the container. Must be at least INFO for the
    # per-call `scored …` lines to be emitted — WARNING would leave only
    # block lines, hiding near-misses and drift.
    log_level: str = "INFO"


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    return Settings(
        model_id=os.environ.get("GUARD_MODEL_ID", "leolee99/PIGuard"),
        model_revision=os.environ.get("GUARD_MODEL_REVISION") or None,
        trust_remote_code=_flag("GUARD_TRUST_REMOTE_CODE", "1"),
        threshold=float(os.environ.get("GUARD_THRESHOLD", "0.85")),
        chunk_chars=int(os.environ.get("GUARD_CHUNK_CHARS", "2000")),
        chunk_overlap=int(os.environ.get("GUARD_CHUNK_OVERLAP", "200")),
        block_detail=_flag("GUARD_BLOCK_DETAIL", "1"),
        chunk_snap=int(os.environ.get("GUARD_CHUNK_SNAP", "200")),
        margin=float(os.environ.get("GUARD_MARGIN", "0")),
        log_level=os.environ.get("GUARD_LOG_LEVEL", "INFO").strip().upper(),
    )
