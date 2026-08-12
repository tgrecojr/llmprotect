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


def load_settings() -> Settings:
    return Settings(
        model_id=os.environ.get("GUARD_MODEL_ID", "leolee99/PIGuard"),
        model_revision=os.environ.get("GUARD_MODEL_REVISION") or None,
        trust_remote_code=os.environ.get("GUARD_TRUST_REMOTE_CODE", "1") == "1",
        threshold=float(os.environ.get("GUARD_THRESHOLD", "0.85")),
        chunk_chars=int(os.environ.get("GUARD_CHUNK_CHARS", "2000")),
        chunk_overlap=int(os.environ.get("GUARD_CHUNK_OVERLAP", "200")),
    )
