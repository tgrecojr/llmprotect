"""Injection classifier wrapper.

transformers/torch are imported lazily inside InjectionClassifier so the API
package can be imported and tested without the ML stack installed.
"""

from __future__ import annotations

from dataclasses import dataclass

# Labels (lowercased) that mean "not an attack" across common guard models:
# PIGuard/ProtectAI use benign/injection, Prompt Guard 2 uses LABEL_0/LABEL_1.
BENIGN_LABELS = {"benign", "safe", "legit", "label_0", "no_injection"}

EXCERPT_CHARS = 120


@dataclass(frozen=True)
class RiskResult:
    """Outcome of scanning one text: the worst chunk and where it was."""

    score: float
    chunk_index: int
    chunk_count: int
    excerpt: str

    @property
    def location(self) -> str:
        return f"chunk {self.chunk_index + 1}/{self.chunk_count}"


def chunk_text(text: str, size: int, overlap: int) -> list[str]:
    """Sliding character windows. The model itself accepts long inputs (no
    hard 512-token cut; verified 2026-08 on PIGuard), so chunking is
    defense-in-depth that keeps each scored window short enough for the
    classifier to stay sharp on a payload buried in a long document."""
    if len(text) <= size:
        return [text]
    step = max(size - overlap, 1)
    return [text[i : i + size] for i in range(0, len(text), step) if text[i : i + size]]


def make_excerpt(chunk: str, limit: int = EXCERPT_CHARS) -> str:
    """Single-line preview of a chunk for logs / block reasons."""
    flat = " ".join(chunk.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


class InjectionClassifier:
    def __init__(
        self,
        model_id: str,
        revision: str | None = None,
        trust_remote_code: bool = False,
        chunk_chars: int = 2000,
        chunk_overlap: int = 200,
    ) -> None:
        from transformers import pipeline  # heavy import, deferred

        self._chunk_chars = chunk_chars
        self._chunk_overlap = chunk_overlap
        self._pipe = pipeline(
            "text-classification",
            model=model_id,
            revision=revision,
            trust_remote_code=trust_remote_code,
            device="cpu",
            top_k=None,
            truncation=True,
        )

    def assess(self, text: str) -> RiskResult:
        """Max probability assigned to any non-benign label across chunks,
        plus which chunk produced it."""
        if not text or not text.strip():
            return RiskResult(score=0.0, chunk_index=0, chunk_count=0, excerpt="")
        chunks = chunk_text(text, self._chunk_chars, self._chunk_overlap)
        results = self._pipe(chunks)
        # top_k=None on a list input yields list[list[{label, score}]]
        if results and isinstance(results[0], dict):
            results = [results]
        worst = RiskResult(score=0.0, chunk_index=0, chunk_count=len(chunks), excerpt="")
        for index, chunk_scores in enumerate(results):
            for entry in chunk_scores:
                score = float(entry["score"])
                if entry["label"].lower() not in BENIGN_LABELS and score > worst.score:
                    worst = RiskResult(
                        score=score,
                        chunk_index=index,
                        chunk_count=len(chunks),
                        excerpt=make_excerpt(chunks[index]),
                    )
        return worst

    def risk_score(self, text: str) -> float:
        """Backwards-compatible scalar form of assess()."""
        return self.assess(text).score
