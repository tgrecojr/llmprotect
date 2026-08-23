"""Injection classifier wrapper.

transformers/torch are imported lazily inside InjectionClassifier so the API
package can be imported and tested without the ML stack installed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from guard_api.chunking import (
    DEFAULT_SNAP,
    chunk_spans,
    chunk_text,
    context_window,
)

__all__ = [
    "BENIGN_LABELS",
    "DEFAULT_MARGIN",
    "EXCERPT_CHARS",
    "InjectionClassifier",
    "RiskResult",
    "chunk_text",
    "make_excerpt",
]

# Labels (lowercased) that mean "not an attack" across common guard models:
# PIGuard/ProtectAI use benign/injection, Prompt Guard 2 uses LABEL_0/LABEL_1.
BENIGN_LABELS = {"benign", "safe", "legit", "label_0", "no_injection"}

EXCERPT_CHARS = 120

# Width of the band above the threshold in which a hit is re-scored with
# more context before it is allowed to block (GUARD_MARGIN). Off by default:
# measured 2026-08-23, the wider window rescued 5/25 attacks planted in a
# real newsletter while clearing the incident only by luck — see
# docs/guardrails.md "Contextual re-score".
DEFAULT_MARGIN = 0.0


@dataclass(frozen=True)
class RiskResult:
    """Outcome of scanning one text: the worst chunk and where it was.

    When the worst chunk landed in the marginal band it was re-scored inside
    a wider, boundary-aligned window; `rescore` then carries that second
    score and decides the outcome (`effective_score`). `score` and `excerpt`
    always describe the original chunk so operators see what they were told
    about."""

    score: float
    chunk_index: int
    chunk_count: int
    excerpt: str
    rescored: bool = False
    rescore: float | None = None
    # Every chunk's score in order (captured for offline replay; empty when a
    # stub or an older caller didn't supply them).
    chunk_scores: tuple[float, ...] = ()

    @property
    def location(self) -> str:
        return f"chunk {self.chunk_index + 1}/{self.chunk_count}"

    @property
    def effective_score(self) -> float:
        return self.rescore if self.rescored and self.rescore is not None else self.score

    def blocks(self, threshold: float) -> bool:
        return self.effective_score >= threshold


def make_excerpt(chunk: str, limit: int = EXCERPT_CHARS) -> str:
    """Single-line preview of a chunk for logs / block reasons."""
    flat = " ".join(chunk.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def risk_of(label_scores: list[dict]) -> float:
    """Max probability assigned to any non-benign label."""
    return max(
        (float(e["score"]) for e in label_scores if e["label"].lower() not in BENIGN_LABELS),
        default=0.0,
    )


class InjectionClassifier:
    def __init__(
        self,
        model_id: str,
        revision: str | None = None,
        trust_remote_code: bool = False,
        chunk_chars: int = 2000,
        chunk_overlap: int = 200,
        chunk_snap: int = DEFAULT_SNAP,
        margin: float = DEFAULT_MARGIN,
    ) -> None:
        from transformers import pipeline  # heavy import, deferred

        self._chunk_chars = chunk_chars
        self._chunk_overlap = chunk_overlap
        self._chunk_snap = chunk_snap
        self._margin = margin
        self._pipe = pipeline(
            "text-classification",
            model=model_id,
            revision=revision,
            trust_remote_code=trust_remote_code,
            device="cpu",
            top_k=None,
            truncation=True,
        )

    def score_texts(self, texts: list[str]) -> list[float]:
        """Non-benign probability for each text, in one pipeline call."""
        results = self._pipe(texts)
        # top_k=None on a list input yields list[list[{label, score}]]
        if results and isinstance(results[0], dict):
            results = [results]
        return [risk_of(label_scores) for label_scores in results]

    def assess(self, text: str, threshold: float | None = None) -> RiskResult:
        """Max non-benign probability across chunks, plus which chunk produced it.

        With a `threshold`, a hit in [threshold, threshold + margin) is
        re-scored inside a window twice the chunk size centred on it; the
        re-score then decides (`RiskResult.effective_score`). Without one
        (or with margin 0) the raw chunk score is the answer."""
        if not text or not text.strip():
            return RiskResult(score=0.0, chunk_index=0, chunk_count=0, excerpt="")
        spans = chunk_spans(text, self._chunk_chars, self._chunk_overlap, self._chunk_snap)
        chunks = [text[start:end] for start, end in spans]
        scores = self.score_texts(chunks)
        index = max(range(len(chunks)), key=lambda i: (scores[i], -i))
        worst = RiskResult(
            score=scores[index],
            chunk_index=index,
            chunk_count=len(chunks),
            excerpt=make_excerpt(chunks[index]),
            chunk_scores=tuple(scores),
        )
        if threshold is None or self._margin <= 0:
            return worst
        if not (threshold <= worst.score < threshold + self._margin):
            return worst
        window = context_window(text, spans[index], 2 * self._chunk_chars, self._chunk_snap)
        if window == spans[index]:
            return worst  # nothing more to show the model
        rescore = self.score_texts([text[window[0] : window[1]]])[0]
        return replace(worst, rescored=True, rescore=rescore)

    def risk_score(self, text: str) -> float:
        """Backwards-compatible scalar form of assess()."""
        return self.assess(text).score
