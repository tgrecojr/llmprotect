"""Injection classifier wrapper.

transformers/torch are imported lazily inside InjectionClassifier so the API
package can be imported and tested without the ML stack installed.
"""

from __future__ import annotations

# Labels (lowercased) that mean "not an attack" across common guard models:
# PIGuard/ProtectAI use benign/injection, Prompt Guard 2 uses LABEL_0/LABEL_1.
BENIGN_LABELS = {"benign", "safe", "legit", "label_0", "no_injection"}


def chunk_text(text: str, size: int, overlap: int) -> list[str]:
    """Sliding character windows so injections past the model's 512-token
    truncation horizon are still scanned."""
    if len(text) <= size:
        return [text]
    step = max(size - overlap, 1)
    return [text[i : i + size] for i in range(0, len(text), step) if text[i : i + size]]


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

    def risk_score(self, text: str) -> float:
        """Max probability assigned to any non-benign label across chunks."""
        if not text or not text.strip():
            return 0.0
        chunks = chunk_text(text, self._chunk_chars, self._chunk_overlap)
        results = self._pipe(chunks)
        # top_k=None on a list input yields list[list[{label, score}]]
        if results and isinstance(results[0], dict):
            results = [results]
        worst = 0.0
        for chunk_scores in results:
            for entry in chunk_scores:
                if entry["label"].lower() not in BENIGN_LABELS:
                    worst = max(worst, float(entry["score"]))
        return worst
