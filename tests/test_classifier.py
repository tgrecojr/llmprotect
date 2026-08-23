"""Unit tests for InjectionClassifier.assess() with a fake pipeline (no ML stack)."""

from guard_api.classifier import InjectionClassifier, RiskResult, make_excerpt


class FakePipe:
    """Mimics a transformers text-classification pipeline with top_k=None:
    a list input yields list[list[{label, score}]]. Scores 'injection' high
    for any chunk containing ATTACK."""

    def __call__(self, chunks: list[str]):
        out = []
        for chunk in chunks:
            hit = 0.97 if "ATTACK" in chunk else 0.02
            out.append(
                [{"label": "injection", "score": hit}, {"label": "benign", "score": 1 - hit}]
            )
        return out


def make_classifier(chunk_chars: int = 100, chunk_overlap: int = 10) -> InjectionClassifier:
    clf = InjectionClassifier.__new__(InjectionClassifier)  # skip transformers import
    clf._pipe = FakePipe()
    clf._chunk_chars = chunk_chars
    clf._chunk_overlap = chunk_overlap
    return clf


def test_empty_text_is_zero_risk():
    result = make_classifier().assess("   ")
    assert result == RiskResult(score=0.0, chunk_index=0, chunk_count=0, excerpt="")


def test_benign_text_reports_low_score():
    result = make_classifier().assess("nothing to see here")
    assert result.score == 0.02
    assert result.chunk_count == 1
    assert result.location == "chunk 1/1"
    assert result.excerpt == "nothing to see here"


def test_assess_identifies_winning_chunk():
    text = ("x" * 250) + " ATTACK here " + ("y" * 50)
    result = make_classifier(chunk_chars=100, chunk_overlap=10).assess(text)
    assert result.score == 0.97
    assert result.chunk_count == 4
    assert result.chunk_index == 2
    assert result.location == "chunk 3/4"
    assert "ATTACK" in result.excerpt


def test_risk_score_is_scalar_of_assess():
    clf = make_classifier()
    assert clf.risk_score("ATTACK") == 0.97
    assert clf.risk_score("fine") == 0.02


def test_block_detail_defaults_on(monkeypatch):
    from guard_api.settings import load_settings

    monkeypatch.delenv("GUARD_BLOCK_DETAIL", raising=False)
    assert load_settings().block_detail is True
    monkeypatch.setenv("GUARD_BLOCK_DETAIL", "0")
    assert load_settings().block_detail is False
    monkeypatch.setenv("GUARD_BLOCK_DETAIL", "false")
    assert load_settings().block_detail is False


def test_make_excerpt_flattens_and_truncates():
    assert make_excerpt("  a\n\n b\tc ") == "a b c"
    long = "word " * 100
    excerpt = make_excerpt(long, limit=20)
    assert len(excerpt) == 20
    assert excerpt.endswith("…")
