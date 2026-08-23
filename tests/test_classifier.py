"""Unit tests for InjectionClassifier.assess() with a fake pipeline (no ML stack)."""

import pytest

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


class ScriptedPipe:
    """Returns the scripted injection score for each text of each call, in
    order, and records every call's input."""

    def __init__(self, *scripts: list[float]) -> None:
        self.scripts = list(scripts)
        self.calls: list[list[str]] = []

    def __call__(self, texts: list[str]):
        self.calls.append(list(texts))
        scores = self.scripts.pop(0)
        assert len(scores) == len(texts), f"scripted {len(scores)} scores for {len(texts)} texts"
        return [
            [{"label": "injection", "score": s}, {"label": "benign", "score": 1 - s}]
            for s in scores
        ]


def make_classifier(
    chunk_chars: int = 100,
    chunk_overlap: int = 10,
    chunk_snap: int = 0,
    margin: float = 0.10,
    pipe=None,
) -> InjectionClassifier:
    clf = InjectionClassifier.__new__(InjectionClassifier)  # skip transformers import
    clf._pipe = pipe or FakePipe()
    clf._chunk_chars = chunk_chars
    clf._chunk_overlap = chunk_overlap
    clf._chunk_snap = chunk_snap
    clf._margin = margin
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
    assert result.rescored is False and result.rescore is None
    assert result.effective_score == 0.02


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


def test_snap_and_margin_settings(monkeypatch):
    from guard_api.settings import load_settings

    monkeypatch.delenv("GUARD_CHUNK_SNAP", raising=False)
    monkeypatch.delenv("GUARD_MARGIN", raising=False)
    assert load_settings().chunk_snap == 200
    assert load_settings().margin == 0.0  # re-score is opt-in
    monkeypatch.setenv("GUARD_CHUNK_SNAP", "0")
    monkeypatch.setenv("GUARD_MARGIN", "0.10")
    assert load_settings().chunk_snap == 0
    assert load_settings().margin == 0.10


def test_log_level_defaults_to_info(monkeypatch):
    from guard_api.settings import load_settings

    monkeypatch.delenv("GUARD_LOG_LEVEL", raising=False)
    assert load_settings().log_level == "INFO"
    monkeypatch.setenv("GUARD_LOG_LEVEL", "warning")
    assert load_settings().log_level == "WARNING"


def test_make_excerpt_flattens_and_truncates():
    assert make_excerpt("  a\n\n b\tc ") == "a b c"
    long = "word " * 100
    excerpt = make_excerpt(long, limit=20)
    assert len(excerpt) == 20
    assert excerpt.endswith("…")


# --- contextual re-score of marginal hits (spec §6.2) ------------------------

THRESHOLD = 0.85
# Three ~100-char chunks of word-y text so snapping has boundaries to find.
THREE_CHUNKS = " ".join(f"word{i:03d}" for i in range(40))  # 319 chars


def test_clear_block_not_rescored():
    pipe = ScriptedPipe([0.1, 0.97, 0.1, 0.1])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS, THRESHOLD)
    assert len(pipe.calls) == 1
    assert result.score == 0.97 and result.rescored is False
    assert result.blocks(THRESHOLD)


def test_clear_pass_not_rescored():
    pipe = ScriptedPipe([0.1, 0.5, 0.1, 0.1])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS, THRESHOLD)
    assert len(pipe.calls) == 1
    assert not result.blocks(THRESHOLD)


def test_marginal_hit_rescored_and_cleared():
    pipe = ScriptedPipe([0.1, 0.855, 0.1, 0.1], [0.41])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS, THRESHOLD)
    assert len(pipe.calls) == 2
    assert result.score == 0.855 and result.chunk_index == 1
    assert result.rescored is True and result.rescore == 0.41
    assert result.effective_score == 0.41
    assert not result.blocks(THRESHOLD)


def test_marginal_hit_rescored_and_confirmed():
    pipe = ScriptedPipe([0.1, 0.86, 0.1, 0.1], [0.93])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS, THRESHOLD)
    assert result.blocks(THRESHOLD)
    assert result.rescore == 0.93


def test_hit_at_margin_edge_blocks_without_rescore():
    pipe = ScriptedPipe([0.1, 0.95, 0.1, 0.1])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS, THRESHOLD)
    assert len(pipe.calls) == 1 and result.blocks(THRESHOLD)


def test_margin_zero_disables_rescore():
    pipe = ScriptedPipe([0.855])
    result = make_classifier(margin=0, pipe=pipe).assess("short text", THRESHOLD)
    assert len(pipe.calls) == 1
    assert result.blocks(THRESHOLD) and result.rescored is False


def test_no_threshold_means_no_rescore():
    pipe = ScriptedPipe([0.1, 0.855, 0.1, 0.1])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS)
    assert len(pipe.calls) == 1 and result.rescored is False


def test_context_window_is_boundary_aligned():
    size, overlap = 100, 10
    pipe = ScriptedPipe([0.1, 0.86, 0.1, 0.1], [0.2])
    clf = make_classifier(chunk_chars=size, chunk_overlap=overlap, chunk_snap=20, pipe=pipe)
    clf.assess(THREE_CHUNKS, THRESHOLD)
    hit_chunk = pipe.calls[0][1]
    context = pipe.calls[1][0]
    assert len(context) <= 2 * size
    assert hit_chunk in context
    offset = THREE_CHUNKS.index(context)
    assert offset == 0 or THREE_CHUNKS[offset - 1] == " "


def test_single_chunk_text_rescore_is_noop():
    pipe = ScriptedPipe([0.86])
    result = make_classifier(pipe=pipe).assess("short text", THRESHOLD)
    assert len(pipe.calls) == 1
    assert result.blocks(THRESHOLD) and result.rescored is False


def test_excerpt_is_from_original_chunk():
    pipe = ScriptedPipe([0.1, 0.86, 0.1, 0.1], [0.2])
    result = make_classifier(pipe=pipe).assess(THREE_CHUNKS, THRESHOLD)
    assert result.excerpt == make_excerpt(pipe.calls[0][1])
    assert result.excerpt != make_excerpt(pipe.calls[1][0])


@pytest.mark.parametrize("scores", [[0.1, 0.1, 0.1, 0.1], [0.9, 0.9, 0.1, 0.1]])
def test_ties_pick_first_chunk(scores):
    result = make_classifier(pipe=ScriptedPipe(scores)).assess(THREE_CHUNKS)
    assert result.chunk_index == 0


def test_dict_result_from_single_input_is_normalised():
    class SinglePipe:
        def __call__(self, texts):
            return [{"label": "injection", "score": 0.3}, {"label": "benign", "score": 0.7}]

    result = make_classifier(pipe=SinglePipe()).assess("one chunk")
    assert result.score == 0.3 and result.chunk_count == 1
