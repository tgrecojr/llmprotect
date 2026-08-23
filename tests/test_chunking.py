"""Unit tests for text chunking (no ML stack required)."""

import random

import pytest

from fixtures.build_cta import build_cta_fixture
from guard_api.chunking import chunk_spans, chunk_text, context_window, snap_start

SIZE, OVERLAP = 2000, 200
NOMINAL = SIZE - OVERLAP


def _legacy_chunks(text: str, size: int, overlap: int) -> list[str]:
    """The pre-snap implementation, minus its one quirk: a trailing window
    that started inside the previous one and so was entirely contained in
    it (e.g. 3700 chars → [0:2000], [1800:3700], [3600:3700])."""
    if len(text) <= size:
        return [text]
    step = max(size - overlap, 1)
    out = []
    for i in range(0, len(text), step):
        out.append(text[i : i + size])
        if i + size >= len(text):
            break
    return out


def _prose(n: int, sentence: str = "The quick brown fox jumps over the lazy dog. ") -> str:
    return (sentence * (n // len(sentence) + 1))[:n]


def test_short_text_single_chunk():
    assert chunk_text("hello", size=100, overlap=10) == ["hello"]


def test_long_text_chunks_cover_everything():
    text = "a" * 5000
    chunks = chunk_text(text, size=2000, overlap=200)
    assert all(len(chunk) <= 2000 for chunk in chunks)
    assert sum(len(chunk) for chunk in chunks) >= 5000  # overlap means coverage, not partition


def test_tail_is_scanned():
    text = ("x" * 4000) + "PAYLOAD"
    chunks = chunk_text(text, size=2000, overlap=200)
    assert any("PAYLOAD" in chunk for chunk in chunks)


def test_overlap_spans_boundaries():
    # A marker straddling a chunk boundary must appear intact in some chunk.
    size, overlap = 100, 20
    text = "x" * 95 + "MARKER" + "y" * 100
    chunks = chunk_text(text, size=size, overlap=overlap)
    assert any("MARKER" in chunk for chunk in chunks)


# --- boundary-aware starts (spec §6.1) ---------------------------------------


def test_snap_to_blank_line():
    text = _prose(NOMINAL - 50) + "\n\n" + _prose(3000)
    chunks = chunk_text(text, SIZE, OVERLAP)
    assert chunks[1] == text[NOMINAL - 48 : NOMINAL - 48 + SIZE]
    assert chunks[1].startswith("The quick")


def test_snap_prefers_stronger_boundary():
    # A blank line at -150 and a sentence end at -20: the blank line wins
    # even though the sentence end is nearer.
    head = _prose(NOMINAL - 150, "xxxx ") + "\n\n"
    mid = "y" * (NOMINAL - 20 - len(head) - 2) + ". " + "z" * 20
    assert len(head + mid) == NOMINAL
    assert (head + mid)[NOMINAL - 22 : NOMINAL - 20] == ". "
    text = head + mid + _prose(3000)
    spans = chunk_spans(text, SIZE, OVERLAP)
    assert spans[1][0] == len(head)


def test_snap_falls_back_to_whitespace():
    text = _prose(NOMINAL + 5, "alpha beta gamma ") + "\n" + "z" * 3000
    assert text[NOMINAL - 1 : NOMINAL + 1] == "ma"  # nominal offset is mid-word
    spans = chunk_spans(text, SIZE, OVERLAP)
    start = spans[1][0]
    assert start <= NOMINAL
    assert text[start - 1].isspace() or text[start].isspace()


def test_no_boundary_uses_raw_offset():
    text = "a" * 6000
    assert chunk_text(text, SIZE, OVERLAP) == chunk_text(text, SIZE, OVERLAP, snap=0)
    assert chunk_spans(text, SIZE, OVERLAP)[1][0] == NOMINAL


def test_snap_zero_is_legacy():
    rng = random.Random(1)
    words = ["alpha", "beta", "gamma\n", "delta.", "\n\n", "epsilon,", "zeta!"]
    for _ in range(20):
        text = " ".join(rng.choice(words) for _ in range(rng.randint(1, 1500)))
        size, overlap = rng.randint(50, 400), rng.randint(0, 40)
        assert chunk_text(text, size, overlap, snap=0) == _legacy_chunks(text, size, overlap)


def test_coverage_is_total():
    rng = random.Random(2)
    text = " ".join(rng.choice(["word", "end.", "line\n", "\n\n", "x"]) for _ in range(3000))
    spans = chunk_spans(text, SIZE, OVERLAP)
    assert spans[0][0] == 0 and spans[-1][1] == len(text)
    rebuilt = ""
    for start, end in spans:
        assert start <= len(rebuilt)  # no gap
        rebuilt += text[len(rebuilt) : end]
    assert rebuilt == text


def test_max_size_respected():
    rng = random.Random(3)
    text = " ".join(rng.choice(["word", "end.", "line\n", "\n\n"]) for _ in range(4000))
    assert all(len(chunk) <= SIZE for chunk in chunk_text(text, SIZE, OVERLAP))


@pytest.mark.parametrize("offset", range(NOMINAL - 10, SIZE + 10))
def test_marker_survives_every_boundary(offset):
    text = _prose(offset) + "MARKER" + _prose(3000)
    assert any("MARKER" in chunk for chunk in chunk_text(text, SIZE, OVERLAP))


def test_cta_fixture_chunk2_starts_on_sentence():
    message = build_cta_fixture(SIZE, OVERLAP)
    fixed = chunk_text(message, SIZE, OVERLAP, snap=0)
    assert fixed[1].startswith("ing, now is the time to register.\nREGISTER NOW")
    snapped = chunk_text(message, SIZE, OVERLAP)
    assert snapped[1].startswith("If you have been considering registering")


def test_drift_does_not_accumulate():
    text = _prose(30_000, "Short sentence here. ")
    spans = chunk_spans(text, SIZE, OVERLAP)
    assert spans[-1][1] == len(text)
    expected = -(-(len(text) - OVERLAP) // (SIZE - OVERLAP))
    assert abs(len(spans) - expected) <= 1
    for (a, _), (b, _) in zip(spans, spans[1:], strict=False):
        assert NOMINAL - OVERLAP <= b - a <= NOMINAL


def test_snap_never_regresses_past_previous_start():
    # snap larger than the step must still make progress.
    text = "\n\n" + "a" * 5000
    spans = chunk_spans(text, size=100, overlap=90, snap=1000)
    assert all(b > a for (a, _), (b, _) in zip(spans, spans[1:], strict=False))
    assert spans[-1][1] == len(text)


def test_snap_start_search_range():
    text = "aaaa bbbb cccc"
    assert snap_start(text, nominal=12, lowest=11) == 12  # nothing in range → raw
    assert snap_start(text, nominal=12, lowest=8) == 10  # after the second space
    assert snap_start(text, nominal=12, lowest=-5) == 10


# --- context window for marginal re-scores (spec §4.B) ----------------------


def test_context_window_centred_and_bounded():
    text = _prose(10_000)
    hit = (3600, 5600)
    start, end = context_window(text, hit, 2 * SIZE)
    assert end - start <= 2 * SIZE
    assert start <= hit[0] and end >= hit[1]
    assert text[start - 1] == " "  # boundary-aligned
    assert abs((start + end) // 2 - (hit[0] + hit[1]) // 2) <= OVERLAP


def test_context_window_clamps_to_text():
    text = _prose(3000)
    assert context_window(text, (0, 2000), 4000) == (0, 3000)
    assert context_window(text, (1800, 3000), 4000) == (0, 3000)
    assert context_window(_prose(2500), (0, 2000), 2500) == (0, 2500)


def test_context_window_keeps_hit_when_snapping_would_cut_it():
    # A last chunk flush against the text end: snapping the start back
    # would push the end before the hit, so the raw start is kept.
    text = "a" * 3900 + " " + "b" * 4099
    hit = (6000, 8000)
    start, end = context_window(text, hit, 4000, snap=200)
    assert (start, end) == (4000, 8000)
