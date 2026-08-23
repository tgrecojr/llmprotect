"""Unit tests for text chunking (no ML stack required)."""

from guard_api.classifier import chunk_text


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
