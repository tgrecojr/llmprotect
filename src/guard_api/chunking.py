"""Sliding-window chunking with boundary-aware window starts.

The model itself accepts long inputs (no hard 512-token cut; verified 2026-08
on PIGuard), so chunking is defense-in-depth that keeps each scored window
short enough for the classifier to stay sharp on a payload buried in a long
document.

Fixed character windows, however, routinely begin mid-sentence ("ing, now is
the time to register. REGISTER NOW …") and that fragment, stripped of the
sentence that makes it obviously marketing copy, is what tripped the
2026-08-23 false positive (docs/spec-cta-false-positive.md). Each window's
start is therefore snapped back — by at most `snap` characters, i.e. within
the overlap — to the strongest nearby boundary: blank line, line break,
sentence end, then any whitespace. No boundary in range (a base64 blob, say)
means the raw offset is used; coverage never shrinks.
"""

from __future__ import annotations

from collections.abc import Callable

DEFAULT_SNAP = 200

Span = tuple[int, int]

_SENTENCE_END = ".!?"


def _after_blank_line(text: str, pos: int) -> bool:
    return pos >= 2 and text[pos - 2 : pos] == "\n\n"


def _after_newline(text: str, pos: int) -> bool:
    return pos >= 1 and text[pos - 1] == "\n"


def _after_sentence(text: str, pos: int) -> bool:
    # Whitespace behind us, a non-space ahead, and the last non-space
    # character before the gap is sentence-ending punctuation.
    if pos < 2 or not text[pos - 1].isspace() or (pos < len(text) and text[pos].isspace()):
        return False
    back = pos - 1
    while back > 0 and text[back].isspace():
        back -= 1
    return text[back] in _SENTENCE_END


def _not_mid_word(text: str, pos: int) -> bool:
    return pos >= len(text) or pos < 1 or text[pos - 1].isspace() or text[pos].isspace()


# Strongest first; the first class with any hit in the search window wins,
# and within a class the hit nearest the nominal offset wins.
_BOUNDARIES: tuple[Callable[[str, int], bool], ...] = (
    _after_blank_line,
    _after_newline,
    _after_sentence,
    _not_mid_word,
)


def snap_start(text: str, nominal: int, lowest: int) -> int:
    """Largest position in [lowest, nominal] that sits on the strongest
    boundary class present; `nominal` itself when the range has none."""
    lowest = max(lowest, 0)
    for is_boundary in _BOUNDARIES:
        for pos in range(nominal, lowest - 1, -1):
            if is_boundary(text, pos):
                return pos
    return nominal


def chunk_spans(text: str, size: int, overlap: int, snap: int = DEFAULT_SNAP) -> list[Span]:
    """(start, end) offsets of the windows that cover `text`.

    Each window is `size` chars from its start. The next window's nominal
    start is `size - overlap` past the *snapped* start of the previous one,
    so snapping cannot accumulate into a drift of the grid; it only widens
    the overlap between two neighbours by the amount snapped back. `snap=0`
    is exactly the fixed grid."""
    length = len(text)
    if length <= size:
        return [(0, length)]
    step = max(size - overlap, 1)
    spans: list[Span] = []
    start = 0
    while True:
        end = min(start + size, length)
        spans.append((start, end))
        if end >= length:
            return spans
        nominal = start + step
        # Never snap back to (or before) the current start: progress is
        # guaranteed even when snap exceeds the step.
        start = snap_start(text, nominal, max(nominal - snap, start + 1))


def chunk_text(text: str, size: int, overlap: int, snap: int = DEFAULT_SNAP) -> list[str]:
    """The windows of chunk_spans() as strings."""
    return [text[start:end] for start, end in chunk_spans(text, size, overlap, snap)]


def context_window(text: str, hit: Span, size: int, snap: int = DEFAULT_SNAP) -> Span:
    """A window of at most `size` chars centred on `hit`, clamped to the text,
    with its start snapped to a boundary when that keeps `hit` inside."""
    length = len(text)
    hit_start, hit_end = hit
    if length <= size:
        return (0, length)
    centre = (hit_start + hit_end) // 2
    start = min(max(centre - size // 2, 0), length - size)
    snapped = snap_start(text, start, start - snap)
    if snapped + size >= hit_end:
        start = snapped
    return (start, min(start + size, length))
