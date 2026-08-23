#!/usr/bin/env python
"""Re-score captured guard traffic (GUARD_CAPTURE_DIR JSONL) under different
settings and show which verdicts would change.

Needs the ML dependency group in a throwaway env (see scripts/score.py):

    /tmp/llmprotect-ml/bin/python scripts/replay.py data/guard-capture/*.jsonl
    /tmp/llmprotect-ml/bin/python scripts/replay.py data/*.jsonl --chunk-chars 500
    /tmp/llmprotect-ml/bin/python scripts/replay.py data/*.jsonl --threshold 0.9 --only-changed

Each record already holds the score the sidecar produced and the config it
ran with; the replay scores the same text with the settings given here and
prints old -> new per record, then a summary (blocked before/after, flips).
Records with identical text (same sha256) are scored once. If a record has
a `label` ("attack"/"benign"), false positives/negatives are counted too.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guard_api.capture import read_records  # noqa: E402
from guard_api.classifier import DEFAULT_MARGIN, InjectionClassifier  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="+", help="capture .jsonl files")
    parser.add_argument("--model", default=os.environ.get("GUARD_MODEL_ID", "leolee99/PIGuard"))
    parser.add_argument(
        "--revision",
        default=os.environ.get("GUARD_MODEL_REVISION", "dd78b24e330193a22d2293ac66922dd4f982f563"),
        help="pass '' for the default branch (e.g. when switching --model)",
    )
    parser.add_argument("--threshold", type=float, default=0.85)
    parser.add_argument("--chunk-chars", type=int, default=2000)
    parser.add_argument("--chunk-overlap", type=int, default=200)
    parser.add_argument("--chunk-snap", type=int, default=200)
    parser.add_argument("--margin", type=float, default=DEFAULT_MARGIN)
    parser.add_argument("--only-changed", action="store_true", help="print flipped verdicts only")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = [r for f in args.files for r in read_records(f)]
    unique: dict[str, dict] = {}
    for rec in records:
        unique.setdefault(rec["sha256"], rec)
    print(f"{len(records)} records, {len(unique)} unique texts")
    print(
        f"replay: model={args.model} threshold={args.threshold} chunk_chars={args.chunk_chars}"
        f" overlap={args.chunk_overlap} snap={args.chunk_snap} margin={args.margin}"
    )

    clf = InjectionClassifier(
        model_id=args.model,
        revision=args.revision or None,
        trust_remote_code=os.environ.get("GUARD_TRUST_REMOTE_CODE", "1") == "1",
        chunk_chars=args.chunk_chars,
        chunk_overlap=args.chunk_overlap,
        chunk_snap=args.chunk_snap,
        margin=args.margin,
    )

    before = after = flips = 0
    confusion = {"fp": 0, "fn": 0, "labelled": 0}
    for rec in unique.values():
        result = clf.assess(rec["text"], args.threshold)
        was, now = rec["blocked"], result.blocks(args.threshold)
        before += was
        after += now
        flips += was != now
        tally(confusion, rec.get("label"), now)
        if args.only_changed and was == now:
            continue
        mark = "FLIP" if was != now else "    "
        print(
            f"{mark} {rec['ts']} {rec['sha256'][:8]} len={rec['len']:>6}"
            f" {rec['score']:.3f}->{result.effective_score:.3f}"
            f" {'BLOCK' if was else 'pass '}->{'BLOCK' if now else 'pass '}"
            f"  {result.location} {result.excerpt[:60]!r}"
        )

    print(f"\nblocked: {before} before, {after} after ({flips} flipped) of {len(unique)}")
    if confusion["labelled"]:
        print(
            f"labelled: {confusion['labelled']}, false positives {confusion['fp']},"
            f" false negatives {confusion['fn']}"
        )
    return 0


def tally(confusion: dict[str, int], label: str | None, blocked: bool) -> None:
    if label not in {"attack", "benign"}:
        return
    confusion["labelled"] += 1
    if label == "benign" and blocked:
        confusion["fp"] += 1
    if label == "attack" and not blocked:
        confusion["fn"] += 1


if __name__ == "__main__":
    sys.exit(main())
