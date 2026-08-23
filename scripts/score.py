#!/usr/bin/env python
"""Explain a guard decision: score a text file or .eml through the classifier
and print per-chunk risk, so you can see WHICH part of an input trips it.

Needs the ML dependency group, which is deliberately NOT in the dev venv.
Build a throwaway env outside the repo and run with it:

    UV_PROJECT_ENVIRONMENT=/tmp/llmprotect-ml uv sync --frozen --group ml
    /tmp/llmprotect-ml/bin/python scripts/score.py blocked.eml
    /tmp/llmprotect-ml/bin/python scripts/score.py prompt.txt --threshold 0.85
    echo "some text" | /tmp/llmprotect-ml/bin/python scripts/score.py -

For an .eml, several views are scored: the text/plain part, text extracted
from the HTML part, and each of those with URLs reduced to their host (the
normalization recommended for email-classifier clients, see
docs/guardrails.md). Pass --model/--revision to compare another classifier
(e.g. meta-llama/Llama-Prompt-Guard-2-86M, gated: needs HF_TOKEN).
"""

from __future__ import annotations

import argparse
import email
import html
import os
import re
import sys
from email import policy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guard_api.classifier import BENIGN_LABELS, chunk_text  # noqa: E402

URL_RE = re.compile(r"https?://([^/\s)>\]]+)[^\s)>\]]*")


def html_to_text(raw: str) -> str:
    raw = re.sub(r"(?is)<(style|script).*?</\1>", " ", raw)
    raw = re.sub(r"(?s)<!--.*?-->", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", raw)
    raw = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"[ \t]+", " ", html.unescape(raw)).strip()


def strip_urls(text: str) -> str:
    """Reduce every URL to scheme + host — drops tracking tokens."""
    return URL_RE.sub(r"https://\1", text)


def load_views(source: str) -> dict[str, str]:
    if source == "-":
        return {"stdin": sys.stdin.read()}
    path = Path(source)
    if path.suffix.lower() != ".eml":
        return {path.name: path.read_text(errors="replace")}

    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    views: dict[str, str] = {"subject": msg.get("subject", "")}
    plain = msg.get_body(preferencelist=("plain",))
    if plain is not None:
        text = plain.get_content()
        views["text/plain"] = text
        views["text/plain, urls->host"] = strip_urls(text)
    part = msg.get_body(preferencelist=("html",))
    if part is not None:
        text = html_to_text(part.get_content())
        views["text/html -> text"] = text
        views["text/html -> text, urls->host"] = strip_urls(text)
    return views


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", help="text file, .eml file, or - for stdin")
    parser.add_argument("--model", default=os.environ.get("GUARD_MODEL_ID", "leolee99/PIGuard"))
    parser.add_argument(
        "--revision",
        default=os.environ.get("GUARD_MODEL_REVISION", "dd78b24e330193a22d2293ac66922dd4f982f563"),
        help="pass '' for the default branch (e.g. when switching --model)",
    )
    parser.add_argument("--threshold", type=float, default=0.85)
    parser.add_argument("--chunk-chars", type=int, default=2000)
    parser.add_argument("--chunk-overlap", type=int, default=200)
    args = parser.parse_args()

    from transformers import pipeline  # heavy import, deferred

    pipe = pipeline(
        "text-classification",
        model=args.model,
        revision=args.revision or None,
        trust_remote_code=os.environ.get("GUARD_TRUST_REMOTE_CODE", "1") == "1",
        device="cpu",
        top_k=None,
        truncation=True,
    )

    print(f"model={args.model} revision={args.revision or 'default'} threshold={args.threshold}")
    any_blocked = False
    for name, text in load_views(args.source).items():
        chunks = chunk_text(text, args.chunk_chars, args.chunk_overlap) if text.strip() else []
        results = pipe(chunks) if chunks else []
        if results and isinstance(results[0], dict):
            results = [results]
        worst = max(
            (
                float(s["score"])
                for scores in results
                for s in scores
                if s["label"].lower() not in BENIGN_LABELS
            ),
            default=0.0,
        )
        verdict = "BLOCKED" if worst >= args.threshold else "pass"
        any_blocked |= verdict == "BLOCKED"
        print(f"\n== {name}: risk={worst:.3f} {verdict}  (len={len(text)}, chunks={len(chunks)})")
        for i, (chunk, scores) in enumerate(zip(chunks, results, strict=True)):
            risk = max(
                (float(s["score"]) for s in scores if s["label"].lower() not in BENIGN_LABELS),
                default=0.0,
            )
            flag = "<<" if risk >= args.threshold else "  "
            preview = " ".join(chunk.split())[:100]
            print(f"  {flag} chunk {i + 1}/{len(chunks)} risk={risk:.3f}  {preview!r}")
    return 1 if any_blocked else 0


if __name__ == "__main__":
    sys.exit(main())
