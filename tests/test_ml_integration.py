"""Acceptance tests against the real classifier (spec §6.5).

Skipped unless the `ml` dependency group is installed — build the throwaway
env described in scripts/score.py and run:

    UV_PROJECT_ENVIRONMENT=/tmp/llmprotect-ml uv sync --frozen --group ml
    /tmp/llmprotect-ml/bin/python -m pytest tests/test_ml_integration.py -m ml -s

`-s` shows the per-case score table that goes into docs/guardrails.md.
The model (pinned revision) is downloaded on first run.
"""

from __future__ import annotations

import copy
import email
import os
import re
from email import policy
from pathlib import Path

import pytest

from fixtures.build_cta import Case, benign_cases, probe_cases, wrap
from guard_api.classifier import InjectionClassifier

pytest.importorskip("transformers")
pytestmark = pytest.mark.ml

THRESHOLD = float(os.environ.get("GUARD_THRESHOLD", "0.85"))
FIXTURES = Path(__file__).parent / "fixtures"
URL_RE = re.compile(r"https?://([^/\s)>\]]+)[^\s)>\]]*")


class CountingPipe:
    def __init__(self, pipe) -> None:
        self.pipe = pipe
        self.calls = 0

    def __call__(self, texts):
        self.calls += 1
        return self.pipe(texts)


@pytest.fixture(scope="module")
def classifier() -> InjectionClassifier:
    clf = InjectionClassifier(
        model_id=os.environ.get("GUARD_MODEL_ID", "leolee99/PIGuard"),
        revision=os.environ.get("GUARD_MODEL_REVISION", "dd78b24e330193a22d2293ac66922dd4f982f563")
        or None,
        trust_remote_code=os.environ.get("GUARD_TRUST_REMOTE_CODE", "1") == "1",
    )
    clf._pipe = CountingPipe(clf._pipe)
    return clf


def variant(clf: InjectionClassifier, snap: int, margin: float) -> InjectionClassifier:
    """Same loaded model, different chunking/re-score settings."""
    other = copy.copy(clf)
    other._chunk_snap = snap
    other._margin = margin
    return other


def incident_content() -> str | None:
    """The real email as the client formats it (URLs normalised), if it was
    saved next to the fixtures (spec §5.1; gitignored — personal data)."""
    path = FIXTURES / "myeloma_cta.eml"
    if not path.exists():
        return None
    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    plain = msg.get_body(preferencelist=("plain",))
    if plain is None:
        return None
    body = URL_RE.sub(r"https://\1", plain.get_content())[:5000]
    return (
        f"Subject: {msg.get('subject', '')}\nFrom: {msg.get('from', '')}\n"
        f"Date: {msg.get('date', '')}\n\nBody:\n{body}"
    )


def _benign() -> list[Case]:
    notification = (FIXTURES / "github_actions_failure.txt").read_text()
    return benign_cases(github_notification=notification)


def _report(name: str, clf: InjectionClassifier, case: Case) -> float:
    result = clf.assess(case.text, THRESHOLD)
    verdict = "BLOCK" if result.blocks(THRESHOLD) else "pass "
    context = f" context={result.rescore:.3f}" if result.rescored else ""
    print(f"  {verdict} {name:<22} {case.id:<22} risk={result.score:.3f}{context}")
    return result.effective_score


@pytest.mark.parametrize("case", _benign(), ids=lambda c: c.id)
def test_benign_set_passes(classifier, case):
    print()
    _report("fixed windows", variant(classifier, 0, 0), case)
    _report("boundary-aware", variant(classifier, 200, 0), case)
    score = _report("boundary-aware+rescore", classifier, case)
    assert score < THRESHOLD


@pytest.mark.parametrize("case", probe_cases(), ids=lambda c: c.id)
def test_probe_set_blocks(classifier, case):
    print()
    score = _report("boundary-aware+rescore", classifier, case)
    assert score >= THRESHOLD


@pytest.fixture
def incident() -> str:
    content = incident_content()
    if content is None:
        pytest.skip("tests/fixtures/myeloma_cta.eml not present")
    return content


def test_incident_email_blocks_in_todays_client_layout(classifier, incident):
    """Documents the measured cause (2026-08-23): the block is driven by the
    client's own trailing instruction in the scanned user message, not by
    the email — so neither chunking change fixes it. Ablation in
    docs/guardrails.md."""
    print()
    wrapped = _report("wrapped (today)", classifier, Case("incident", wrap(incident)))
    assert wrapped >= THRESHOLD
    tail = wrap(incident).split("</email>")[0] + "</email>"
    assert _report("wrapped, no tail", classifier, Case("incident", tail)) < THRESHOLD


def test_incident_email_passes_with_instructions_in_system_role(classifier, incident):
    """What the guard scores once gmailclassifier sends its instructions as
    the (unscanned) system message and only the delimited email as user."""
    print()
    user_only = f"<email>\n{incident}\n</email>"
    assert _report("email only", classifier, Case("incident", user_only)) < THRESHOLD


@pytest.mark.parametrize("case", _benign() + probe_cases(), ids=lambda c: c.id)
def test_rescore_cost_bounded(classifier, case):
    pipe: CountingPipe = classifier._pipe
    before = pipe.calls
    classifier.assess(case.text, THRESHOLD)
    assert pipe.calls - before <= 2  # one batched chunk call + at most one re-score
