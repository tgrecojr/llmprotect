"""Contract tests for the Generic Guardrail API endpoint (stubbed classifier)."""

import logging
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from guard_api.classifier import RiskResult
from guard_api.main import create_app
from guard_api.settings import Settings

SETTINGS = Settings(
    model_id="stub",
    model_revision=None,
    trust_remote_code=False,
    threshold=0.85,
    chunk_chars=2000,
    chunk_overlap=200,
)

ENDPOINT = "/beta/litellm_basic_guardrail_api"


class StubClassifier:
    """Scores 0.99 when the text contains INJECT, else 0.01. Reports the
    hit as chunk 2 of 3 so tests can check location plumbing. MARGINAL-CONFIRM
    / MARGINAL-CLEAR simulate a re-scored marginal hit that the wider
    context confirmed (0.91) or cleared (0.40)."""

    def __init__(self) -> None:
        self.thresholds: list[float] = []

    def assess(self, text: str, threshold: float | None = None) -> RiskResult:
        self.thresholds.append(threshold)
        if "INJECT" in text:
            return RiskResult(score=0.99, chunk_index=1, chunk_count=3, excerpt="INJECT payload")
        if "MARGINAL-CONFIRM" in text:
            return RiskResult(0.86, 1, 3, "cta copy", rescored=True, rescore=0.91)
        if "MARGINAL-CLEAR" in text:
            return RiskResult(0.86, 1, 3, "cta copy", rescored=True, rescore=0.40)
        return RiskResult(score=0.01, chunk_index=0, chunk_count=1, excerpt="")


def make_client(settings: Settings = SETTINGS) -> TestClient:
    return TestClient(create_app(classifier=StubClassifier(), settings=settings))


@pytest.fixture
def client():
    with make_client() as test_client:
        yield test_client


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_clean_prompt_passes(client):
    resp = client.post(ENDPOINT, json={"texts": ["write a haiku"], "input_type": "request"})
    assert resp.status_code == 200
    assert resp.json()["action"] == "NONE"


def test_injection_blocked(client):
    resp = client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "request"})
    body = resp.json()
    assert body["action"] == "BLOCKED"
    assert "prompt injection" in body["blocked_reason"]


def test_block_reason_includes_detail_by_default(client):
    resp = client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "request"})
    reason = resp.json()["blocked_reason"]
    assert reason == (
        "prompt injection detected (risk=0.990 >= threshold 0.85) in chunk 2/3: 'INJECT payload'"
    )


def test_block_reason_omits_detail_when_disabled():
    with make_client(replace(SETTINGS, block_detail=False)) as client:
        resp = client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "request"})
    reason = resp.json()["blocked_reason"]
    assert reason == "prompt injection detected (risk=0.990 >= threshold 0.85)"


def test_every_text_is_score_logged(client, caplog):
    with caplog.at_level(logging.INFO, logger="guard_api"):
        client.post(
            ENDPOINT,
            json={"texts": ["fine", "also fine"], "input_type": "request", "litellm_call_id": "c1"},
        )
    scored = [r for r in caplog.records if r.getMessage().startswith("scored call_id=c1")]
    assert len(scored) == 2
    assert "risk=0.010" in scored[0].getMessage()


def test_block_log_carries_excerpt_by_default(client, caplog):
    with caplog.at_level(logging.WARNING, logger="guard_api"):
        client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "request"})
    blocked = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(blocked) == 1
    assert "chunk 2/3" in blocked[0]
    assert "excerpt='INJECT payload'" in blocked[0]


def test_block_log_hides_excerpt_when_disabled(caplog):
    with (
        make_client(replace(SETTINGS, block_detail=False)) as client,
        caplog.at_level(logging.WARNING, logger="guard_api"),
    ):
        client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "request"})
    blocked = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(blocked) == 1
    assert "chunk 2/3" in blocked[0]
    assert "excerpt='<off>'" in blocked[0]
    assert "INJECT" not in blocked[0]


def test_response_side_is_passthrough(client):
    resp = client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "response"})
    assert resp.json()["action"] == "NONE"


def test_system_messages_not_scanned(client):
    resp = client.post(
        ENDPOINT,
        json={
            "structured_messages": [
                {"role": "system", "content": "INJECT-looking system prompt"},
                {"role": "user", "content": "harmless question"},
            ],
            "input_type": "request",
        },
    )
    assert resp.json()["action"] == "NONE"


def test_user_message_in_structured_messages_blocked(client):
    resp = client.post(
        ENDPOINT,
        json={
            "structured_messages": [{"role": "user", "content": "INJECT payload"}],
            "input_type": "request",
        },
    )
    assert resp.json()["action"] == "BLOCKED"


def test_multimodal_text_parts_scanned(client):
    resp = client.post(
        ENDPOINT,
        json={
            "structured_messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "INJECT payload"},
                        {"type": "image_url", "image_url": {"url": "data:..."}},
                    ],
                }
            ],
            "input_type": "request",
        },
    )
    assert resp.json()["action"] == "BLOCKED"


def test_threshold_override_via_provider_params(client):
    resp = client.post(
        ENDPOINT,
        json={
            "texts": ["harmless"],
            "input_type": "request",
            "additional_provider_specific_params": {"threshold": 0.005},
        },
    )
    assert resp.json()["action"] == "BLOCKED"


def test_threshold_is_passed_to_classifier():
    app = create_app(classifier=StubClassifier(), settings=SETTINGS)
    with TestClient(app) as client:
        client.post(ENDPOINT, json={"texts": ["a"], "input_type": "request"})
        client.post(
            ENDPOINT,
            json={
                "texts": ["b"],
                "input_type": "request",
                "additional_provider_specific_params": {"threshold": 0.5},
            },
        )
    assert app.state.classifier.thresholds == [0.85, 0.5]


# --- marginal re-score plumbing (spec §6.4) ----------------------------------


def test_blocked_reason_includes_context_score_when_rescored(client):
    resp = client.post(ENDPOINT, json={"texts": ["MARGINAL-CONFIRM"], "input_type": "request"})
    body = resp.json()
    assert body["action"] == "BLOCKED"
    assert body["blocked_reason"] == (
        "prompt injection detected (risk=0.860 (context 0.910) >= threshold 0.85)"
        " in chunk 2/3: 'cta copy'"
    )


def test_rescored_block_log_carries_context(client, caplog):
    with caplog.at_level(logging.WARNING, logger="guard_api"):
        client.post(ENDPOINT, json={"texts": ["MARGINAL-CONFIRM"], "input_type": "request"})
    blocked = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(blocked) == 1
    assert "risk=0.860 (context 0.910)" in blocked[0]


def test_rescored_pass_logs_scored_not_blocked(client, caplog):
    with caplog.at_level(logging.INFO, logger="guard_api"):
        resp = client.post(
            ENDPOINT,
            json={"texts": ["MARGINAL-CLEAR"], "input_type": "request", "litellm_call_id": "c2"},
        )
    assert resp.json()["action"] == "NONE"
    messages = [r.getMessage() for r in caplog.records]
    scored = [m for m in messages if m.startswith("scored call_id=c2")]
    assert len(scored) == 1
    assert "risk=0.860 context=0.400 threshold=0.85 chunks=3" in scored[0]
    assert not any(m.startswith("blocked") for m in messages)


def test_none_when_below_threshold_unchanged(client, caplog):
    with caplog.at_level(logging.INFO, logger="guard_api"):
        resp = client.post(
            ENDPOINT, json={"texts": ["fine"], "input_type": "request", "litellm_call_id": "c3"}
        )
    assert resp.json()["action"] == "NONE"
    scored = [r.getMessage() for r in caplog.records if r.getMessage().startswith("scored")]
    assert scored == ["scored call_id=c3 text=0 risk=0.010 threshold=0.85 chunks=1"]


def test_unknown_fields_ignored(client):
    resp = client.post(
        ENDPOINT,
        json={
            "texts": ["hello"],
            "input_type": "request",
            "litellm_trace_id": "t-1",
            "request_headers": {"User-Agent": "x"},
        },
    )
    assert resp.status_code == 200
