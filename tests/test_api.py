"""Contract tests for the Generic Guardrail API endpoint (stubbed classifier)."""

import pytest
from fastapi.testclient import TestClient

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
    """Scores 0.99 when the text contains INJECT, else 0.01."""

    def risk_score(self, text: str) -> float:
        return 0.99 if "INJECT" in text else 0.01


@pytest.fixture
def client():
    app = create_app(classifier=StubClassifier(), settings=SETTINGS)
    with TestClient(app) as test_client:
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
