"""FastAPI app implementing LiteLLM's Generic Guardrail API.

Contract (LiteLLM >= 1.96):
  POST /beta/litellm_basic_guardrail_api
  request:  {texts, structured_messages, input_type, additional_provider_specific_params, ...}
  response: {action: "BLOCKED"|"NONE"|"GUARDRAIL_INTERVENED", blocked_reason?, texts?}
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel, ConfigDict

from guard_api.settings import Settings, load_settings

logger = logging.getLogger("guard_api")

# Only these roles carry attacker-controllable content; scanning our own
# system prompts would just invite false positives.
SCANNED_ROLES = {"user", "tool", "function"}


class GuardrailRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    texts: list[str] | None = None
    structured_messages: list[dict[str, Any]] | None = None
    input_type: str = "request"
    additional_provider_specific_params: dict[str, Any] | None = None
    litellm_call_id: str | None = None


class GuardrailResponse(BaseModel):
    action: str
    blocked_reason: str | None = None
    texts: list[str] | None = None


def texts_to_scan(req: GuardrailRequest) -> list[str]:
    """Prefer structured messages (lets us skip system/assistant roles);
    fall back to the flat texts list."""
    if req.structured_messages:
        out: list[str] = []
        for message in req.structured_messages:
            if message.get("role") not in SCANNED_ROLES:
                continue
            content = message.get("content")
            if isinstance(content, str):
                out.append(content)
            elif isinstance(content, list):  # multimodal content parts
                out.extend(
                    part.get("text", "")
                    for part in content
                    if isinstance(part, dict) and part.get("type") == "text"
                )
        return out
    return req.texts or []


def create_app(classifier: Any = None, settings: Settings | None = None) -> FastAPI:
    """classifier is injectable for tests; None means load the real model
    during startup (so the container only turns healthy once it can score)."""
    app_settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.classifier is None:
            from guard_api.classifier import InjectionClassifier

            logger.info("loading model %s", app_settings.model_id)
            app.state.classifier = InjectionClassifier(
                model_id=app_settings.model_id,
                revision=app_settings.model_revision,
                trust_remote_code=app_settings.trust_remote_code,
                chunk_chars=app_settings.chunk_chars,
                chunk_overlap=app_settings.chunk_overlap,
            )
            logger.info("model loaded")
        yield

    app = FastAPI(title="llmprotect guard", lifespan=lifespan)
    app.state.classifier = classifier
    app.state.settings = app_settings

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "model": app_settings.model_id}

    @app.post("/beta/litellm_basic_guardrail_api", response_model_exclude_none=True)
    async def scan(req: GuardrailRequest, request: Request) -> GuardrailResponse:
        # Response-side content is scanned by the Presidio post_call guardrail;
        # an injection classifier has nothing to say about model output.
        if req.input_type == "response":
            return GuardrailResponse(action="NONE")

        threshold = app_settings.threshold
        extra = req.additional_provider_specific_params or {}
        if "threshold" in extra:
            threshold = float(extra["threshold"])

        for text in texts_to_scan(req):
            score = request.app.state.classifier.risk_score(text)
            if score >= threshold:
                logger.warning(
                    "blocked call_id=%s risk=%.3f threshold=%.2f",
                    req.litellm_call_id,
                    score,
                    threshold,
                )
                return GuardrailResponse(
                    action="BLOCKED",
                    blocked_reason=(
                        f"prompt injection detected (risk={score:.3f} >= threshold {threshold})"
                    ),
                )
        return GuardrailResponse(action="NONE")

    return app


app = create_app()
