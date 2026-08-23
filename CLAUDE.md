# llmprotect

## Overview
Guardrail gateway for homelab LLM traffic: LiteLLM proxy in front of
OpenRouter with three guardrails — Presidio PII/secrets masking on egress
(pre_call), a self-hosted prompt-injection classifier sidecar (pre_call, via
LiteLLM's Generic Guardrail API), and Presidio response scanning (post_call).
This replaces an earlier LLM Guard-based design; LLM Guard is archived and
must not be reintroduced (see docs/guardrails.md).

## Tech Stack
- Language: Python 3.14 (sidecar only; everything else is off-the-shelf images)
- Framework: FastAPI + transformers (PIGuard classifier, CPU inference)
- Packaging: uv (pyproject range floors + uv.lock; ML stack is the `ml`
  dependency group, Docker-image-only). Sidecar image: Chainguard python
  `:latest-dev` builder / `:latest` runtime, digest-pinned, kept in lockstep
  by a Renovate group rule (renovate.json) — never bump one without the other
- Gateway: LiteLLM `v1.96.0` (pinned; guardrails use the `guardrails:` config
  format — `presidio` and `generic_guardrail_api` providers only, both OSS-tier)
- PII: Microsoft Presidio 2.2.362 (analyzer + anonymizer containers)
- Database: Postgres 18 (LiteLLM UI/keys/spend; PGDATA parent-mount gotcha
  is handled in docker-compose.yml)

## Commands
- `docker compose up -d --build` — start the stack
- `scripts/test-guardrails.sh` — end-to-end guardrail smoke test (mock model,
  zero OpenRouter spend)
- `scripts/score.py <file|.eml|->` — explain a guard decision offline with
  per-chunk scores (needs the `ml` group in a throwaway venv outside `.venv`;
  see the script header)
- `scripts/bench-guard-models.py [marketing.eml]` — PIGuard vs Prompt Guard 2
  on the FP/FN probe sets; rerun before changing GUARD_MODEL_ID/REVISION
- `uv sync --frozen` — dev env (dev group only; ML group is Docker-only)
- `uv run pytest --cov` — sidecar tests (classifier is stubbed; 75% gate in CI)
- `uv run ruff check .` — lint

## Architecture
- `docker-compose.yml` — five services; only LiteLLM (:4000) is published
- `config/litellm-config.yaml` — guardrails + test-only mock model; real
  models are DB-stored and managed via the Admin UI (store_model_in_db)
- `config/presidio_recognizers.json` — ad-hoc regex recognizers: custom US_SSN
  (stock recognizer returns zero matches — do not remove), AWS/GitHub/Slack
  tokens, private-key blocks, generic sk- keys
- `src/guard_api/` — sidecar: `main.py` (Generic Guardrail API contract:
  POST /beta/litellm_basic_guardrail_api, actions NONE/BLOCKED),
  `classifier.py` (lazy ML imports so tests run without torch), `settings.py`
- `tests/` — contract tests with a stubbed classifier; never download models
  in tests
- Guard model is pinned by revision because it needs trust_remote_code;
  changing GUARD_MODEL_ID requires re-checking label semantics against
  BENIGN_LABELS in classifier.py, and re-running the measured FP/FN table in
  docs/guardrails.md
- Known PIGuard false positive: long tracking-URL query strings score ~1.0
  (every marketing email). Fix belongs in the client (normalise URLs to
  host), not in the sidecar — see docs/guardrails.md
- The stack is deployed on a separate homelab host; this checkout has no
  `.env` and no running containers

## Environment Variables
Required: OPENROUTER_API_KEY, LITELLM_MASTER_KEY, LITELLM_SALT_KEY (encrypts
DB-stored model credentials — set before first model is added, never rotate),
POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB.
Optional: GUARD_MODEL_ID, GUARD_MODEL_REVISION, GUARD_TRUST_REMOTE_CODE,
GUARD_THRESHOLD, GUARD_BLOCK_DETAIL, GUARD_CHUNK_CHARS, GUARD_CHUNK_OVERLAP,
HF_TOKEN.
