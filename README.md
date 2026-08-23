# llmprotect — guardrail gateway for homelab LLM traffic

OpenAI-compatible proxy in front of OpenRouter. Every prompt is scanned before
it leaves the network, every response is scanned on the way back.

```
client ──> LiteLLM :4000 ──┬─ pre_call:  Presidio  — mask PII + secrets (egress)
                           ├─ pre_call:  guard     — block prompt injection
                           │                          (PIGuard classifier sidecar)
                           ├──────────────────────> OpenRouter
                           └─ post_call: Presidio  — scan/mask response PII
```

All components are free, self-hosted, and actively maintained (the previous
LLM Guard-based iteration was scrapped — that project is archived/unmaintained;
see `docs/guardrails.md` for the full rationale and coverage matrix).

| Service | Image | Exposed |
|---|---|---|
| LiteLLM proxy + Admin UI | `ghcr.io/berriai/litellm:v1.96.0` | **:4000** (only public port) |
| Injection classifier | built from `Dockerfile` (Chainguard python, FastAPI + PIGuard) | internal |
| Presidio analyzer/anonymizer | `mcr.microsoft.com/presidio-*:2.2.362` | internal |
| Postgres (UI, keys, spend) | `postgres:18` | internal |

## Setup

1. ```bash
   cp .env.example .env    # then fill in OPENROUTER_API_KEY + LITELLM_MASTER_KEY
   ```
2. ```bash
   docker compose up -d --build
   ```
   First boot downloads the classifier model (~700 MB) into the `hf-cache`
   volume; the guard healthcheck allows up to 10 minutes. Watch with
   `docker compose logs -f guard`. LiteLLM starts only after every dependency
   is healthy.
3. Admin UI: <http://localhost:4000/ui> — login `admin` / your
   `LITELLM_MASTER_KEY`. All three guardrails appear under Guardrails.

## Test (spends zero OpenRouter tokens)

```bash
scripts/test-guardrails.sh
```

Uses the `guardrail-test` mock model: the full guardrail chain runs, but the
upstream call is stubbed. Verifies injection blocking and exercises PII/secrets
masking (masked values visible in the UI request logs).

## Using it from your apps

`config/litellm-config.yaml` defines an `openrouter/*` wildcard route, so any
OpenRouter model id works as-is with an `openrouter/` prefix — no per-model
setup. Mint a virtual key per app (Admin UI → Virtual Keys, or
`POST /key/generate` with the master key; restrict `models` / set a budget
there), then configure the app like any OpenAI-compatible endpoint:

```bash
OPENAI_BASE_URL=https://<host>/v1          # :4000 behind your TLS reverse proxy
OPENAI_API_KEY=sk-<virtual key for this app>
# model: openrouter/anthropic/claude-sonnet-4.5
```

Optional friendly aliases (e.g. `sonnet` → a specific OpenRouter model) are
managed in the Admin UI (Models page) and stored in Postgres — set the API key
field to `os.environ/OPENROUTER_API_KEY` so the credential stays out of the
DB. Guardrails stay version-controlled in `config/litellm-config.yaml`
(deliberately not UI-editable). If you front LiteLLM with a reverse proxy,
disable response buffering so streaming works.

## Tuning

- **Why was this blocked?** — the LiteLLM error message names the offending
  chunk and quotes a short (Presidio-masked) excerpt; set
  `GUARD_BLOCK_DETAIL=0` in `.env` to keep prompt excerpts out of the spend
  table and guard logs. Every scan is also logged with its score:
  `docker compose logs guard | grep scored`. To reproduce offline, run
  `scripts/score.py` against the text or `.eml` (see the script header; it
  needs the `ml` dependency group in a throwaway venv). Details and known
  false-positive triggers are in `docs/guardrails.md`.
- **Injection sensitivity** — `GUARD_THRESHOLD` in `.env` (default `0.85`;
  raise for fewer false positives). Restart with `docker compose restart guard litellm`.
  Note that confident false positives score 0.99+, so the threshold cannot fix
  them — fix the input (see `docs/guardrails.md`) or swap the model.
- **Scan windows** — `GUARD_CHUNK_CHARS`/`GUARD_CHUNK_OVERLAP` (2000/200),
  `GUARD_CHUNK_SNAP` (200; window starts snap to a line/sentence/word
  boundary, `0` = fixed windows), `GUARD_MARGIN` (0; opt-in re-score of
  marginal hits in a wider window — measured to let attacks through, see
  `docs/guardrails.md`). Smaller windows catch buried attacks far better,
  but only after client apps keep their own instructions in the `system`
  message rather than the scanned `user` message.
- **PII entities / MASK vs BLOCK** — `pii_entities_config` in
  `config/litellm-config.yaml`.
- **Secrets patterns** — `config/presidio_recognizers.json` (regex ad-hoc
  recognizers, includes the custom `US_SSN` fix — the stock recognizer is dead).
- **Swap classifier model** — `GUARD_MODEL_ID`/`GUARD_MODEL_REVISION` in `.env`
  (e.g. `meta-llama/Llama-Prompt-Guard-2-86M` + `HF_TOKEN` for the gated Meta
  model). Label handling is model-agnostic (`BENIGN_LABELS` in
  `src/guard_api/classifier.py`).

## Development (sidecar)

```bash
uv sync --frozen          # dev env (no ML stack — that's the `ml` group)
uv run ruff check .
uv run pytest --cov
```

Tests stub the classifier — the ML dependency group (`torch`, `transformers`)
is only installed inside the Docker image (`uv sync --group ml`). The
acceptance tests against the real model (`tests/test_ml_integration.py`,
marker `ml`) are skipped unless run from a throwaway ML env (see the header
of `scripts/score.py`); they print the score table kept in `docs/guardrails.md`. Dependencies
use range floors in `pyproject.toml` with `uv.lock` for reproducibility;
Renovate maintains the lock and keeps the Chainguard builder/runtime images in
lockstep (see `renovate.json`).

## Environment variables

See `.env.example`. Required: `OPENROUTER_API_KEY`, `LITELLM_MASTER_KEY`,
`LITELLM_SALT_KEY` (set before adding models in the UI; never rotate),
`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`. Optional:
`GUARD_MODEL_ID`, `GUARD_MODEL_REVISION`, `GUARD_TRUST_REMOTE_CODE`,
`GUARD_THRESHOLD`, `GUARD_BLOCK_DETAIL`, `GUARD_CHUNK_CHARS`,
`GUARD_CHUNK_OVERLAP`, `GUARD_CHUNK_SNAP`, `GUARD_MARGIN`, `HF_TOKEN`.

## Limitations (read before trusting it)

- Injection classifiers catch known attack patterns; they are bypassable under
  adversarial pressure. This is one layer — keep least-privilege on anything
  agentic behind the proxy.
- `post_call` response scanning applies to complete responses; streaming
  responses are scanned via LiteLLM's unified guardrail translation but
  chunk-level behavior varies by release.
- PIGuard loads with `trust_remote_code=True`; the model revision is pinned to
  an exact commit so upstream cannot change the executed code silently.
