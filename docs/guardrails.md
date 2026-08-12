# Guardrail design, coverage, and history

## How we got here (so we stop re-learning this)

1. **LLM Guard (`laiyer/llm-guard-api`) — rejected twice.** First iteration
   (~May 2026) was scrapped because the project was already effectively dead.
   It was formally **archived on GitHub 2026-07-09** (read-only, HF models
   unmaintained). Its LiteLLM integration (`llmguard_moderations` callback) is
   Enterprise-only anyway. Do not reintroduce it.
2. **LiteLLM's built-in `detect_prompt_injection` callback — rejected.**
   It is a ~376-phrase fuzzy match on "ignore previous instructions" variants;
   misses indirect injection, obfuscation, non-English; its similarity/threshold
   params are no-ops. Security theater.
3. **Paid SaaS guardrails (Lakera, Aporia, etc.) — rejected** for homelab:
   sends prompt content to a third party and costs money.
4. **Current design:** Presidio (OSS, maintained, first-class in LiteLLM) for
   PII/secrets + a self-hosted classifier sidecar for injection, integrated via
   LiteLLM's `generic_guardrail_api` provider (OSS-tier, no custom plugin).

## Coverage matrix

| Risk | Guardrail | Mode | Action |
|---|---|---|---|
| PII leaving the network to OpenRouter | pii-egress-mask (Presidio) | pre_call | MASK (restored in response via output_parse_pii) |
| Secrets (AWS/GitHub/Slack/sk-/private keys) in prompts | pii-egress-mask + ad-hoc recognizers | pre_call | MASK |
| Direct prompt injection | prompt-injection (PIGuard sidecar) | pre_call | BLOCK at threshold (default 0.85) |
| Indirect injection via tool/RAG content | prompt-injection sidecar | pre_call | Scans `user`, `tool`, `function` roles |
| PII/secrets in model responses | pii-response-scan (Presidio) | post_call | MASK |
| Availability of the injection gate | `fail_on_error: true`, `unreachable_fallback: fail_closed` | — | Requests rejected if sidecar is down |

Not covered (deliberate): toxicity/content moderation (single-user homelab),
ban-topics, hallucination checks.

## Classifier model choice

Default: **`leolee99/PIGuard`** (ACL 2025) — DeBERTa-v3-base classifier,
non-gated, state-of-the-art on injection benchmarks while fixing the
over-defense/false-positive problem of older guard models (NotInject
benchmark). Labels: `benign` / `injection`.

- Requires `trust_remote_code=True` (custom `modeling_piguard.py`), so the
  **revision is pinned** to commit `dd78b24e330193a22d2293ac66922dd4f982f563`.
  Bumping the revision means re-reviewing the remote code.
- Alternative (gated): `meta-llama/Llama-Prompt-Guard-2-86M` — set
  `GUARD_MODEL_ID`, `HF_TOKEN`, and check labels against `BENIGN_LABELS`.
- Fallback (frozen but standard architecture, no remote code):
  `protectai/deberta-v3-base-prompt-injection-v2`.

Long inputs are scanned in ~2000-char sliding windows with 200-char overlap
(`GUARD_CHUNK_CHARS`/`GUARD_CHUNK_OVERLAP`) because DeBERTa truncates at 512
tokens — without chunking, an injection at the end of a pasted document would
never be seen.

## Known limitations

- **Classifiers are bypassable.** Published attacks (controlled-release
  prompting, paraphrase evasion) defeat all current prompt guards some of the
  time. This gate raises cost; it is not a boundary. Keep least-privilege on
  agents behind the proxy and treat output-side controls as equally important.
- **System prompts are not scanned** (by design, to avoid false positives on
  our own instructions). If a client app builds system prompts from untrusted
  content, that content bypasses the injection scan.
- **Streaming**: post_call scanning of streamed responses depends on LiteLLM's
  unified guardrail translation (works as of v1.96.0 for /v1/messages; verify
  after upgrades).
- **US_SSN**: the stock Presidio recognizer returns zero matches for every SSN
  format. The ad-hoc recognizer in `config/presidio_recognizers.json` is the
  real coverage — keep it when upgrading Presidio, and re-test.
- **Ad-hoc secrets regexes** are a curated list, not a full secrets engine
  (LiteLLM's `hide_secrets` is Enterprise-only). Extend
  `presidio_recognizers.json` as new token formats show up.

## Tuning knobs

- `GUARD_THRESHOLD` (default 0.85): raise toward 0.9+ if benign security-topic
  prompts get blocked; lower to catch more.
- Per-entity `MASK` → `BLOCK` in `config/litellm-config.yaml` for bank-grade
  posture on SSN/credit-card.
- Per-request bypass: guardrails support `guardrails: []` request metadata via
  LiteLLM key permissions — leave `default_on: true` and scope exceptions to
  virtual keys rather than turning anything off globally.
