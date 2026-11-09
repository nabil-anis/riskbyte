# Riskbyte: self-hosted SOC agent

Riskbyte ingests telemetry inside your network, detects threats with Sigma-style rules, investigates each alert
with a local LLM, and proposes response actions that an analyst approves. Nothing leaves your environment.

```
sources -> ingest/normalize -> event store -> detection engine -> alert + case -> triage agent (local LLM)
                                                                                     |
                                       audit trail (hash-chained) <- analyst approval gate -> response actions
```

## Quick start (local, no Docker)

```bash
pip install -r requirements.txt
export RISKBYTE_DEV_MODE=1            # dev tokens + license bypass. Never use in production.
python -m riskbyte serve              # console: http://localhost:8080  (token: dev-analyst)
python -m riskbyte demo               # in another shell: sends sample attacks
python -m unittest discover -s tests  # 32 tests
```

## Production (Docker)

```bash
cp .env.example .env                  # fill in three strong tokens
python tools/issue_license.py keygen --out keys/        # VENDOR side, once. Keep keys/vendor_private.pem offline.
cp keys/vendor_public.pem .
python tools/issue_license.py issue --key keys/vendor_private.pem --customer "Acme" --plan trial -o license.rbl
docker compose up -d
docker compose exec ollama ollama pull llama3.1:8b
```
Put a TLS reverse proxy (Caddy, nginx, Traefik) in front of port 8080. The built-in server speaks plain HTTP.

## Choosing the triage model

| Provider | Set | Where data goes |
|---|---|---|
| none (default) | nothing | Stays local. Heuristic scoring only. |
| `ollama` | `RISKBYTE_LLM_PROVIDER=ollama`, `RISKBYTE_LLM_URL` | Stays local. |
| `openai` | `RISKBYTE_LLM_PROVIDER=openai`, `RISKBYTE_LLM_API_KEY` | Alert context is sent to OpenAI. |
| `gemini` | `RISKBYTE_LLM_PROVIDER=gemini`, `RISKBYTE_LLM_API_KEY` | Alert context is sent to Google. |

Cloud providers break the "nothing leaves your network" promise for the alert context sent to the model, so use them
knowingly. Mitigations built in: hostnames, usernames and private IPs are replaced with stable pseudonyms before sending
(and mapped back in what the analyst sees); only the alert and up to 10 events are sent, never the whole store; the key is
read from the environment or a `*_FILE` secret, goes in an HTTP header (never a URL), and is never logged or stored.
Redaction is not perfect: command lines and messages are kept, with known entity names masked inside them, so secrets that
appear in free text can still be sent. Check your provider's data-retention terms and consider a zero-retention agreement
before using real production logs. Cloud URLs must be `https://`. If the API fails or returns bad output, triage falls back
to the local heuristic. Put a spending cap on the key in the provider's dashboard.

## Sending data

- HTTP: `POST /api/ingest` with `Authorization: Bearer <ingest token>`, body = one event, a list, or `{"events":[...]}`.
- Syslog: UDP 5514 (RFC 3164 style; SSH login events are parsed natively).

## What is in this build (plan sprints 1 to 8, MVP scope)

| Plan epic | Status | Where |
|---|---|---|
| E1 Platform foundation | Done: config, Docker, CI, role tokens | `config.py`, `Dockerfile`, `.github/` |
| E2 Ingestion | Done: HTTP + syslog, normalization, retention purge | `ingest.py`, `service.py` |
| E3 Detection | Done: field rules, `any_of`, thresholds, 5 sample rules | `detect.py`, `rules/` |
| E4 Triage agent | Done: enrichment, correlation, Ollama client, validated output, heuristic fallback | `agent.py` |
| E5 Knowledge base | Partial: flat threat-intel list. Runbook retrieval not built | `intel/` |
| E6 Case management | Done (basic): auto-grouped cases, hash-chained audit | `service.py`, `db.py` |
| E7 Response + approval | Done: approval gate, dry-run and signed webhook, guardrails | `response.py` |
| E8 Analyst console | Done (basic): alerts, detail, approve/dismiss, cases, audit | `ui/` |
| E9 Licensing | Done offline half: Ed25519 licenses, trial/grace/expiry, endpoint caps, issuing CLI | `licensing.py`, `tools/` |
| E10 / E11 | Not built: metrics, backup tooling, pen test, full docs | |

**Not built:** the vendor-side trial signup server, payment/billing integration, and the public website's backend.
`riskbyte.html` (the product page) is a front-end prototype only. To run trials, wire a signup form to a small
service that calls `licensing.issue()` and emails the license file.

## Security design

- Fail-closed config: refuses to start without strong tokens (unless dev mode).
- Three roles (ingest / analyst / admin), constant-time token comparison, strict CSP, no inline scripts.
- Log content is untrusted. The model gets it as quoted data, cannot pick actions or targets, and its JSON output is
  schema-validated. A threat-intel hit can never be argued down to "benign". Rules decide the action.
- Nothing executes without approval. Targets are validated; non-public IPs are never blocked; protected ranges are configurable.
- Audit trail is hash-chained; `/api/stats` reports `audit_intact`.

## Known limitations (read before relying on it)

- The OpenAI, Gemini and Ollama clients are tested against local mock servers that mimic their request and response
  formats. They have not been run against the live services from here; run one real alert through your chosen provider
  and evaluate triage quality on your own data before trusting verdicts. The heuristic fallback is deliberately conservative.
- SQLite and a single worker suit small to mid-size deployments. Larger volumes need Postgres and a real queue.
- Threshold state is in memory, so counts reset on restart.
- A customer with the source can remove license checks. Licensing here deters casual overuse; enforce the rest by contract.
- No TLS, SSO, per-user accounts or rate limiting yet. Use a reverse proxy and network controls.
