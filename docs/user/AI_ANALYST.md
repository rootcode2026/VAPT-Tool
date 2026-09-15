# AI Security Analyst — G1 Foundation (Phase G)

> **Status:** G1 **COMPLETE / READY** — retrieval foundation + provider abstraction + bounded tenant-isolated context + evidence provenance. G2+ (investigation, explanations, attack reasoning, remediation, reports, conversational deeper) **DEFERRED**.

## G1 Objective

Establish the AI analyst **above** the deterministic security platform:

```
Existing platform data (PostgreSQL: findings/assets/scans/evidence)
        ↓
Trusted retrieval/context (bounded, sanitized, project-isolated)
        ↓
AI analyst (provider abstraction, mock default)
        ↓
Evidence-grounded response (answer + confidence + claims + evidence + limitations)
        ↓
User (SOC, org_admin, analyst, viewer)
```

AI **explains or reasons over** deterministic facts; it never becomes source of truth for vulnerability existence, severity/CVSS, asset identity, finding status, tenant ownership, authorization, or remediation completion.

## Architecture (G1)

- **Retrieval:** `backend/app/services/ai_context.py :: build_context` — structured retrieval first, no vector DB cluster. Caps `findings 20 / assets 10 / scans 5`, evidence 500/300, prompt 1500, output 2000, total 8k JSON. Sources: findings (tenant `Project.organization_id`, allowlisted `severity/status/scanner`), assets, scans. Each finding citation carries `id`, `scan_id`, `target_id`, `asset_id`, `scanner/source`, `evidence`, `severity/score`, `cve/cwe`, `created_at`, `confidence`; assets carry `id`, `asset_type`, `value`, `status`, `criticality`, `first/last_seen_at`; scans carry `profile/status/risk_score`.
- **Provider:** `backend/app/services/ai_provider.py` — `AIProvider` ABC, `MockAIProvider` (deterministic, bounded, mock-analyst, `[FINDING:id]`/`[ASSET:id]` citations), `OpenAIProvider` (compat `/chat/completions`, `AI_BASE_URL`, `AI_API_KEY` never committed), `local` → mock. `get_ai_provider()` respects `AI_ENABLED`. Replaceable without rewrite.
- **Orchestration:** `backend/app/services/ai_service.py` — sanitizes prompt (3–2000), neutralizes injection (`INJECTION_RE` → `[filtered]`), builds trusted boundary prompt, validates plan (`ALLOWED_OPERATIONS` 6, `ALLOWED_FILTERS` 5, limit ≤20), calls provider with timeout, validates output (answer ≥10 chars, `confidence` enum, `claims` evidence ∈ context, hallucinated refs stripped, final secret redaction).
- **API:** `backend/app/api/routes/ai.py` — 7 endpoints under `protected` (`get_current_user` + `set_rls_context`): `GET /status` (200 enabled/provider/model), `GET /usage` (project 20), `POST /conversations` (201, `require_project_access`), `GET /conversations` (paginated 50), `GET /conversations/{id}` (403 if not owner unless super_admin), `POST /conversations/{id}/messages` (201, saves user+assistant, `AI_RESPONSE_GENERATED`), `DELETE /conversations/{id}` (204), `POST /query`, `POST /findings/{id}/explain`, `POST /assets/{id}/investigate`. All 503 when `AI_ENABLED=false`, 400 short/invalid, 404 cross-tenant, 429 rate, 500 safe.
- **Persistence:** `backend/app/models/ai.py` + migration `h8a9b0c1d2e3` — `ai_conversations`, `ai_messages` (`sanitized_content`, `evidence_refs` JSONB), `ai_usage` (token counts). No vector tables.
- **Frontend:** `frontend/src/app/(app)/ai/page.jsx` — project-scoped, `PageHeader` AI Security Analyst, disabled banner `AI is disabled — set AI_ENABLED=true... Platform works normally`, conversations panel, quick queries, thread with `confidence` + `evidence` citations `[FINDING:id]`, disclaimer `AI is advisory; deterministic engines authoritative`.

## How to Use

1. Ensure `AI_ENABLED=true` in `.env` (default `false` — platform works without AI).
2. Optional: set `AI_PROVIDER=mock` (default, no key) or `openai` with `AI_API_KEY` + `AI_BASE_URL`.
3. Open **AI Analyst** in sidebar (requires project selection). Create conversation → ask question → receive evidence-grounded answer with citations.
4. Verify citations via linked finding/asset pages — AI never invents.

## Tenant / Project Isolation

Every retrieval filters `WHERE Project.organization_id == organization_id` and `require_project_access(project_id)`. `listConversations` filters `user_id` + `project_id`; `getConversation` denies foreign user (403) and foreign project (404). Tests verify org-A cannot read org-B, project-A cannot read project-B unless authorized.

## Evidence-First

Answers include provenance: `finding ID`, `asset ID`, `scan ID`, `scanner/source`, `evidence` (redacted), `severity/score`, `cve/cwe`, `created_at`, `confidence`. If platform has insufficient evidence, confidence is `low` and answer states `[no evidence]` + limitations `Mock provider — limited to supplied context...`.

## Resource Efficiency (Constraint)

G1 is intentionally lightweight: existing PostgreSQL, deterministic preprocessing, `mock-analyst` provider, no large model download, no GPU, no vector DB cluster, no batch embedding jobs, small fixtures (8 tests). Embedding/vector abstraction deferred until G2+ actually requires it; architecture allows later replacement.

## Security Controls

- Redaction: `[REDACTED]` for `password/secret/token/private key/bearer` in context and final answer.
- Injection: retrieved content treated as DATA, neutralized (`ignore previous instructions` → `[filtered]`), prompt sections labeled trusted vs untrusted.
- Bounds: records 20/10/5, evidence 500/300, prompt 1500, output 2000, total 8k.
- No autonomous exploitation, destructive pentest, payment, or AI-authoritative state mutation.

## Tests

`backend/tests/test_ai_analyst.py` — **8 passed**: disabled 503, tenant isolation, bounded sanitized query, injection, secret redaction, planner validation (allowlist + limit), no state mutation (finding status unchanged after query), cross-project blocked.

## Known Limitations (G1)

- Structured retrieval only — no semantic embeddings/vector search (deferred).
- Mock answers are templated and evidence-bound — not full LLM reasoning.
- Context limited to findings/assets/scans — relationships, attack paths, risk, monitoring, remediation, reports not yet enriched (G2+).
- No continuous learning, no feedback loop, no external intel.

## NOT in G1 (Deferred to G2+)

Do **not** expect: automated investigation workflows, attack reasoning graph, remediation generation/execution, report drafting, RAG over entire DB, vector DB cluster, continuous monitoring AI, autonomous exploitation, payment. See `docs/PROJECT_STATE.md` G1 row for deferred list.
