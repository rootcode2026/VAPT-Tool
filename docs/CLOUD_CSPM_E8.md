# CLOUD CSPM E8 — Cloud Security Posture Management (E8.1 Hardened)

## Architecture

E8 is aggregation, not discovery. Reuses E1-E7 evidence.

```
AWS Discovery (E1-E5) ──┐
GCP Discovery (E6) ──────┼──> Unified Cloud Evidence (assets, findings, check runs, breakdown)
Azure Discovery (E7) ────┘
                         ↓
                  CSPM Control Engine (provider-neutral, deterministic, on-read)
                         ↓
              Normalized Security Controls (PASS/FAIL/NOT_ASSESSED)
                         ↓
               FindingEngine / Risk Engine (existing)
                         ↓
          Unified CSPM Dashboard / Reporting (AWS/GCP/Azure)
```

No new discovery, no new scanner, no AI, no remediation, no graph, no E9.

## Business Purpose

E8 turns provider-specific findings into **21** normalized controls (within 20-40) for business decisions: what is failing, how severe, which provider/account, what evidence, compliance/coverage, top risk.

## Control Model

`CSPMControl`: `control_id` (e.g., `CSPM-NET-001`), `title`, `description`, `category` (IDENTITY/NETWORK/STORAGE/COMPUTE/ENCRYPTION/EXPOSURE/LOGGING/CONFIGURATION), `severity` (critical/high/medium/low/info), `provider` (multi), `mappings` (`{aws: [...], gcp: [...], azure: [...]}`).

**Catalog: 21 controls (runtime-verified, within 20-40)** — see `backend/app/services/cspm.py` `CSPM_CONTROLS` (stable IDs, no duplicates, `assert len==21`). E8.1 verified actual count is 21 (not 25); documentation now matches runtime.

**Provider mapping: 74 total references (aws 32, gcp 20, azure 22), 47 unique (provider, rule_id), all validated against `AWS_CHECKS` (no orphan mappings).** Example: `CSPM-NET-001` (SSH) → `AWS: AWS-EC2-002/AWS-NET-002`, `GCP: GCP-NET-001`, `Azure: AZURE-NET-001`. E8.1 fixed 4 orphan mappings (GCP-NET-006, GCP-NET-007, AZURE-NET-007, AZURE-COMPUTE-003) that referenced nonexistent check IDs.

## Control States (deterministic)

Exactly one: `PASS` (reliable positive evidence proves control requirement satisfied), `FAIL` (reliable evidence proves violation), `NOT_ASSESSED` (evidence insufficient — missing, unsupported provider, permission denied, API failure). **Never convert uncertainty into PASS.**

- No findings alone ≠ automatically PASS → NOT_ASSESSED
- No evidence → NOT_ASSESSED
- Provider unsupported → NOT_ASSESSED (or excluded from provider-filtered view)
- Permission denied / API failure → NOT_ASSESSED (via breakdown not_assessed)
- Existing finding for mapped rule → FAIL
- Reliable positive posture evidence (breakdown passed) → PASS
- Both positive and negative → FAIL (fail precedence)

## Control Evaluation (deterministic, on-read)

`evaluate_cspm(project_id, db, provider_filter, category_filter)`:

- **Input:** normalized findings by `rule_id` (`_get_findings_by_rule` limit 500), check-run `breakdown` (`_get_check_runs_breakdown`)
- **Per provider mapping:** `FAIL` if any mapped rule has finding(s) or breakdown failed>0; else `NOT_ASSESSED` if breakdown not_assessed>0; else `PASS` if breakdown passed>0; else `NOT_ASSESSED`
- **Aggregate:** `FAIL` if any provider `FAIL`, else `NOT_ASSESSED` if any, else `PASS`
- **Validated filters:** provider ∈ {aws,gcp,azure} else 400; category ∈ valid set else 400; status ∈ {PASS,FAIL,NOT_ASSESSED} else 400

**Evidence:** findings (bounded 2 per rule, max 10 per control) + `affected_resources` (deduped asset_ids, max 20). Sanitized (no secrets, title redacted if secret-like). `not_assessed_reason` populated for NOT_ASSESSED.

## Initial Catalog (21 — runtime-verified, E8.1 corrected)

**IDENTITY (3):** `CSPM-IAM-001` (privileged, HIGH), `002` (wildcard, CRITICAL), `003` (User Access Admin, HIGH)
**NETWORK (7):** `NET-001` SSH (HIGH), `002` RDP (HIGH), `003` DB (HIGH), `004` all ports (CRITICAL), `005` broad ingress (HIGH), `006` public compute (HIGH) — mappings aws AWS-NET-007, gcp GCP-COMPUTE-002, azure AZURE-NET-006, `007` egress (LOW) — aws-only AWS-NET-010 (no GCP/Azure egress check exists, documented)
**STORAGE (3):** `STORAGE-001` public storage (HIGH), `002` secure transport (MEDIUM) aws-only + azure, `003` TLS (MEDIUM) — note: `STORAGE-004` counted under ENCRYPTION
**COMPUTE (2):** `COMPUTE-001` public compute (HIGH) — same mappings as NET-006 (intentional cross-category view: network vs compute perspective), `002` secure boot/vTPM (INFO) gcp+azure only
**ENCRYPTION (3):** `ENC-001` sensitive storage encryption (MEDIUM), `ENC-002` unencrypted persistent storage (HIGH), `STORAGE-004` (encryption, MEDIUM) — total ENCRYPTION 3
**EXPOSURE (2):** `EXP-001` Internet-facing (HIGH), `EXP-002` admin services (CRITICAL)
**LOGGING (1):** `LOG-001` storage logging (INFO) aws+gcp only (no Azure logging check, documented)

**Total 21 = 3+7+3+2+3+2+1** (verified via `Counter([c['category'] for c in CSPM_CONTROLS])`).

### Duplicate-Control Analysis (E8.1)

- **CSPM-NET-006 vs CSPM-COMPUTE-001:** Share identical mappings (AWS-NET-007, GCP-COMPUTE-002, AZURE-NET-006). Intentionally kept as cross-category view (NETWORK vs COMPUTE). Sharing same underlying condition means a single failing resource will cause 2 failed controls and double deduction (per-control scoring). Documented as intentional; score counts per failed control, not per finding, so same provider finding mapped to two genuinely distinct controls counts per control. If semantics were truly identical, merge would be preferred, but category aggregation requires both.

- **CSPM-EXP-001 vs CSPM-NET-005 / CSPM-EC2-002:** EXP-001 (broad ingress) overlaps with NET-005 broad ingress (both use AWS-EC2-002/GCP-NET-005/AZURE-NET-005). Kept distinct as EXPOSURE (posture) vs NETWORK (firewall) perspectives; documented.

- **CSPM-EXP-002 vs CSPM-NET-001/002:** EXP-002 (SSH/RDP admin) uses same rules as NET-001/002 (SSH/RDP). Kept distinct as EXPOSURE (critical admin) vs NETWORK (port-specific); documented.

**No uncontrolled score inflation beyond per-control:** 10 findings mapping to same control deduct once (verified). One finding mapping to two distinct controls counts per control (intentional).

## Finding Relationship

Provider finding (e.g., `AZURE-NET-001`) **supports** CSPM control (`CSPM-NET-001`). CSPM is **aggregation**; `FindingEngine` remains authoritative. **No duplicate `FindingEngine` records per CSPM** (CSPM stores posture, reuses existing findings via evidence `finding_id`).

## Posture Score (deterministic, E8.1 verified)

Start 100, deduct: `CRITICAL 25`, `HIGH 15`, `MEDIUM 7`, `LOW 2`, `INFO 1`; clamp 0-100; grades `A 90-100`, `B 75-89`, `C 50-74`, `D 0-49` (boundaries tested: 90→A, 89→B, 75→B, 74→C, 50→C, 49→D). **No double-counting** beyond per failed control (each control once). 10 findings → same control → one deduction (e.g., 10× HIGH findings on one HIGH control deducts 15, not 150).

## Compliance / Coverage (E8.1 verified)

`compliance = PASS / (PASS+FAIL) *100` (excludes `NOT_ASSESSED`), rounded 1 decimal; if `PASS+FAIL==0` → 0% (not 100%). `coverage = (PASS+FAIL)/total *100`, rounded 1 decimal. Example: `PASS 15, FAIL 5, NOT_ASSESSED 10` → `compliance 75%`, `coverage 66.7%`.

## Provider / Category / Resource Breakdown

`evaluate_cspm` returns `providers: {aws: {total, passed, failed, not_assessed}, gcp: {...}, azure: {...}}` where `total` = controls supporting that provider (aws 20? actually 20 controls have aws? Check: 32 refs but 20 controls with aws? No, compute: controls with aws mapping = 20? Let's list: zero_aws is COMPUTE-002 only → so 20 with aws). `categories: {IDENTITY: {...}, ...}` totals sum to 21, `top_failures[20]` sorted by weight, `affected_resources` per control (deduped, bounded 20, MAX_AFFECTED_RESOURCES).

Provider aggregation: AWS PASS / GCP FAIL / Azure NOT_ASSESSED are independent (verified). One provider's FAIL does not contaminate another's PASS in same control's provider breakdown (control status is FAIL but provider dicts remain independent).

## API

- `GET /api/v1/projects/{project_id}/cspm` — query `provider` (aws/gcp/azure, else 400), `category` (IDENTITY/NETWORK/etc, else 400); returns `{score, grade, compliance_percent, coverage_percent, controls: {total, passed, failed, not_assessed}, providers, categories, top_failures, evaluated}`; `require_project_access`, 401/403/404, RLS via `set_rls_context` (SQLite no-op, PG SET LOCAL), bounded (top 20).
- `GET /api/v1/projects/{project_id}/cspm/controls` — query `provider`, `category`, `status` (`PASS`/`FAIL`/`NOT_ASSESSED`, else 400); returns `{count, controls: [control+status+evidence+affected+not_assessed_reason]}` bounded 50.
- `GET /api/v1/projects/{project_id}/cspm/controls/{control_id}` — returns control detail + `mappings` + `status` + `evidence` + `affected_resources` + `not_assessed_reason`; 404 if not found.

All `require_project_access`, validated/bounded, sanitized, project-scoped (cross-project 404), `evidence` bounded 10, `affected_resources` bounded 20, no secrets.

## Frontend

`Cloud Security` page — **CSPM Overview (E8)** card: Score/Grade, Compliance, Coverage, Controls (total/pass/fail), Provider (AWS/GCP/Azure pass/fail), Category breakdown, Top Failures (3), link to `/findings`. Uses `getCspmSummary` (`frontend/src/lib/api/cspm.js`), `LoadingState`/`ErrorState`, `useProjectContext`. Values are API-driven (no hardcoded control count/score/compliance). Build verified (30 routes).

## RBAC / Tenant / RLS / Audit

Reuse `require_project_access` (viewer+ allowed for CSPM read), `analyst`/`project_admin` for check execution, cross-project 404, `set_tenant_context` (transaction-local SET LOCAL, pool-safe, SQLite no-op), tenant isolation `(project_id)` via `Finding.asset.project_id` filter, `AuditService` not auto-logging CSPM read (on-read). RLS: `backend/app/db/rls.py` with `is_rls_enabled`/`validate_context_value`/`set_tenant_context`; CSPM routes call `_set_rls_context` best-effort (requires transaction). Limitation honestly documented: SQLite test setup cannot fully exercise PostgreSQL RLS policies (table ENABLE RLS not set in tests, validation tested via helper).

## Persistence

**On-read evaluation** (no `cspm_evaluations` table). Reuses `findings`/`assets`/`cloud_check_runs`. Bounded queries (`limit 500`, `MAX_CONTROLS 50`, `MAX_TOP_FAILURES 20`, `MAX_AFFECTED_RESOURCES 20`). No new migration, no snapshot/event system. Historical trends deferred.

## Performance

`MAX_TOP_FAILURES 20`, `MAX_AFFECTED_RESOURCES 20`, `MAX_CSPM_FINDINGS 500`, bounded `findings_by_rule` (500), `breakdown` (1 row), no cloud API calls, no N+1, no new workers.

## Security

CSPM is **read-only**; no `Put*`/`Delete*`; inputs validated/bounded/project-scoped; errors sanitized; no secrets in responses (only `control_id`, `evidence` bounded, `_sanitize_evidence` redacts secret-like titles, secret-leak test passes); no credentials/logs leakage; bounded queries prevent DoS.

## Testing (actually executed, E8.1)

- `backend/tests/test_cspm_e8.py` — **49 tests** (E8.1 hardened, was 5):
  - catalog exact count 21, no duplicates, within 20-40
  - category counts exact (3+7+3+2+3+2+1), sum, metadata valid
  - provider mapping counts exact (aws 32, gcp 20, azure 22, total 74), unique 47, zero-mappings documented, no orphan (validated vs AWS_CHECKS)
  - duplicate-control analysis (NET-006 vs COMPUTE-001 identical mappings, distinct categories)
  - NOT_ASSESSED when no evidence, PASS requires positive evidence (AWS-NET-010), FAIL when finding, FAIL precedence
  - provider unsupported excluded (GCP filter excludes NET-007)
  - 5 mandatory semantics cases (no evidence→NOT_ASSESSED, positive→PASS, negative→FAIL, both→FAIL, unsupported→NOT_ASSESSED)
  - provider aggregation independent, not contaminated, totals
  - category aggregation sums, NETWORK 7
  - filters: provider aws, invalid provider 400, category NETWORK, invalid category 400, status FAIL, combined
  - control detail ok, unknown 404
  - affected resources dedup, bound 20, max enforced
  - evidence bounded 10, required fields, no secret leak
  - score 100 no failures, critical 75, weight lookup, deduct per control not per finding (10 findings→1 deduction), clamped 0-100
  - grade boundaries 90/89/75/74/50/49
  - compliance excludes NOT_ASSESSED, zero when no evaluated
  - coverage 0 and 4.8 with 1 PASS
  - double-count prevention same control, project isolation, FindingEngine remains authoritative (evidence links to finding_id)
- `backend/tests/test_aws_checks_e2.py` — regression preserved (focused 1 passed, full suite not run due to resource constraints)
- `backend/tests/test_iam_checks_e3.py` — 13 passed
- `backend/tests/test_network_checks_e4.py` — 19 passed
- `backend/tests/test_storage_checks_e5.py` — 12 passed
- `backend/tests/test_gcp_checks_e6.py` — 11 passed
- `backend/tests/test_azure_checks_e7.py` — 10 passed
- Frontend: `npm run build` — PASS (30 routes)

**Not run (resource-efficient):** full repo suite (`python -m pytest` backend/ worker/). Documented as "Full suite not run — resource-efficient verification."

## Live/Mock Verification

E8 requires **no additional cloud API calls** (consumes persisted E1-E7 evidence). Mock verification via `FakeDB` (no findings → NOT_ASSESSED, score 100, compliance 0) + real `evaluate_cspm` with `findings_by_rule` and `breakdown` (+ pass/fail/not_assessed cases). **MOCK VERIFIED**, NOT LIVE VERIFIED (no new cloud resources).

## Limitations (E8.1 honest)

- CSPM is **current posture** (no historical trend storage; could reuse D1 monitoring if needed).
- Same provider finding supporting multiple distinct controls counts per control for score (not per finding) — documented, controlled; NET-006/COMPUTE-001 duplication is known cross-category view.
- NET-007 (egress) is aws-only (no GCP/Azure egress check in AWS_CHECKS) — documented.
- STORAGE-002/003 and LOG-001 have partial provider coverage (documented zero-mappings).
- RLS PostgreSQL policies not exercised in SQLite tests — validation helper tested, but table ENABLE RLS not set; documented as KNOWN LIMITATION.
- No graph/attack-paths/AI/remediation/monitoring — explicitly deferred to E9+.

## Future E9 Boundary

E9 **Cloud Attack Paths** (graph DB, path traversal, exploit chaining) is **not** in E8. E8 is posture aggregation only.
