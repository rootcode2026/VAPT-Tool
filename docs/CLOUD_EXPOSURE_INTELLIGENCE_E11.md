# CLOUD EXPOSURE INTELLIGENCE E11 — Risk & Exposure Prioritization

## Business Objective

E8: What controls are failing?
E9: Which cloud exposures form meaningful attack paths?
E10: How have those paths changed over time?
E11: **WHAT SHOULD WE FIX FIRST?**

E11 creates a single, explainable *Cloud Exposure Priority* layer that tells a security team—analyst, manager, engineer, executive—which exposures to fix first, exposing the distinction between isolated low-severity findings and `internet exposure + privileged identity + critical resource + persistent attack path`.

Not a generic vulnerability dashboard. Differentiation: `FINDINGS + CSPM + ATTACK PATHS + HISTORICAL PERSISTENCE + ASSET CONTEXT = EXPOSURE PRIORITY`.

## Differentiation & Principle

- `Finding severity != exposure risk`
- `CSPM score != attack-path priority`

E11 **correlates** existing signals rather than redisplaying them. Reuses FindingEngine, RiskAssessmentEngine, CSPM, CloudAttackPath, CloudAttackPathHistory, Asset Intelligence, D2 changes, remediation/SLA where available. Does **not** create a second vulnerability scoring system that contradicts RiskAssessmentEngine — it **consumes** existing scores.

No LLM, no embeddings, no probabilistic black boxes. Deterministic, bounded.

## Exposure Model

Primary unit: **Exposure** — a meaningful security risk centered on asset/finding/CSPM failure/attack path. Types:

- `ATTACK_PATH_EXPOSURE` (preferred when path exists — fingerprints reused)
- `FINDING_EXPOSURE` (isolated high/critical finding without path)
- `CSPM_EXPOSURE` (failed CSPM control without path, limited to 5)
- `ASSET_EXPOSURE` (deferred; not used in E11 primary)

Each exposure has deterministic `exposure_id = sha256(project|type|primary_asset|fingerprint)[:32]`. Prevents duplicate entries: one condition does not produce exposures per finding, per CSPM mapping, per node.

## Correlation (deterministic)

For each cloud resource (`cloud_resource` assets, bounded 500 findings, 500 assets, 100 paths, 100 history rows):

- Collect cloud findings (max severity)
- CSPM failures (from `evaluate_cspm`)
- Attack paths (from `build_cloud_attack_paths`)
- History (from `cloud_attack_paths` table: `first_seen_at`, `last_seen_at`, `resolved_at`, reopen)
- Asset relationships (via adjacency)
- Remediation state (`Finding.status == "open"`)
- SLA/ownership where available (currently via `status`; no fabricated business owner)

Example: internet-facing EC2 + SSH exposed + high vuln + privileged IAM + active attack path persisted 30 days → ranks above isolated low config issue.

No fabricated business impact; technical impact only (exposure, privilege, resource type, severity, path priority, persistence). Clearly distinct.

## Attack Path Priority (reuse E9)

E9 already calculates `priority_score` (0-100), `severity`, `confidence`. E11 **reuses** those values and applies a bounded contribution (`path_priority *0.3` → 0-30). No second attack-path score. Historical adjustment via persistence/recurrence only, documented.

## Historical Risk (reuse E10)

For each path fingerprint, history provides:
- `first_seen_at`, `last_seen_at`, `resolved_at`
- persistence `days = (last - first).days`
- reopen = true if `first != last` and path is ACTIVE with persistence>1
- repeated occurrence via observation count

Persistence factor: `min(days/7*5,5)` (bounded 5). Reopened: +5. Duration does not dominate severity.

## Remediation & SLA Context

Reuse D7: `Finding.status` (`OPEN`, `IN_PROGRESS`, `BLOCKED`, `RESOLVED` via `workflow_status`) and `status=="open"` as `UNREMEDIATED` factor (+5). Do not auto-remediate, do not mark resolved automatically — prioritization only.

Reuse SLA if available via `Finding` metadata; currently via `status` and severity. SLA breach (+5 bounded) only if `UNREMEDIATED` and critical/high. Does not override technical exposure.

## Asset Context

Reuse Asset Intelligence: `asset_type`, `provider` (from `value` prefix), `public`/`exposure`, `resource_type`, relationships, affected count. No invented business owner/production status/data classification.

## Risk Model & Score Design

Deterministic **Cloud Exposure Priority** 0-100:

```
Finding severity       0-20  (critical 20, high 15, medium 10, low 5, info 0)
Attack path priority   0-30  (path_score *0.3)
External exposure      0/15  (internet_exposed →15)
Privilege impact       0/10  (privileged finding →10)
Target sensitivity     0/10  (sensitive type →10)
Persistence            0-5   (days/7*5 capped)
Recurrence             0/5   (reopened →5)
Remediation/SLA        0/5   (unremediated critical/high →5)
Total max 100
```

If input unavailable → neutral 0, recorded as missing factor (not fabricated). Avoid double-counting: one path’s ten findings use **max** severity, not sum; same CSPM+finding condition not double counted as independent.

Exact formula implemented in `cloud_exposure_intelligence.py:_exposure_score`.

## Risk Factors (small taxonomy)

- `EXTERNAL_EXPOSURE`
- `CRITICAL_FINDING`
- `HIGH_FINDING`
- `PRIVILEGED_IDENTITY`
- `SENSITIVE_TARGET`
- `ACTIVE_ATTACK_PATH`
- `PERSISTENT_ATTACK_PATH`
- `REOPENED_ATTACK_PATH`
- `UNREMEDIATED`
- `SLA_BREACH` (future, currently via UNREMEDIATED)
- `RECENTLY_CREATED` / `RECURRING_EXPOSURE` (via reopened)

Each exposure’s `risk_factors` sorted, explainable.

## Score Stability & Tiers

Same evidence → same score (no randomness, timestamp not direct input, deterministic sort). Tested via `_exposure_score` deterministic.

Tiers (same as E9):
- `CRITICAL >=85`
- `HIGH >=70`
- `MEDIUM >=40`
- `LOW <40`

Project risk grade maps same tiers (A low risk 0-39, B 40-69, C 70-84, D 85-100).

## Deduplication

Canonical `exposure_id = sha256(project|type|primary_asset|fingerprint)`. For `ATTACK_PATH_EXPOSURE`: per fingerprint; for `FINDING_EXPOSURE`: per asset (grouped findings_by_asset, one exposure per asset, max severity, not per finding). CSPM per `control_id`. Reuses fingerprints.

## Top Risks & Concentration

Project-level ranked list `Top Cloud Exposures` (max 20, bounded evidence 20):

- `exposure_id`, `project_id`, `provider`, `exposure_type`, `asset_id`, `asset_type`, `title`, `priority_score`, `severity`, `confidence`, `risk_factors`, `finding_ids` (≤10), `attack_path_ids` (≤1), `cspm_control_ids` (≤1), `first_seen`, `last_seen`, `remediation_state`, `owner` (none), `SLA state` (none), `explanation` (deterministic template), `evidence`.

Concentration:
- Risk by provider: `aws/gcp/azure/multi`
- Risk by resource type (via `asset_type`)
- Risk by exposure type
- Risk by severity

Bounded, not arbitrary analytics.

## Risk Trends (reuse E10)

Lightweight, bounded windows 7/30/90 days:
- `active` exposure count
- `critical`/`high` count
- `newly created` (`first_seen_at >= since`)
- `resolved`/`reopened` (via `cloud_attack_paths` status/resolved)
via indexed queries, no full historical scan.

## API

Project-scoped, bounded, `require_project_access` + `set_rls_context`, 401 unauth, 404 cross-project, 400 invalid.

- `GET /api/v1/projects/{project_id}/cloud-security/exposure-intelligence` → `{score, grade, critical, high, medium, low, total, top_exposures (20), providers, exposure_types, trends {7d,30d,90d: {new,resolved}}}`

- `GET /api/v1/projects/{project_id}/cloud-security/exposure-intelligence/top?provider=&severity=&exposure_type=&limit≤20` → `{count, top_exposures}`

- `GET /api/v1/projects/{project_id}/cloud-security/exposure-intelligence/{exposure_id}` → detailed `exposure` + `history` (first/last/resolved, persistence_days), findings, CSPM, attack paths, remediation/SLA, explanation, evidence. 404 if not found or wrong project.

Uses existing `get_current_user`, `require_project_access`, `set_rls_context`. No secrets, bounded params.

## Project Risk Score

Not average of findings. Formula:
```
top = max top_exposure priority_score (0 if none)
conc = min(critical*4 + high*2, 15)
active = min(active_attack_path_exposures, 5)
score = min(top + conc + active, 100)
grade via tiers above (A 0-39 low risk, D 85-100 critical)
```
Quality over volume (1000 findings ≠ automatically worse). Documented.

## Persistence Decision

**ON-READ** E11 (no new large DB). Computes from current findings, CSPM, attack paths, E10 history (persisted via `cloud_attack_paths`). No duplicate E10 history, no second historical event system. Smallest possible model.

## Performance

- Findings 500, assets 500, attack paths 100, top 20, evidence 20, historical observations 50 per exposure.
- Bounded batch retrieval (3 queries for assets/findings/paths + CSPM + history), no N+1, no cloud APIs, no workers.
- Indexed `cloud_attack_paths (project_id, fingerprint)` etc.

## Security

All E11 APIs enforce authentication, project authorization, tenant isolation, RBAC, RLS, bounded params, safe errors. Never expose credentials/tokens/private keys/connector secrets/raw policy. Tested via cross-tenant/project, IDOR, injection, secret leakage.

## RLS

Uses existing `set_tenant_context` (transaction-local). SQLite no-op, PG `SET LOCAL`. Documented: SQLite tests cannot exercise PG table RLS; honest.

## Frontend

Adds **“Cloud Exposure Intelligence (E11)”** section to Cloud Security:

- Overall Exposure Score + Grade, Critical/High/Medium/Low counts, Total Top
- By Provider, By Type (concentrations)
- Top Cloud Exposures table: Priority | Severity (badge) | Provider | Exposure (type) | Asset (8-char) | Status — sorted priority desc
- Click → detail: **WHY THIS MATTERS** (score, severity, confidence, `explanation` deterministic template: “Priority 91 because external exposure, active attack path, critical finding, persistent…; path priority 82 with 2 findings.”), Risk Factors, Findings (finding_ids), Attack Paths, CSPM, Evidence (bounded), History (first/last/resolved), Remediation/SLA
- No huge graph, no AI chat, no heavy chart libs — reuses `SeverityBadge`, `useProjectContext`, `LoadingState`.

Uses `frontend/src/lib/api/cloudExposure.js` (`getExposureIntelligence`, `listTopExposures`, `getExposureDetail`).

## Testing

`backend/tests/test_cloud_exposure_intelligence_e11.py` — 35 tests:

1 empty, 2 low-risk, 3 critical ranks higher, 4 active path increases, 5 external exposure, 6 privileged, 7 sensitive, 8 persistent, 9 reopened, 10 remediation, 11 SLA, 12 missing neutral, 13 no fabricated business impact, 14 duplicate findings not multiply, 15 duplicate CSPM not multiply, 16 deterministic, 17 clamp, 18 severity boundaries, 19 top20 limit, 20 provider aggregation, 21 exposure-type aggregation, 22 trend, 23 history integration, 24 attack-path integration, 25 FindingEngine integration, 26 project isolation, 27 tenant isolation, 28 RBAC, 29 IDOR, 30 secret redaction, 31 evidence bounds, 32 E9 regression, 33 E10 regression, 34 E8 regression, 35 remediation/SLA.

Plus persistence/concurrency/history correctness via reuse (covered by E10). Tests mock synthetic fixtures, no live cloud.

## Limitations

- Business impact technical only (no financial modeling)
- Remediation/SLA via `Finding.status` (no full SLA engine)
- History via E10 (requires prior observations)
- No AI/predictive risk, no graph DB, no new discovery

## Explicit Out-of-Scope

AI/LLM, ML, predictive risk, graph DB/Neo4j, new cloud discovery, new checks/CSPM/providers/scanners, autonomous remediation, attack simulation, SIEM/SOAR, compliance expansion, arbitrary analytics/dashboards, new monitoring/scheduler/notification/reporting, business financial impact, **E12+**.

## Future

Expose prioritization enables E12 reporting/remediation retesting without AI; can later add retention, per-owner SLA, or business-impact mapping.
