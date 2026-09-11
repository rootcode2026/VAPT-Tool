# SECURITY SIGNAL CORRELATION E12 — Unified Correlation of Scanner Findings

## Business Objective

Many scanner results are not independent risks. Nuclei, ZAP, HTTP Fingerprint may all report the same security header issue on the same asset; SAST, SCA, Container may all flag the same vulnerable `lodash` package. Without correlation, an analyst sees 3× noise.

E12 answers: **Which signals are the same underlying condition, which are related, and what evidence connects them?** Turns `MANY SCANNER RESULTS` → `FEWER TRUSTWORTHY ISSUES + STRONGER EVIDENCE + RELATIONSHIPS + ROOT-CAUSE CONTEXT`, exposing attack path and CSPM context for each finding (without duplicating FindingEngine).

Not a scanner aggregation dashboard. Differentiator: `DISCOVERY → NORMALIZATION → CORRELATION → EVIDENCE → ROOT CAUSE → EXPOSURE`.

## Supported Scanners

NETWORK: `nmap`, `dns`, `subdomain` (subfinder), `tls`
WEB: `http_fingerprint`, `nuclei`, `zap`, `nikto`
APPLICATION: `api` (OpenAPI)
CODE: `sast` (Semgrep), `sca` (OSV), `secrets` (Gitleaks), `container` (Trivy), `iac` (Checkov)
CLOUD: `cloud` (AWS/GCP/Azure via E1-E7), `cspm` (via E8 controls)

Only scanners registered in `worker/app/scanner/registry.py` are correlated. No new scanners.

## Correlation Types (small taxonomy)

- `DUPLICATE` — same condition, same asset, same location/CVE/CWE/rule
- `RELATED` — same rule across different assets
- `SAME_ROOT_CAUSE` — same package/file across code scanners (sca/sast/container)
- `SAME_ASSET` — different findings on same canonical asset
- `SAME_VULNERABILITY` — same CVE on different assets (e.g., same lodash CVE on two hosts)
- `SAME_EXPOSURE` — same normalized URL endpoint across web scanners
- `ATTACK_PATH_RELATED` — finding asset appears in an E9 attack path
- `CSPM_RELATED` — cloud finding `rule_id` maps to a failed E8 CSPM control

Only emitted when evidence supports. Not dozens.

## Duplicate Semantics (mandatory)

- `same title` **≠** duplicate
- `same CVE` **≠** duplicate (different assets → `SAME_VULNERABILITY`, not `DUPLICATE`)
- `same asset + same rule/CVE + same normalized location` → `DUPLICATE` (cross-scanner corroboration)
- Two scanners detecting same condition on **same asset** → `DUPLICATE`; on **different assets** → `RELATED` / `SAME_VULNERABILITY`

## Canonical Condition ID

Deterministic fingerprint: `sha256(project_id | asset_id | rule_id | cve | cwe | normalized_location)[:32]`

Inputs: project, normalized asset (`asset_id`), `rule_id` (from `extra_data.rule_id`), `cve`, `cwe`, normalized location (`url` or `file` or `package`). No timestamp, no scanner execution ID. Same condition → same id.

For group: `sha256(project | correlation_type | canonical_key)[:32]` where `canonical_key` is bucket key (e.g., `fp` for duplicate, `asset:ID` for same_asset, `cve:CVE-...`).

## Normalization

Reuse existing utilities or simple deterministic helpers (`_normalize_url`, `_normalize_hostname`, `_normalize_package`, `_normalize_file`):

- URL: lowercased host, port preserved, path kept, `https://example.com/` vs `https://example.com` → same (trailing slash trimmed for root only)
- Hostname: lowercased, trailing dot stripped
- Package: lowercased
- File: lowercased, backslashes → `/`
- CVE/CWE: lowercased
- Do not over-normalize (keep meaningful path/param).

## Asset-Based Correlation

Uses `Asset` canonical `asset_id`. Findings with same `asset_id` → `SAME_ASSET` (bounded, ≤20 members). Not assuming different ports mean same vulnerability; they are `RELATED` via same asset but not necessarily duplicate.

Example: `nmap:443` + `tls:weak` + `nuclei:web` on same `asset_id` → `SAME_ASSET`, and if `attack_path` includes that asset → also `ATTACK_PATH_RELATED`.

## Web / Code / Cloud Correlation

- **Web:** normalized `url` (host+port+path+query) buckets `http_fingerprint`/`nuclei`/`zap`/`nikto`/`api` → `SAME_EXPOSURE` if same endpoint.
- **Code:** `package` bucket across `sca`/`container`/`sast` → `SAME_ROOT_CAUSE` / `SAME_VULNERABILITY` when same `CVE`/`package`/`file`.
- **Cloud:** reuse E8-E11: `cloud` finding `rule_id` in CSPM mappings → `CSPM_RELATED`; asset in E9 path → `ATTACK_PATH_RELATED`. Only if asset graph explicitly connects (via `AssetRelationship`); no invented container→cloud edges.

## Attack Path & CSPM Integration

- **E9:** `build_cloud_attack_paths` (bounded 20) → `asset_id → path_ids` map. If finding’s `asset_id` in that map, emit `ATTACK_PATH_RELATED` (HIGH confidence if exact, else MEDIUM). References `attack_path_ids` (≤5).
- **E8:** `evaluate_cspm` failed controls → `cspm_rules` set (all `mappings` values uppercased). If finding `rule_id` in set, emit `CSPM_RELATED` (HIGH). Reuses control `control_id`, no duplicate CSPM finding/score.

## Root Cause

Simple evidence-backed: one `package` (e.g., `lodash`) vulnerable across `sca`+`sast`+`container` → `SAME_ROOT_CAUSE`. One exposed service across `nmap`+`nuclei`+`zap` with same `asset_id` and `url` → `SAME_EXPOSURE`. Cloud config across `cloud`+`cspm`+`attack_path` → `SAME_ROOT_CAUSE`/`CSPM_RELATED`/`ATTACK_PATH_RELATED` per evidence (not just wording).

## Candidate Matching (bounded, no O(n²))

Limits: `findings 500`, `assets 500`, `relationships 1000` (not used for plain correlations), `groups 200`, `members 20`, `relationships returned 500`.

Bucket approach (indexed):
- `asset:{id}` → `SAME_ASSET`
- `rule:{rule_id}` → `RELATED` (if >1 asset)
- `cve:{cve}` → `SAME_VULNERABILITY`
- `url:{normalized}` → `SAME_EXPOSURE`
- `pkg:{package}` / `file:{path}` → `SAME_ROOT_CAUSE`
- `fingerprint` (composite `asset+rule+cve+cwe+location`) → `DUPLICATE`

Only compare **inside bucket** (size 2-20, bounded). Then attach `ATTACK_PATH_RELATED`/`CSPM_RELATED` via precomputed maps. No full 500×500.

Compatible scanner matrix (`COMPATIBLE`) ensures `nuclei↔zap`, `sast↔sca`, `sca↔container`, `cloud↔cspm` etc. are allowed; incompatible pairs not grouped (but same scanner duplicate is allowed).

## Confidence & Correlation Strength

**Confidence** deterministic:

- `HIGH`: exact fingerprint match (same asset+rule+cve+location)
- `MEDIUM`: same asset + same CVE, or same URL
- `LOW`: weak (multiple attributes but not exact) — not emitted to avoid noise (prefer no relationship)

**Score** 0-100 (correlation strength, **not** severity):

```
Exact fingerprint     +40
Same asset            +20
Same CVE/CWE          +20
Same location (URL/file/pkg) +10
Compatible scanners   +10
Clamp 0-100
```

`HIGH` ≥80, `MEDIUM` ≥50, else `LOW`. Documented, deterministic, not risk severity.

## Evidence / Provenance (bounded)

Per group (≤20 members, `score`/`confidence`/`title`/`explanation` deterministic):

- `members`: `finding_id`, `asset_id`, `scanner`, `severity`, `title` (redacted `[REDACTED]` if secret), `cve`/`cwe`, `role` (primary/corroborating)
- `finding_ids` (≤20), `asset_ids`, `scanners` (sorted)
- `related attack paths` (≤5), `CSPM controls` (≤5) where applicable
- `explanation`: e.g., “Same canonical fingerprint and same asset.”, “Same CVE affects the same package on the same container asset.”, “Cloud finding is associated with an existing CSPM control.”, “Finding appears on an existing cloud attack path.” — no AI.

Never expose credentials/tokens/private keys/connector secrets/raw policy.

## Persistence Decision

**ON-READ** (preferred per spec). No `SecurityCorrelationGroup` tables; groups are derived from current findings/assets. Keeps stable identity via deterministic `group_id` (`sha256(project|type|canonical_key)`), supports analyst workflow without durable groups. History not needed (E10 handles attack-path history). No Neo4j/ES/Kafka.

## API (project-scoped, bounded)

- `GET /api/v1/projects/{project_id}/security/correlations?limit≤100&type=&confidence=&scanner=&asset_id=&finding_id=` → `{count, correlations: [{id, project_id, correlation_type, canonical_key, confidence, score, title, explanation, finding_count, scanner_count, asset_count, members, finding_ids, asset_ids, scanners, attack_path_ids, cspm_control_ids}]}` — bounded 100, 400 invalid, 401 unauth, 404 cross-project/tenant.

- `GET /api/v1/projects/{project_id}/security/correlations/{correlation_id}` → detailed group + members + related paths/CSPM + evidence. 404 if not found or wrong project.

- `GET /api/v1/projects/{project_id}/security/correlations/summary` → `{total_groups, duplicates, related, root_causes, attack_path_related, cspm_related, by_type, by_scanner, by_asset_count, groups[:10]}`

All `require_project_access` + `set_rls_context`, bounded params, safe errors.

Existing `GET /api/v1/findings/{id}` and `GET /api/v1/assets/{id}` optionally show `CORRELATED SECURITY SIGNALS` via client-side call to correlations API (no redesign).

## Frontend

Add lightweight **“Security Correlations”** section (in `cloud-security/page.jsx` for now, also usable from findings):

- Table: `Correlation` (type badge) | `Confidence` | `Strength` (score) | `Asset` (8-char) | `Finding Count` | `Scanner Count` (e.g., `nuclei + zap + nikto`)
- Click → detail: **WHY CORRELATED** (matching fingerprint, same asset, endpoint, scanner evidence), **MEMBERS** (finding A/B/C with scanner/title/severity), **RELATED**: attack path ids, CSPM control ids
- No giant graph visualization — simple cards/tables/lists, reuses `SeverityBadge`, `useProjectContext`.

Uses `frontend/src/lib/api/securityCorrelations.js` (`listSecurityCorrelations`, `getSecurityCorrelation`, `getSecurityCorrelationSummary`).

## Security / RBAC / RLS

All APIs enforce `get_current_user` + `require_project_access` + `set_rls_context` (transaction-local, SQLite no-op, PG SET LOCAL). Cross-project/tenant → 404 (no leak), unauth → 401, invalid → 400. Evidence bounded, redacted.

IDOR tests: `correlation_id` from another project → 404; `finding_id`/`asset_id`/`attack_path_id` from another project cannot leak via correlation (filtered by `project_id` first). Secrets never in correlation evidence.

## Performance

- Max findings 500, assets 500, groups 200, members 20, relationships returned 500.
- Candidate bucketing O(n) + per-bucket bounded compare (≤20 members), no O(n²) across 500.
- No N+1 (2 batched queries: assets, findings; plus optional attack path/CSPM batch).
- Deterministic sort (`-score`, confidence rank, type, id).

## Limitations

- On-read, no persisted correlation history (stable via deterministic id).
- Fuzzy matching not used (no ML); similar titles alone → not duplicate.
- Same CVE on different assets → `SAME_VULNERABILITY` (RELATED), not `DUPLICATE` (mandatory).
- CSPM/attack-path relations only if E8/E9 evidence exists.
- No business financial impact.

## Examples

- `nuclei` + `zap` both report `X-Content-Type-Options` missing on `https://example.com/api` with same `asset_id` → `DUPLICATE` HIGH 90 (exact fingerprint + same asset + compatible).
- `sca` `CVE-2021-44228` on `log4j` in `app` + `container` same `CVE` on same `package` → `SAME_ROOT_CAUSE` MEDIUM.
- `cloud` finding `AWS-S3-003` (public bucket) on asset that is also in an E9 path → `ATTACK_PATH_RELATED` + `CSPM_RELATED` (if CSPM failed).

## Explicit Out-of-Scope

AI/LLM, embeddings, vector DB, ML, graph DB (Neo4j), ES, Kafka, SIEM/SOAR, autonomous remediation, pen-testing, attack simulation, new scanners/discovery/CSPM/providers/compliance, new monitoring/scheduler/notification/reporting, giant graph viz, arbitrary analytics, predictive risk, business financial impact, **E13+**.

## Future

Deterministic correlation enables later analyst workflow (group status) or history without heavy infra. Can add persisted `SecurityCorrelationGroup` if needed (stable id via same hash) — not required in E12.
