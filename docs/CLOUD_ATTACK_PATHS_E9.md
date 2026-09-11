# CLOUD ATTACK PATHS E9 — Exposure Path Analysis

## Objective

Turn existing cloud evidence (assets, relationships, findings, CSPM) into a small number of trustworthy, explainable evidence-backed cloud attack/exposure paths answering: how can an attacker reach an important resource, which exposure enables it, which identity/network relationship matters, which finding makes it meaningful, what is impact, which path to investigate first. Differentiates platform from standalone CSPM/scanners by correlating **EXPOSURE + IDENTITY + NETWORK + RESOURCE + FINDING**. This is exposure/reachability analysis, **not proof of exploitation** — never claim successful exploitation unless evidence proves it.

## Business Value

Prioritizes cloud risk by reachability: an isolated critical finding vs an internet-reachable privileged path are not equal. E9 surfaces 5-20 high-value paths per project deterministically, bounded, provider-neutral (AWS/GCP/Azure).

## Architecture

```
Existing DB evidence
  ↓ (bounded batch: assets 500, relationships 1000, findings 500)
Normalized graph (provider-neutral nodes/edges)
  ↓ (entry detection)
Evidence-backed entry points
  ↓ (BFS depth ≤6)
Bounded traversal
  ↓ (validation, deduplication)
Path validation + fingerprint
  ↓ (scoring)
Risk/path scoring + confidence
  ↓ (API)
Bounded API response (≤100)
```

No new discovery, no new CSPM controls, no graph DB (PostgreSQL relational), no Neo4j/Kafka/ES, no AI. On-read computation, deterministic, no duplicate FindingEngine findings. Interfaces allow future graph backend without domain rewrite.

## Normalized Graph Model

**Nodes:**
- `cloud_account` (aws account, gcp project, azure subscription)
- `cloud_resource` with `extra_data.resource_type` (aws_ec2_instance, aws_rds_instance, aws_s3_bucket, aws_iam_role, gcp_compute_instance, gcp_storage_bucket, azure_vm, azure_storage_account, etc.)
- `provider` derived from `value` prefix `cloud_resource:aws|gcp|azure:...` or metadata

Provider-specific adapters at edges: `_extract_provider` normalizes to `aws|gcp|azure|unknown|multi`.

**Edges:**
- `AssetRelationship` rows (`contains`, `uses`, `observed_on`, `trusts`, `has_permission`, `permits`, etc.) — existing, bounded, deterministic sort `(source, target, type, id)`
- Implicit edges not invented; only explicit relationships are traversed. Findings do not create edges, they add security condition to nodes.

Limits: `MAX_NODES_PER_GRAPH 500`, `MAX_EDGES_PER_GRAPH 1000`, `MAX_PATH_DEPTH 6`, `MAX_PATHS 100`, `MAX_PATH_EVIDENCE 20`, `MAX_API_LIMIT 100`. No N+1, no cloud API calls.

## Node Types (normalized)

- `external_entry` (public IP, internet-facing LB, public storage, permissive ingress)
- `identity` (iam user/role, gcp service account, azure RBAC assignment)
- `role` / `permission`
- `network` (security group, NSG, firewall, subnet)
- `resource` (generic cloud_resource)
- `workload` (vm, compute instance)
- `storage` (s3 bucket, gcs bucket, azure storage)
- `database` (rds, sql)
- `load_balancer` (alb/nlb)
- `finding` (correlated, not duplicated)
- `sensitive_target` (db, storage with important data, privileged role)

## Edge Types (existing)

Reuses `relationship_type` values already persisted (contains, uses, etc.). No speculative relationships merely because two resources exist in same account.

## Entry Points (evidence-backed)

`_is_entry_asset` returns true if:
- `extra_data.public == true` or `public_ip` present
- `exposure == INTERNET_EXPOSED/ PUBLIC` or `scheme == internet-facing`
- `allow_blob_public_access == true` or `is_public == true`
- attached finding `rule_id` in `ENTRY_RULE_IDS` (AWS-EC2-002, NET-002/003/004/005/007, S3-003/005, RDS-001, GCP-NET-001-004 etc, AZURE-NET-001-004 etc)
- asset type internet_gateway

Do not invent entry points.

## Path Types (controlled taxonomy)

- `INTERNET_TO_RESOURCE`
- `INTERNET_TO_VULNERABLE_RESOURCE` (default when findings present)
- `PUBLIC_RESOURCE_TO_INTERNAL_RESOURCE`
- `IDENTITY_TO_PRIVILEGED_RESOURCE`
- `EXTERNAL_TRUST_TO_PRIVILEGED_RESOURCE` (if finding IAM-004/005)
- `NETWORK_TO_SENSITIVE_RESOURCE`

Only types actually supported by evidence are emitted.

## Traversal Bounds & Validation

- BFS from each sorted entry_id, queue `[(asset_ids, rel_ids, rel_objects)]`, visited per path (cycle prevention: `target_id in cur_asset_ids` skip)
- Depth ≤6, paths ≤100, nodes ≤500, edges ≤1000, evidence ≤20
- Validation: same project, edge has evidence-backed relationship, referenced findings exist, provider known, path contains meaningful security condition (findings_on_path non-empty and target in target_ids), no cycles, length bounded, duplicates removed, incomplete evidence → no path (prefer no path over speculative)

## Finding Correlation

FindingEngine remains authoritative. Paths reference `finding_id`/`rule_id`/`severity`/`asset_id`/`evidence` but **do not create duplicate findings**. Uses `Finding.scanner=="cloud"` joined via `Asset.project_id`. Examples: AWS-EC2-002, IAM-001/003/004, RDS-001, S3-003, GCP-NET-001, AZURE-NET-001. No invented rule IDs.

## Scoring (deterministic, explainable)

Formula in `_score_path`:
```
score = 30  # base
+20 if entry_exposure
+15 + min(privilege_count,2)*5 if privilege
+20 if critical finding else +10 if high else +5 if any finding
+10 if sensitive target
- (path_len-3)*2 if len>3  # length penalty
+ min(total_severity_weights//4, 10)  # finding weight
clamp 0-100
```

Severity from score:
- `critical` 85-100
- `high` 70-84
- `medium` 40-69
- `low` 0-39

Score does **not** represent probability of successful exploitation (documented).

## Confidence

- `HIGH`: all edges are explicit relationships and ≥1 finding
- `MEDIUM`: no inferred edges but 0 findings OR 1 inferred edge with finding
- `LOW`: ≥2 inferred edges or no findings (LOW is emitted but filtered as not useful; prefer not to create path if LOW and no finding)

Do not call speculative path HIGH.

## Evidence / Provenance

Per path bounded `findings` (≤20, sanitized `_sanitize_evidence` — redacts secret/private_key/credential/token titles to `[REDACTED]`), `relationships` (id/source/target/type), `nodes` (asset_id/value/asset_type/provider), `affected_resources` (deduped asset_ids ≤20), `explanation` (“Evidence-backed potential attack path: … via N resources with M finding(s).”). No secrets, no raw policy secrets.

## Deduplication / Canonical ID

Fingerprint via `hashlib.sha256("{project_id}|{path_type}|{provider}|{'->'.join(sorted(asset_ids))}".encode()).hexdigest()[:32]` — ordered meaningful node identity, provider, project, path type; **no timestamp**. Same logical path repeatedly → same `id`/`fingerprint`. In-memory `seen_fingerprints` set, sorted deduplication.

## Provider Neutrality

Domain model not `if AWS...elif GCP...` throughout; normalized concepts + provider extraction at edges. Provider-specific logic confined to `_extract_provider`, `ENTRY_RULE_IDS`, `PRIVILEGE_RULE_IDS`, metadata checks.

## Sensitive Targets

Recognized via `SENSITIVE_TYPES` set (rds, s3, ebs, gcp storage, azure storage, iam roles, etc.) or high/critical finding on asset. Do not invent business-criticality labels.

## Cloud Attack Path Service

`backend/app/services/cloud_attack_paths.py` — on-read, no persistence.

Responsibilities: build bounded graph, normalize, identify entries, correlate findings, traverse BFS, validate, score, confidence, evidence, deduplicate, return bounded results. New persistence not added (simpler, consistent with E8 CSPM). Documented decision: **keep on-read**; durable path identity via fingerprint allows future persistence without schema yet.

## Persistence Decision

**On-read** (no `cloud_attack_paths` table). Reuses assets/relationships/findings. Bounded queries, no snapshot. If monitoring/change needs durable identity, fingerprint enables later minimal model (`id, project_id, provider, path_type, fingerprint, priority_score, severity, confidence, status, entry_asset_id, target_asset_id, evidence`).

## Path Status

On-read paths are `ACTIVE`. No lifecycle yet; existing finding lifecycle remains authoritative. If persisted, support `ACTIVE`/`RESOLVED` when evidence disappears (integrates with D2 change detection, not expanded).

## Change Detection Integration

Reuses D2: entry/relationship/finding appearance/disappearance naturally changes path set (fingerprint stable). No D2 expansion.

## API

- `GET /api/v1/projects/{project_id}/cloud-security/attack-paths` — query `provider` (aws/gcp/azure → 400 else), `severity` (critical/high/medium/low → 400), `confidence` (HIGH/MEDIUM/LOW → 400), `path_type` (valid taxonomy → 400), `status` (ACTIVE/RESOLVED → 400, RESOLVED returns [] on-read), `limit` 1-100 (bounded, default 50). Requires `require_project_access`, RLS `_set_rls_context`, bounded response `{count, paths: [..]}`. Cross-project → 404.

- `GET /api/v1/projects/{project_id}/cloud-security/attack-paths/{path_id}` — detail includes `id`/`fingerprint`/`provider`/`path_type`/`severity`/`priority_score`/`confidence`/`entry_asset_id`/`target_asset_id`/`asset_ids`/`nodes` (ordered)/`relationships` (ordered)/`findings`/`evidence`/`affected_resources`/`explanation`/`status`. Unknown → 404. Invalid filter → 400.

Registered in `backend/app/main.py` with `dependencies=protected`.

## Frontend

`frontend/src/lib/api/cloudAttackPaths.js` + `frontend/src/app/(app)/cloud-security/page.jsx` — lightweight section “Cloud Attack Paths (E9)” with table:

- Priority (score) | Severity (badge) | Provider | Path Type | Entry (8-char id) | Target | Confidence | Findings | Status

Click row → detail view with chain: `ENTRY ↓ NODE ↓ TARGET`, findings list, relationships list, explanation, provider, confidence, score. Simple visual chain, no heavy graph viz library. Uses `useProjectContext`, API-driven (no hardcoded).

## Security

Every endpoint enforces `get_current_user` + `require_project_access` + tenant isolation + RLS context + secure error handling + sanitized evidence. No credentials/tokens/private keys/sensitive connector config leaked. Bounded inputs, 400 on invalid filter, 404 on unknown path/cross-project (no existence leak).

## Tenant Isolation / RBAC / RLS

- Project isolation: `Asset.project_id == project_id` filter, cross-project 404
- Tenant isolation: organization check via `require_project_access`, cross-tenant 404
- RBAC: viewer+ can read (protected deps), no bypass
- RLS: `set_tenant_context` best-effort transaction-local `set_config(..., true)`, SQLite no-op, PG SET LOCAL; honestly documented limitation (SQLite tests cannot exercise PG ENABLE RLS policies; helper validation tested)

## Testing

`backend/tests/test_cloud_attack_paths_e9.py` — **30 tests** (unit + API):

- Empty graph no paths, single valid internet→resource, internet→vulnerable, identity→privileged, external trust→privileged, multi-hop, depth limit, count limit, cycle prevention, duplicate elimination, fingerprint stability, finding correlation, missing evidence no speculative path, confidence calc, priority scoring, severity classification, AWS/GCP/Azure normalization, mixed-provider isolation, project isolation, invalid filters, evidence bounds, secret redaction, no duplicate FindingEngine findings, tenant isolation, unauthorized 401, project isolation API, invalid filters 400, detail+404, evidence bounds, tenant isolation

## Performance / Bounds

- Nodes ≤500, edges ≤1000, depth ≤6, paths ≤100, evidence ≤20, API limit ≤100, no unbounded DFS/BFS, no N+1 (3 bounded batch queries: assets, relationships, findings), no cloud API calls, no new infra.

## Limitations

- On-read, no historical persistence (fingerprint allows later)
- Entry detection heuristic (public_ip, exposure metadata, entry rule_ids) — not packet-level reachability; terminology “evidence-backed reachable” not “confirmed exploitable”
- Sensitivity via resource_type + finding severity, not business labels
- Same finding supporting multiple distinct paths counts per path (intentional distinct paths)
- RLS table policies not exercised in SQLite (known limitation)
- No AI/remediation/SIEM/SOAR/graph viz/E10

## Explicit Out-of-Scope

Graph DB, Neo4j, Kafka, ES, heavy infra, new cloud discovery, new checks/CSPM controls/providers, AI/LLM, autonomous remediation, active exploitation, SIEM/SOAR, compliance expansion, notification/reporting, network simulator, packet reachability, browser execution, E10.

## Future

Interfaces allow later graph backend (replace bounded SQL→graph without rewriting domain model). Persistence can be added via fingerprint + minimal table.
