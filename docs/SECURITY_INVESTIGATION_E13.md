# SECURITY INVESTIGATION E13 — Unified Investigation & Operations

## Business Objective

E12: *Which signals are related?*
E13: *What should the analyst investigate, why does it matter, what evidence supports it, what has happened over time, and what action should be taken next?*

One unified investigation context replaces hunting across Finding → Asset → CSPM → Attack Path → Exposure → Remediation → Retest → Audit. Measurable value: **less investigation time, less context switching, less alert fatigue, better evidence, faster triage**.

## Investigation Model

**SECURITY INVESTIGATION** aggregates authoritative systems:

```
Finding (authoritative)
 → Correlations (E12)
 → Assets (Asset Intelligence)
 → Attack Paths (E9/E10)
 → CSPM Controls (E8)
 → Exposure Intelligence (E11)
 → History / Changes (D2 + finding_history)
 → Remediation (D7)
 → Retesting (D8)
 → Audit Events
 → SLA / Ownership
```

Do NOT duplicate vulnerability/risk/asset engines. Aggregation layer only.

## Subject Types

Investigation can be initiated from existing identifiers:

- `finding` (`finding_id`)
- `asset` (`asset_id`)
- `correlation` (`correlation_id` via E12)
- `attack_path` (`attack_path_id` / fingerprint via E9/E10)
- `exposure` (`exposure_id` via E11)

Service `resolve_subject(project_id, db, subject_type, subject_id)` validates subject belongs to project (via asset project, finding asset, correlation lookup, path lookup, exposure lookup). No duplicate records.

## Deterministic Identity

`investigation_id = SHA256(project_id | subject_type | subject_id)[:32]`

No timestamps, stable across repeated create requests. `POST` with same subject returns existing investigation (idempotent). Same condition → same id.

## Lifecycle

```
OPEN → IN_PROGRESS → RESOLVED → CLOSED
```

- `OPEN`: exists but not actively worked
- `IN_PROGRESS`: analyst investigating
- `RESOLVED`: underlying condition verified resolved (does not auto-resolve finding)
- `CLOSED`: intentionally closed

Small lifecycle, no unnecessary states. Finding lifecycle remains authoritative (closing investigation does not auto-close finding).

## Persistence Decision

**Minimal persistence** required for analyst state (status, assigned_to, notes, resolved_at/closed_at). Model:

**SecurityInvestigation**
- `id` (deterministic), `organization_id`, `project_id`, `subject_type`, `subject_id`, `status` (OPEN/IN_PROGRESS/RESOLVED/CLOSED), `title`, `priority` (critical/high/medium/low), `severity`, `assigned_to` (FK users), `created_by`, `created_at`, `updated_at`, `resolved_at`, `closed_at`
- Indexes: `(project_id, status)`, `(project_id, priority)`, `(project_id, assigned_to)`, `(project_id, created_at)`, `(subject_type, subject_id)`
- Tenant: `organization_id` + `project_id` (RLS compatible)

**InvestigationNote**
- `id`, `investigation_id` FK CASCADE, `author_id` FK SET NULL, `content` Text (≤4000), `created_at`, `updated_at`
- Index: `investigation_id`

Do NOT duplicate finding/asset/risk data. Bounded notes.

Migration `e13f6a7b8c9d_add_security_investigations` creates both tables, reversible downgrade, deterministic.

## Investigation Summary (deterministic)

Every investigation provides:

- `title` (redacted, from subject title)
- `subject` (type+id)
- `status`, `priority` (derived from underlying severity via `_priority_from_severity`), `severity`, `confidence` (MEDIUM)
- `risk/exposure score` where applicable (via E11)
- `affected assets` (from finding asset or subject asset, ≤10)
- `affected findings` (subject finding)
- `scanners`
- `correlations` (via E12, filtered by finding_id/asset_id, ≤10)
- `attack paths` (via E9, asset_ids intersection, ≤5)
- `CSPM controls` (via E8 `evaluate_cspm` failed, ≤5)
- `exposure` (via E11 `get_top_exposures`, matched)
- `remediation` (D7 `FindingRemediation` latest)
- `retest` (D8 `FindingRetest` latest)
- `ownership` (`Finding.assigned_to`, `owner_user_id`)
- `SLA` (`FindingSLA` latest)
- `notes` (≤50)

All values from authoritative systems, bounded.

## Why This Matters (deterministic)

Template, no AI:

- Critical/high severity → “Critical finding…”
- Internet-facing asset → “affects an internet-facing asset”
- Has correlations → “has N correlated signal(s)”
- Has attack path → “is associated with an active cloud attack path”
- Has exposure → “contributes to … with priority X”

Example: *“Critical finding affects an internet-facing asset and is associated with an active cloud attack path. Reported by nuclei. Evidence is backed by existing asset and attack path data.”*

Corresponds to actual scoring factors, no exploitability claims.

## Investigation Priority (reuse existing)

Do NOT create new risk engine. Reuse:

- Finding severity → priority (`critical→critical`, `high→high`, etc.)
- Finding confidence (existing)
- E11 exposure priority (if exposure exists)
- Attack path priority (via exposure)
- CSPM state

Priority displayed as `INVESTIGATION PRIORITY` (critical/high/medium/low), distinct from vulnerability severity, ordered critical first.

## E12 Correlation Integration

For `finding` → `get_correlations(project_id, db, finding_id=...)`
For `asset` → `get_correlations(..., asset_id=...)`
Reuses E12, does not duplicate logic. Shows duplicate, same_asset, same_vuln, attack-path-related, cspm-related, etc.

## Asset Context (reuse)

Shows `asset_type`, `value` (truncated 80), `provider` (from value), `first_seen`/`last_seen` via asset timestamps, related assets via `AssetRelationship` (not duplicated), findings via asset, correlations via E12, attack paths via E9, exposure via E11.

## Attack Path Context (reuse E9/E10)

If related to E9 path: `path_type`, `provider`, `entry`, `target`, `assets`, `severity`, `priority`, `confidence`, `evidence`, `first_seen`, `last_seen`, `status`. Reuse E9 `build_cloud_attack_paths` and E10 `CloudAttackPath` history. No second path generation.

## CSPM Context (reuse E8)

Shows `affected controls` (FAIL via `evaluate_cspm`), `provider`, `control status` PASS/FAIL/NOT_ASSESSED, `affected resources`, `evidence`. No duplicate CSPM findings.

## Exposure Context (reuse E11)

Shows `exposure_type`, `exposure score`, `risk tier` (critical/high/medium/low), `factors`, `affected asset`, `attack path`, `finding`, `persistence`, `recurrence`, `remediation state`. Reuse `get_top_exposures`.

## History / Timeline (unified, bounded 200)

Normalized from existing systems (no duplicate event DB):

- `finding created` (`Finding.created_at`)
- `finding status/severity changed` (`FindingHistory`)
- `remediation started/evidence` (`FindingRemediation`)
- `retest started/passed/failed` (`FindingRetest`)
- `attack path created/resolved/reopened` (`CloudAttackPath.first_seen/resolved_at`)
- `exposure changed` (via E11, not separate)
- `investigation created/updated` (`SecurityInvestigation.created/updated_at`)
- `note created` (`InvestigationNote`)

Each event: `timestamp` (iso), `source` (finding, monitoring, attack_path, remediation, retest, audit, investigation), `type`, `detail`. Provenance preserved, no invented events; if unavailable, return known only. Bounded, sorted chronologically.

## Timeline Security

Every event identifies `source`; no invented history. If historical info unavailable (e.g., no retest), timeline simply lacks that source.

## Investigation Notes

If persistent investigations, allow bounded notes:

- `note_id`, `investigation_id`, `author_id`, `content` (≤4000), `created_at`, `updated_at`
- Redacted via `_redact` (secret, private_key, credential, token, password → `[REDACTED]` on title, stored sanitized for notes where appropriate)
- All note creations auditable.

## Ownership (reuse Finding ownership)

Finding ownership (`Finding.assigned_to`, `owner_user_id`) remains authoritative. Investigation `assigned_to` is separate **INVESTIGATION OWNER** (analyst). Changing investigation owner does not change finding owner unless explicitly via finding workflow.

## SLA (reuse)

Shows `SLA status`, `due_at`, `breached_at`, `paused` via `FindingSLA` latest. If none → `NOT CONFIGURED`. No second SLA engine.

## Remediation (reuse D7)

Shows `status` (open/in_progress/blocked/resolved), `owner`, `due_at`, `evidence_ref`, `blocked_reason`, timestamps. No auto-create.

## Retest (reuse D8)

Shows `status`, `scanner`, `scanner_version`, `digest`, `result` (PASS/FAIL/ERROR), `fingerprint parity`, `completed_at`. No auto-run on page open.

## Analyst Actions (if persistent)

- `assign owner` (PATCH assigned_to)
- `change status` (PATCH status)
- `add note` (POST /notes)
- `close` / `reopen` (via status)
No autonomous remediation, no shell commands, no bulk destructive. All writes require `analyst`/`project_admin`.

## RBAC

- **Read**: `viewer`+ with `require_project_access`
- **Write**: `analyst`+ (`_effective_project_role` in `analyst`/`project_admin`, super_admin bypass)
- Administration: `project_admin`
No new role invented; reuses existing permission catalog (`project_membership` roles).

## API

Project-scoped, bounded, `require_project_access` + `set_rls_context`, 400 invalid, 401 unauth, 404 cross-tenant (no leak).

- `GET /api/v1/projects/{project_id}/security/investigations?status=&priority=&subject_type=&assigned_to=&severity=&limit≤100` → `{count, investigations: [{id, project_id, subject_type, subject_id, status, title, priority, severity, assigned_to, created_by, created_at, updated_at}]}`
- `GET /api/v1/projects/{project_id}/security/investigations/{id}` → full context (see Investigation Summary)
- `POST /api/v1/projects/{project_id}/security/investigations` body `{subject_type, subject_id}` (finding/asset/correlation/attack_path/exposure) → validates subject belongs to project, deterministic id, creates or returns existing, 400 invalid, 404 wrong project.
- `PATCH /api/v1/projects/{project_id}/security/investigations/{id}` body `{status, assigned_to}` → updates, transactional, audit.
- `POST /api/v1/projects/{project_id}/security/investigations/{id}/notes` body `{content}` (≤4000, not empty, not secret) → creates note, auditable.
- `GET /api/v1/projects/{project_id}/security/investigations/{id}/timeline` → `{count, timeline: [{timestamp, source, type, detail}]}` bounded 200.
- `GET /api/v1/projects/{project_id}/security/investigations/summary` → `{open, in_progress, resolved, closed, total, critical, high, assigned, unassigned, sla_breached, attack_path_related, cspm_related}`

All validate `subject_id` via `resolve_subject` (checks `asset.project_id` etc.), cross-tenant → 404.

## Frontend

Creates **SECURITY INVESTIGATIONS** page (`frontend/src/app/(app)/investigations/page.jsx`):

- Header stats: Open, In Progress, Critical, SLA Breached (from summary)
- Create form: `subject_type` select + `subject_id` input → `POST` (analyst)
- Table: Priority | Subject (type:8-char) | Severity (badge) | Owner (8-char or —) | Status — bounded 100, click → detail
- Detail:
  - Header: `[PRIORITY] title` + Status, Priority, Owner, SLA
  - **WHY THIS MATTERS** (deterministic)
  - **SECURITY SUMMARY** (severity, confidence, scanners)
  - **CORRELATED SIGNALS** (E12, ≤5)
  - **ATTACK PATHS** (E9/E10, ≤3)
  - **CSPM** (E8, ≤3)
  - **EXPOSURE INTELLIGENCE** (E11)
  - **REMEDIATION** (D7)
  - **RETEST** (D8)
  - **TIMELINE** (chronological, 20)
  - **ANALYST NOTES** (list + input 4000 + Add button)
  - Actions: In Progress / Resolved / Closed buttons (PATCH), Close
  - Deep-links to finding/asset/attack path pages where useful (subject_id)

Do not duplicate existing pages; no giant graph.

Optionally add compact “Investigations Requiring Attention” card to `dashboard` (deferred, not required in E13 minimal).

## Dashboard Integration (optional)

Not required in minimal E13; documented as future. If added, show top critical investigations + SLA breaches + active attack-path investigations (bounded).

## Persistence Safety

Every `security_investigations` record includes `organization_id` + `project_id` (tenant). Indexes: `(project_id, status)`, `(project_id, priority)`, `(project_id, assigned_to)`, `(project_id, created_at)`, `(subject_type, subject_id)`. IDs validated as `String(36)`; no raw IDs without project validation.

## Concurrency

Transaction per update (`db.commit()`), notes not overwriting each other (separate rows). Status updates transactional; no silent lost updates beyond last-write-wins (acceptable for analyst workflow, no in-memory locks).

## Audit

Uses `AuditService.record`:

- `INVESTIGATION_CREATED` (actor, org, project, investigation id, subject_type/id)
- `INVESTIGATION_UPDATED` (status/assigned_to)
- `INVESTIGATION_NOTE_CREATED` (note_id)

No second audit system, no secrets in audit (`content` truncated 500, redacted).

## Performance (bounds)

- investigations 100, timeline 200, findings 100, assets 100, correlations 100, attack paths 50, CSPM controls 50, notes 50
- Batch loading (single `list_investigations` query + per-detail bounded queries, no N+1 across investigations list)
- No repeated service calls per finding within request (cached)

No Redis/Kafka/ES/graph DB.

## Limitations

- Investigation priority derived from underlying severity (no new risk engine)
- Timeline historical depth limited to available `FindingHistory`/`Audit`/`CloudAttackPath` (no invented events)
- No automatic remediation or scanner execution on investigation open
- No bulk actions
- No business financial impact

## Deferred (E14+)

AI/LLM/RAG/embeddings/vector DB/ML, graph DB (Neo4j)/ES/Kafka, SIEM/SOAR, autonomous remediation/exploitation, pen-testing, new scanners/providers/discovery/CSPM, predictive analytics, threat intel platform, business financial impact, giant graph viz, new monitoring/scheduler/notification/reporting.

## Future

Investigation layer can later add bulk triage, per-investigation SLA, or automated assignment without duplicating authoritative data.
