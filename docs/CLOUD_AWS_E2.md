# E2 — AWS Security Checks

> Status: IMPLEMENTED (pending merge). DISCOVERY ONLY is E1; E2 evaluates
> persisted E1 evidence into findings. No IAM analysis (E3), no network-flow
> analysis (E4), no storage-policy analysis (E5), no CSPM/attack paths (E8/E9).

## Architecture

- Check engine: `backend/app/services/cloud_checks.py` — provider-neutral
  structure (`AWS_CHECKS` pack + `DEFERRED_CHECKS`), pure offline evaluation
  over persisted asset metadata. No AWS calls, no credentials, no network.
- E1 collector extension (same read-only calls, additive fields only):
  EC2 `MetadataOptions` → `imds_v2_enforced` (+`http_endpoint`); RDS
  `PubliclyAccessible`/`StorageEncrypted`; S3 public-access-block flags +
  default-encryption algorithm (+ error codes); ELB `DescribeListeners`;
  Lambda `ListFunctionUrlConfigs`.
- Findings persist through the existing Findings table (`scanner="cloud"`,
  `scan_id`/`target_id` NULL, `asset_id` set) reusing FindingEngine severity
  scoring semantics, backend fingerprint identity, existing lifecycle states,
  SLA/remediation/retest flows (asset path), and dashboard/alert/report
  integrations where asset-scoped.
- One new table: `cloud_check_runs` (UNIQUE per discovery run → idempotent
  re-evaluation). No results table: PASS/NOT_ASSESSED aggregate on the run;
  per-finding detail lives on findings.

## Check catalog (pack v1.0, all enabled)

| ID | Title | Severity | Evidence |
|---|---|---|---|
| AWS-EC2-001 | IMDSv1 allowed | high | `imds_v2_enforced=false` |
| AWS-RDS-001 | RDS publicly accessible | critical | `publicly_accessible=true` |
| AWS-RDS-002 | RDS storage unencrypted | high | `storage_encrypted=false` |
| AWS-S3-001 | S3 Block Public Access disabled | high | any `pab_*` explicitly false |
| AWS-S3-002 | S3 no default encryption | medium | `NoSuchEncryptionConfiguration` (+alias) |
| AWS-ELB-001 | Internet-facing LB with HTTP listener | medium | HTTP listener + internet-facing scheme |
| AWS-LAMBDA-001 | Lambda URL unauthenticated | high | function URL `AuthType NONE` |

Deferred with reasons (`DEFERRED_CHECKS`): AWS-EC2-002 (needs SG ingress rule
bodies — E4). Deeper S3 policy analysis needs policy documents (E5). IAM
beyond identity enumeration needs policy documents (E3).

## Result states

PASS (explicit secure value), FAIL (explicit insecure value + bounded
evidence), NOT_ASSESSED (missing/denied evidence — never PASS, never FAIL),
ERROR (evaluation exception only). Permission denial on evidence calls is
recorded in asset error fields and yields NOT_ASSESSED with reason.

## Evidence model

Per FAIL: check/version, resource value, field, observed vs expected, region,
account, discovery run, observed_at. Bounded (≤2000 chars JSON), redacted,
no raw AWS responses, no secrets.

## Finding integration

- `rule_id` = check ID (in metadata; feeds scanner-independent fingerprint
  together with title + asset identity, so scanner/version changes never
  duplicate).
- Asset-linked (`asset_id`); severity/score per FindingEngine map; status
  `open`; remediation guidance per check; CVE/CWE NULL (never fabricated);
  confidence 90/high (explicit API evidence).
- Deduplication: fingerprint match skips creation across runs. Absent
  conditions never auto-resolve (D8 owns verification).
- Findings without scan/target: list/detail/cloud surfaces scope via asset;
  lifecycle (SLA/remediation/retest/risk-acceptance) resolves the project via
  asset. Target-joined aggregates (org reports, some dashboards) exclude them
  — documented limitation, not silent: run detail + findings views are
  authoritative for cloud findings.

## Discovery provenance

Every evaluation binds a completed/partial discovery run (rejected otherwise);
findings carry `discovery_run_id`, `connection_id`, asset `observed_at`.
Stale assets are evaluated transparently (timestamps surfaced), never presented
as freshly verified.

## Severity & confidence

Per-check deterministic severity (documented above). Confidence 90/high for
all created findings (explicit AWS API fields). No confidence inflation for
partial evidence — that path is NOT_ASSESSED.

## Partial-permission behavior

Denied evidence calls produce error-code fields; checks map denial to
NOT_ASSESSED with reason. Absence of findings for a denied service means
"could not assess", surfaced in run breakdown + warnings.

## AWS permissions required (E2 adds, read-only)

`rds:DescribeDBInstances` (covered), `s3:GetBucketLocation`,
`s3:GetPublicAccessBlock`, `s3:GetBucketEncryption`,
`elasticloadbalancing:DescribeListeners`, `lambda:ListFunctionUrlConfigs`
(all read-only; no mutating calls anywhere in E2).

## RBAC / isolation / audit

Run: analyst+. Catalog/runs: any member. Tenant/project scoping on every
query; cross-project/tenant → 404. Audit: run requested/completed/partial/
failed + per-finding FINDING_CREATED (existing event), IDs + bounded metadata
only.

## Limitations

1. Seven checks only; EC2-002/S3-policy/IAM-depth deferred with reasons.
2. Nullable scan/target is new: target-joined aggregates exclude cloud findings
   (documented; run + findings views authoritative).
3. `alembic upgrade head` pre-existing-blocked at `o1p2q3r4s5t6`; E2 migration
   verified via offline SQL; live DDL applied out-of-band.
4. Evaluation is synchronous in the API (bounded 500 assets); no worker queue.
5. SQLite suites with JSONB/stale-DDL fixtures fail pre-existing; E2 suite
   carries the local shim and passes.

## E3/E4/E5 dependencies

- E3: IAM policy documents (`iam:GetPolicy*`), access-key metadata, privilege
  graph — none collected in E1/E2.
- E4: SG `IpPermissions`/`IpPermissionsEgress`, NACLs, VPC flow logs, route
  propagation — EC2-002 and VPC architecture risk need these.
- E5: S3 bucket policies/ACLs, versioning/MFA-delete, logging, encryption
  gaps beyond default SSE; RDS backup/retention/deletion-protection.
