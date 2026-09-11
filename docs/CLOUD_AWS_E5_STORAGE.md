# CLOUD AWS E5 — Storage Security

## Architecture

E5 extends E1 (discovery), E2 (checks), E3 (IAM policy normalization), E4 (posture vs vulnerability, dedup, fingerprint) with deterministic storage security.

```
AWS Connection (AssumeRole, temp creds memory-only)
 -> worker/aws_discovery (global S3 + regional EBS/EFS/RDS)
   S3: bucket, region, PAB, encryption, policy (normalized), ACL, versioning, logging, ownership, website
   EBS: volume (encrypted, KMS, size, AZ, attached instance)
   Snapshots: encrypted, KMS, is_public (createVolumePermission)
   EFS: filesystem (encrypted, KMS)
   RDS: storage_encrypted (reuse E2)
 -> cloud_resource assets (extra JSON, bounded, sanitized)
 -> backend/cloud_checks pack 1.3 (S3-003..008, EBS-001/002, EFS-001) + existing S3-001/002, RDS-002
 -> FindingEngine (scanner=cloud, d8 fingerprint)
 -> Risk, Dashboard, Storage API, Audit
```

No new tables; reuses `cloud_resource`/`cloud_account`, `Finding`.

## Discovery (read-only, bounded)

**S3 (global, 100 buckets):** `list_buckets` + per-bucket `get_bucket_location`, `get_public_access_block`, `get_bucket_encryption` (SSEAlgorithm + KMSMasterKeyID), `get_bucket_policy` (normalized via `iam_analysis` 20 stmts), `get_bucket_acl` (20 grants, public AllUsers/AuthenticatedUsers), `get_bucket_versioning`, `get_bucket_logging`, `get_bucket_ownership_controls`, `get_bucket_website`. No object enumeration, no download.

**EBS (regional, 100 volumes):** `describe_volumes` → `volume_id, encrypted, kms_key_id, size, AZ, state, attached_instance`.

**Snapshots (100, OwnerIds=self):** `describe_snapshots` + `describe_snapshot_attribute` (createVolumePermission) → `is_public` (group all). Bounded 20 per snapshot.

**EFS (100):** `describe_file_systems` → `encrypted, kms_key_id`.

Bounds: `MAX_S3_POLICY_STATEMENTS 20`, `MAX_SG_RULES 50` etc., pagination `PageSize 50`, retry 3 for throttling only. Errors sanitized, `SECRET_KEY_RE` strips secrets, `is_public` etc. stored bounded.

**Relationships:** `cloud_account contains` all; `volume uses instance`, `snapshot uses volume`, `EFS contains in VPC` via `uses`/`contains` (existing taxonomy).

## Checks (pack 1.3)

Existing S3-001 (PAB disabled, HIGH) and S3-002 (encryption, MEDIUM) and RDS-002 (RDS encrypted, HIGH) retained from E2. E5 adds:

| ID | Title | Resource | Severity | Condition |
|---|---|---|---|---|
| AWS-S3-003 | S3 bucket allows public access via policy | s3 bucket | CRITICAL | Allow + Principal * + s3:GetObject etc. |
| AWS-S3-004 | S3 weak encryption posture (SSE-S3) | s3 | INFO | `AES256` not `aws:kms` (posture) |
| AWS-S3-005 | S3 public ACL grant | s3 | HIGH | AllUsers/AuthenticatedUsers with READ etc., not BucketOwnerEnforced |
| AWS-S3-006 | S3 versioning disabled (posture) | s3 | INFO | `versioning != Enabled` |
| AWS-S3-007 | S3 logging disabled (posture) | s3 | INFO | `logging_enabled == False` |
| AWS-S3-008 | S3 object ownership weak (posture) | s3 | INFO | `object_ownership != BucketOwnerEnforced` |
| AWS-EBS-001 | EBS volume unencrypted | ebs volume | HIGH | `encrypted == False` |
| AWS-EBS-002 | EBS snapshot shared publicly | ebs snapshot | CRITICAL | `is_public == True` |
| AWS-EFS-001 | EFS filesystem unencrypted | efs | HIGH | `encrypted == False` |

**Posture vs vulnerability:** Versioning/logging/ownership/weak encryption are `INFO` posture, not critical. Public exposure is `CRITICAL`/`HIGH`.

**NOT_ASSESSED:** Missing `bucket_policy_statements`/`acl_grants`/`encryption` etc. → `not_assessed` with `permission_denied`/`unavailable`, never `PASS`.

**Dedup:** Same bucket+condition → one finding; different buckets or different conditions (public vs unencrypted) → separate. Relies on `d8` (rule_id + asset_value + port/source). E4 dedup for SG still applies.

**Fingerprint:** `d8` over `rule_id + asset_type + asset_value (+ port/source)`; `discovery_run_id`/`timestamps` excluded. Same bucket across runs → same fingerprint; different bucket/action → different.

## APIs

- `GET /projects/{id}/cloud-security/storage` — new E5: `{counts: {s3, ebs volume/snapshot, efs, rds}, public_s3_buckets, unencrypted_ebs_volumes, public_snapshots, unencrypted_efs, storage_findings, not_assessed}`; `require_project_access`, 401/403/404, RLS.

Existing: `GET /cloud-security/summary`, `GET /cloud-security/network`, `GET /cloud-security/checks` (now 1.3 includes S3-003..008, EBS, EFS), `POST /cloud/security-checks/run` (idempotent, 19 checks).

No raw policies in summary; bounded evidence in findings.

## Frontend

`Cloud Security` page — new **Storage Security (E5)** card: S3 buckets, public S3, EBS volumes, unencrypted EBS, public snapshots, storage findings, not_assessed. Uses `getStorageSummary`, `LoadingState`/`ErrorState`, `useProjectContext`, link to `/findings`. No graph, no new hierarchy.

## RBAC / Tenant

All E5 endpoints `require_project_access`; check run requires `analyst`/`project_admin`; cross-project 404; `set_rls_context` via `protected`. Tenant isolation via `(project_id, asset_type, value)`.

## Audit

`CLOUD_CHECK_RUN_*` + `FINDING_CREATED` per storage FAIL; audit metadata `check_id` only, no raw policies, bounded.

## Performance / Limits

Same E1 limits + E5 storage bounds; no new infra; bulk persistence; no N+1.

## Testing (actually executed)

- `worker/tests/test_storage_discovery.py` — 7 tests (public policy, ACL, versioning/logging, EBS volume/snapshot, EFS)
- `backend/tests/test_storage_checks_e5.py` — 12 tests (S3 public/ACL, versioning/logging/ownership, weak encryption, EBS/EFS, fingerprint, catalog)
- `worker/tests/test_iam_analysis.py` — 16 (E3 regression)
- `backend/tests/test_iam_checks_e3.py` — 14 (E3 regression)
- `worker/tests/test_network_discovery.py` — 6 (E4 regression)
- `backend/tests/test_network_checks_e4.py` — 19 (E4 regression, now 19 with hardening)
- `worker/tests/test_aws_discovery.py` — 22 (E1 regression)
- Frontend: `npm run build` — PASS (30 routes), `npm run lint` — 0 errors, 3 warnings (pre-existing).

**Not run:** full suite (resource-efficient focused); E2 cloud regression previously verified.

## Live AWS

**NOT LIVE VERIFIED** — no authorized AWS account/role available. **Mocked/deterministic verified** via `FakeClient` + real discovery + `cloud_checks` + `FindingEngine` + `d8`. No mutation, no object access.

## Limitations

- S3 public requires policy/ACL evidence; PAB disabled alone is LOW/MEDIUM via existing S3-001, not auto-critical.
- Encryption `AES256` is posture (INFO), not vulnerability; `aws:kms` is pass.
- Versioning/logging/ownership are INFO posture.
- Snapshot public requires `describe_snapshot_attribute` permission; else `NOT_ASSESSED`.
- No object enumeration, no E5 storage attack-path (E9).
