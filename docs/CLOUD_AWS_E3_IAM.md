# CLOUD AWS E3 — IAM Security

## Architecture

E3 extends the E1/E2 foundation with deterministic IAM security analysis.

Flow:

```
AWS Connection (CloudConnection role_arn)
  -> Worker aws_discovery.discover_iam (global IAM enumeration)
  -> Normalized IAM evidence (bounded extra on cloud_resource assets)
     -> iam_policies (managed + inline, normalized statements)
     -> iam_trust_statements (role assume-role)
     -> iam_mfa_device_count / iam_mfa_devices
     -> iam_access_keys (suffix + hash, status, create/last_used)
     -> iam_password_enabled
  -> Backend cloud_checks evaluate_asset (AWS-IAM-001..008)
  -> FindingEngine (scanner=cloud, rule_id=AWS-IAM-*)
  -> AssetRelationship (cloud_account contains cloud_resource, existing taxonomy)
  -> RiskEngine, Dashboard, Alerts, Reports, Remediation, Retesting, Audit
```

No new tables. IAM identities reuse `cloud_resource` assets with `resource_type` in
`aws_iam_role / aws_iam_user / aws_iam_group` and canonical value `arn:aws:iam::<acct>:role|user|group/<name>` or fallback `cloud_resource:aws:<acct>:global:iam:<type>:<id>`.

## IAM Evidence Collection

Source: read-only IAM APIs via AssumeRole session (memory only). Bounded:

- `list_roles / list_users / list_groups` — 100 each
- Per identity: `list_attached_*_policies` + `get_policy` + `get_policy_version` (managed)
  `list_*_policies` + `get_*_policy` (inline) — max 20 policies/identity
- `get_role` trust fallback if ListRoles omitted AssumeRolePolicyDocument
- Users: `list_mfa_devices`, `list_access_keys` + `get_access_key_last_used` (5), `get_login_profile`
- Max 50 statements/policy, 200 actions/resources per statement, 50 principals

All paginated via `get_paginator` with `PageSize 50`, hard cap `MAX_TOTAL_RESOURCES 500`.

Errors: permission -> `*_unavailable = "permission_denied"` (→ NOT_ASSESSED), never silent PASS.
Throttling -> bounded retry (3 attempts, exponential). Other errors sanitized (no secrets).

No secret storage: no SecretAccessKey, no session token, no password hash, no raw AccessKeyId (only last-4 suffix + SHA256 16-char hash for correlation).

## Policy Normalization

`worker/app/iam_analysis.py`

- `decode_policy_document`: URL-decodes `%7B` style, JSON parses, size ≤64KB, malformed → NOT_ASSESSED/ERROR
- `normalize_policy_document`: `Statement` may be object or list; bounded truncation metadata (`truncated`, `reasons`)
  Each statement → `{effect, actions, resources, principals, sid, condition_keys, not_action/not_resource}` with bounded lists.
- `statement_identity`: SID if present else SHA256 of canonical sorted content (deterministic)
- Detectors: `has_wildcard_action`, `has_wildcard_resource`, `has_dangerous_action`, `has_wildcard_principal`, `has_external_account_principal`

Limits are fixed (env-configurable future): `MAX_POLICIES 20`, `MAX_STATEMENTS 50`, etc. String truncation 1024.

If truncation occurs, `iam_policies_truncated` / `iam_trust_truncated` flags are set.

## Trust Normalization

Role trust `AssumeRolePolicyDocument` normalized same as policy but preserves `principals`:
- `AWS:arn:aws:iam::123:root`, `AWS:*`, `Service:ec2.amazonaws.com`, `Federated:arn:...`

## Check Catalog

Provider `aws`, pack version `1.1` (E2 1.0 + IAM). All `enabled=True`.

| ID | Title | Resource Types | Severity | Condition |
|---|---|---|---|---|
| AWS-IAM-001 | IAM policy allows Action '*' | role/user/group | HIGH | Allow + Action "*" |
| AWS-IAM-002 | IAM policy allows wildcard Resource '*' | role/user/group | HIGH | Allow + Resource "*" |
| AWS-IAM-003 | IAM policy allows dangerous administrative actions | role/user/group | HIGH | Allow + action in `iam:*, organizations:*, sts:AssumeRole, kms:*, s3:*, ec2:*, lambda:*, cloudformation:*` focused set |
| AWS-IAM-004 | IAM role trust policy allows wildcard principal | role | CRITICAL | Allow + Principal "*" / "AWS:*" |
| AWS-IAM-005 | IAM role trusts an external AWS account | role | MEDIUM | Allow + AWS principal account ≠ own |
| AWS-IAM-006 | IAM user has no MFA configured | user | HIGH | mfa_device_count == 0 → FAIL, >0 → PASS, unavailable → NOT_ASSESSED |
| AWS-IAM-007 | IAM user has active access key older than 90 days | user | MEDIUM | Active key age >90d → FAIL, no active old → PASS, no date → NOT_ASSESSED |
| AWS-IAM-008 | IAM user has console password enabled without MFA | user | HIGH | password True + mfa 0 → FAIL, otherwise PASS/NOT_ASSESSED |

AWS-managed policies are **not** excluded automatically (spec §12): if reliably distinguishable (`arn:aws:iam::aws:policy/`) they are marked `is_aws_managed` but still evaluated; flag normally.

## Evidence Requirements & Result States

- Missing required evidence (`iam_policies` absent, `iam_mfa_unavailable`, `iam_trust_unavailable`) → NOT_ASSESSED, never PASS.
- Policy/statement present and condition absent → PASS
- Condition present → FAIL with bounded evidence (`policy`, `statement_index`, `sid`, observed/expected)
- Malformed document → `*_unavailable` with error → NOT_ASSESSED
- Evaluation exception → ERROR

Evidence stored in Finding `evidence` JSON (bounded 2000) + `extra_data` (`rule_id`, `resource_type`, `arn`, `region`, `account_id`, `discovery_run_id`, `observed_at`, `confidence 90/high`).

## Fingerprinting

Reuses `finding_lifecycle.d8_fingerprint` (rule_id + asset_type/asset_value + title normalization). Deterministic: same identity + same check + same statement → same fingerprint across discovery runs. Different identities/statements → different fingerprints. No scan/discovery IDs in fingerprint. Verified via `test_iam_remediation_d7` vectors.

## Discovery Provenance

Every IAM finding retains `discovery_run_id`, `connection_id`, `account_id`, `region`, `arn`, `observed_at` in `extra_data` + `evidence`. Asset metadata also stores `observed_at` from discovery time.

## Partial Discovery Behavior

If `list_*_policies` or `get_policy_version` is AccessDenied, the identity's `iam_policies_unavailable` is set and all IAM permission checks for that identity return NOT_ASSESSED with permission reason, preserving warnings in `cloud_discoveries.warnings`. No false PASS.

## Policy Attachment Handling

A dangerous managed policy attached to 20 users produces **identity-specific findings** (one per asset). This preserves traceability to affected identity while enabling correlation via `rule_id + asset_value`. No deduplication noise; bulk evaluation is O(N) with idempotent `UNIQUE(discovery_run_id)` check-run guard.

AWS-managed vs customer-managed distinguished via `is_aws_managed` flag; both analyzed where evidence available.

## Access Key & Password Handling

- Never retrieve/store `SecretAccessKey`, `SessionToken`, or password.
- Access keys: `id_suffix` (last 4) + `id_hash` (SHA256 16 chars), `status`, `create_date`, `last_used`
- MFA: count + serial prefix (100 chars) only
- Password: boolean `iam_password_enabled`, no hash

Redaction verified: `SECRET_KEY_RE` strips `secret/token/private/credential/password/access[_-]?key` from any persisted field via `_bounded_extra`.

## APIs

Reuse existing project-scoped auth (`require_project_access`):

- `GET /api/v1/projects/{id}/cloud/security-checks/catalog` — includes 8 IAM checks
- `POST /api/v1/projects/{id}/cloud/security-checks/run` — evaluates latest or specified `discovery_run_id`; idempotent per run
- `GET /api/v1/projects/{id}/cloud/security-checks/runs` + `/runs/{id}` — run history with `breakdown` per check
- `GET /api/v1/projects/{id}/cloud-security/iam` — IAM identities (roles/users/groups) with bounded policy/trust/mfa/key summary
- `GET /api/v1/projects/{id}/cloud-security/summary` — counts by provider including IAM findings
- `GET /api/v1/cloud/providers` — capability `iam_discovery: true`

All list APIs bounded (100/200), sanitized, 400 on invalid filter, 404 on missing project/run.

## RBAC / RLS

- IAM discovery enqueue: `analyst` or `project_admin` (or super_admin/org_admin bypass) — `_require_discover`
- Check execution: same `analyst`/`project_admin` — `_require_run`
- IAM listing: any project member (viewer+) via `require_project_access`
- Tenant isolation: `(project_id, asset_type, value)` unique; cross-project `discovery_run_id` mismatch → 400/404
- RLS: `set_rls_context` still applied via `protected` dependencies

## Audit

- `CLOUD_DISCOVERY_*` (queued/started/completed) already covers IAM discovery
- `CLOUD_CHECK_RUN_*` (requested/completed/partial) covers IAM evaluation
- `FINDING_CREATED` per IAM FAIL
- No audit per policy statement; no raw policy in audit metadata (only `check_id`, `discovery_run_id`)

## Security

- Read-only AWS: only `list_*`, `get_*`, `describe_*`; forbidden `Put*/Attach*/Detach*/Delete*/Update*/Create*` never called (verified via `rg` scan)
- No privileged containers, no Docker socket (worker via `docker-socket-proxy:2375`), isolated per-scan workspaces
- `SECRET_KEY_RE` redaction, `_bounded_extra` sanitization, `to_safe_dict` stripping
- Rate-limited via `call_with_retry` (throttling only, not permission), 32 region cap, 500 resource cap

## Limitations

- Service-linked AWS-managed policies are flagged normally (no auto-exclusion; `is_aws_managed` preserved for future allowlisting)
- Cross-account trust is MEDIUM “requires validation” — not auto-vulnerable
- MFA check is human-user oriented; service principals not distinguished beyond unavailable evidence
- Access key age uses `CreateDate` only; last-used is informational
- Policy versions beyond DefaultVersionId not evaluated
- No attack-path or graph analysis (E9)

## E4/E5/E9 Dependencies

- E4 network: SG ingress rule bodies needed for `AWS-EC2-002`
- E5 storage: bucket policy evaluation beyond PAB flags
- E9 graph: IAM intelligence (this E3) is prerequisite for trust/permission graph and attack-path phases

## Required AWS Permissions (read-only)

`iam:ListRoles`, `iam:ListUsers`, `iam:ListGroups`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListAttachedGroupPolicies`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `iam:GetLoginProfile`, `sts:AssumeRole`, `sts:GetCallerIdentity`

Missing any yields NOT_ASSESSED with `permission_denied`, never false PASS.
