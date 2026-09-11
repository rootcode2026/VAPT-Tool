# CLOUD GCP E6 — GCP Security

## Architecture (provider-neutral)

```
CloudConnector (backend) ─┬─ AWSConnector (role ARN, AssumeRole, STS)
                         └─ GCPConnector (project_id, SA JSON / WIF, sanitized)
                                    │
Worker: gcp_discovery (mocked, bounded, read-only)
  project, compute Engine (instances, disks), VPC, subnets, firewalls, storage buckets, IAM bindings, SA
         │
   gcp_to_asset_inputs → cloud_resource (gcp_*) + cloud_account:gcp:<project>:global
         │
   cloud_checks pack 1.4 (GCP-IAM-001..004, GCP-NET-001..005, GCP-GCS-001..004, GCP-COMPUTE-001/002)
         │
   FindingEngine (scanner=cloud, d8)
         │
   Risk / Monitoring / Audit / UI
```

Reuses E1-E5 patterns: bounded pagination, `NOT_ASSESSED`, posture vs vulnerability, canonical dedup, `d8` fingerprint.

## Authentication

- **Preferred:** Workload Identity Federation (`workload_identity_provider` + `service_account`) — no long-lived key.
- **Compat:** Service-account JSON — validated via `validate_service_account_json` (checks `project_id`, `client_email`, size 16KB), **private_key never persisted**, never logged, never in audit (sanitized via `sanitize_gcp_error`).
- Identity: `project_id`, `principal` (SA email or `project:<id>`), type. `get_gcp_identity` is mocked for tests; real would call `google.auth` + Resource Manager.

Secrets: `ConnectorSecret` holds ciphertext if SA JSON provided; `credential_reference` opaque; `to_safe_dict` strips `private_key`.

## Discovery (bounded, read-only, no object access)

**Project:** `gcp_project` (project_id, lifecycle_state).

**Compute Engine:** `gcp_compute_instance` (name, zone, machineType, network, subnet, external IP `natIP`, internal IP, serviceAccount, shielded VM `enableSecureBoot`, status, attached disks), `gcp_disk` (size, zone).

**VPC Network:** `gcp_vpc` (autoCreateSubnetworks, routingMode), `gcp_subnet` (network, cidr, region, privateIpGoogleAccess), `gcp_firewall` (network, direction, priority, sourceRanges, destinationRanges, allowed[] {protocol, ports[]}, targetTags/SAs, disabled) — all bounded 50, ports 20.

**Storage:** `gcp_storage_bucket` (name, location, storageClass, uniformBucketLevelAccess, public IAM `public_iam_members[20]` {role, member}, versioning, encryption `defaultKmsKeyName`, logging) — no objects.

**IAM:** `gcp_iam_policy` (bindings[50] {role, members[20]}) via `get_iam_policy`, `gcp_service_account` (email, displayName, disabled, keys[10] {key_id, validAfter/Before} — **no private material**).

All via `get_paginator` `PageSize 50`, `MAX_GCP_RESOURCES 500`, `call_with_retry` for throttling only. `SECRET_KEY_RE` filtering, `_bounded_extra` depth 3.

**Relationships:** `project contains` all; `VPC contains subnet`; `VM uses serviceAccount`; `Bucket belongs_to project` (via account contains). Reuses `contains`/`uses`.

## Checks (pack 1.4, provider=gcp, deterministic)

| ID | Title | Resource | Severity | Condition |
|---|---|---|---|---|
| GCP-IAM-001 | Public IAM member | iam_policy, bucket | CRITICAL | `allUsers`/`allAuthenticatedUsers` in bindings |
| GCP-IAM-002 | Excessive owner/editor | iam_policy | HIGH | `roles/owner` or `roles/editor` |
| GCP-IAM-003 | Privileged service account | iam_policy | HIGH | `serviceAccount:*` with owner/editor |
| GCP-IAM-004 | SA key >90d | service_account | MEDIUM | `validAfterTime` >90d (no private) |
| GCP-NET-001 | SSH 22 open to Internet | firewall | HIGH | `tcp 22` + `0.0.0.0/0` |
| GCP-NET-002 | RDP 3389 open | firewall | HIGH | `tcp 3389` + `0.0.0.0/0` |
| GCP-NET-003 | DB port open | firewall | HIGH | `3306/5432/1433/1521/27017/6379/9200` |
| GCP-NET-004 | All ports open to Internet | firewall | CRITICAL | `all`/`-1` + `0.0.0.0/0` |
| GCP-NET-005 | Broad Internet ingress | firewall | HIGH | any allowed + `0.0.0.0/0` |
| GCP-GCS-001 | Public bucket (allUsers) | bucket | CRITICAL | `allUsers` in `public_iam_members` |
| GCP-GCS-002 | Uniform access disabled (posture) | bucket | INFO | `uniformBucketLevelAccess != true` |
| GCP-GCS-003 | Versioning disabled (posture) | bucket | INFO | `versioning != Enabled` |
| GCP-GCS-004 | Weak encryption (posture) | bucket | INFO | not CMEK (`defaultKmsKeyName` missing) |
| GCP-COMPUTE-001 | Shielded VM disabled (posture) | instance | INFO | `shielded_vm != true` |
| GCP-COMPUTE-002 | VM public IP + permissive (bounded) | instance | HIGH | `external_ip` present → `NOT_ASSESSED` until firewall correlation proven |

**Posture vs vuln:** Public/SSH/RDP/DB → `CRITICAL`/`HIGH`; versioning/uniform/shielded → `INFO`/`LOW` posture; missing evidence → `NOT_ASSESSED` (never `PASS`).

**Dedup:** Same firewall + same port + same source → one finding (canonical key `firewall + proto + port + cidr`). Different ports/sources → separate.

**Fingerprint:** `d8` over `rule_id + asset_type + asset_value + port + source_cidr` (via `finding_meta.port`/`parameter`), excludes `discovery_run_id`/`timestamps`/`version`. Same rule across runs → same; port/source/resource change → different. Verified.

## NOT_ASSESSED

Missing `bindings`/`allowed`/`source_ranges`/`public_iam_members`/`shielded_vm` → `NOT_ASSESSED` (`permission_denied`, `unavailable`, `inherited_policy_unresolved`). Never `PASS`.

## Evidence (bounded, sanitized)

IAM: `{project, role, member}`; Network: `{firewall, protocol, port, source}`; Storage: `{bucket, member, role}`; Compute: `{instance, shielded_vm}`. No raw `getIamPolicy` payload, no private keys.

## API

- `POST /projects/{id}/cloud/connections` — now accepts `provider: gcp`, `project_id`, `service_account_json` or `workload_identity_*`; validates `project_id`, stores SA JSON as `ConnectorSecret` if provided, else mock; `credential_type: service_account`.
- `POST /connections/{id}/validate` — for `gcp` calls `_validate_gcp_connection` (project validation, no secrets in logs).
- `POST /connections/{id}/discover` — for `gcp` enqueues `discover_cloud` with `provider=gcp`; worker `discover_cloud` branches to `_discover_gcp`.
- `GET /projects/{id}/cloud-security/gcp` — new E6: `{counts: {gcp_project, compute, firewall, bucket, ...}, public_buckets, public_firewalls, gcp_findings, not_assessed}`; `require_project_access`, 401/403/404, RLS.
- `GET /projects/{id}/cloud-security/checks` / `POST /cloud/security-checks/run` — now include GCP pack (1.4) via same `FindingEngine` (scanner `cloud`).

## Frontend

`Cloud Security` page — new **GCP Security (E6)** card (projects, VMs, firewalls, public buckets/firewalls, findings, not_assessed) via `getGcpSummary`, `LoadingState`/`ErrorState`, `useProjectContext`, link to `/findings`. No graph.

## RBAC / Tenant / RLS / Audit

Reuse existing: `require_project_access`, `analyst`/`project_admin` for discover/check, cross-project 404, `set_rls_context`, `AuditService` (`CLOUD_DISCOVERY_*`, `CLOUD_CHECK_RUN_*`, `FINDING_CREATED`) with bounded metadata, no private keys.

## Performance / Limits

`MAX_GCP_RESOURCES 500`, `MAX_FIREWALL_RULES 50`, `MAX_IAM_BINDINGS 50`, pagination 50, no new infra, bulk persistence.

## Testing (actually executed)

- `worker/tests/test_gcp_discovery.py` — 4 tests (firewall, storage public, IAM bindings, compute)
- `backend/tests/test_gcp_checks_e6.py` — 11 tests (IAM public/owner, firewall SSH/RDP/DB/all, storage public, versioning, compute shielded, fingerprint, catalog)
- `worker/tests/test_storage_discovery.py` — 7 (E5 regression)
- `backend/tests/test_storage_checks_e5.py` — 12 (E5 regression)
- `worker/tests/test_aws_discovery.py` — 22 (E1 regression, updated for EFS)
- `backend/tests/test_network_checks_e4.py` — 19 (E4 regression)
- Frontend: `npm run build` — PASS (30 routes), `npm run lint` — 0 errors, 3 warnings (pre-existing).

**Not run:** full suite (focused).

## Live GCP

**NOT LIVE VERIFIED** — no authorized GCP project/service identity available. **Mocked/deterministic verified** via `FakeClient` + `FakePaginator` + real `gcp_discovery` + `cloud_checks` + `FindingEngine` + `d8` + persistence path.

## Limitations

- GCP discovery is mocked (no real `google-cloud-*` calls in tests); real deployment needs `google-auth` + GCP APIs.
- Firewall target-tag matching for `GCP-COMPUTE-002` is bounded (`NOT_ASSESSED` until proven).
- Uniform/versioning/encryption/shielded are `INFO` posture, not vuln.
- No Azure, no CSPM, no attack-path graph.
