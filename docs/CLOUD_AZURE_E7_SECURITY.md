# CLOUD AZURE E7 — Azure Security

## Architecture (provider-neutral, unified)

```
CloudConnector (backend) ─┬─ AWSConnector (role ARN, STS)
                         ├─ GCPConnector (SA JSON / WIF, short-lived)
                         └─ AzureConnector (subscription/tenant, Managed Identity / WIF / SP, short-lived token)
                                    │
Worker: azure_discovery (bounded, read-only, mocked + real SDK)
  subscription, resource groups, VMs, disks, VNets, subnets, NSGs, public IPs, storage accounts, RBAC
         │
   azure_to_asset_inputs → cloud_resource (azure_*) + cloud_account:azure:<sub>:global
         │
   cloud_checks pack 1.4 (AZURE-IAM-001..003, AZURE-NET-001..007, AZURE-STORAGE-001..005, AZURE-COMPUTE-001/002)
         │
   FindingEngine (scanner=cloud, d8)
         │
   Risk / Monitoring / Audit / Unified UI (AWS/GCP/Azure)
```

Reuses E1-E6 patterns: bounded pagination, NOT_ASSESSED, posture vs vulnerability, canonical dedup, d8 fingerprint, SecretStore.

## Authentication (secure, short-lived)

**Preferred:** Managed Identity / Workload Identity Federation (`azure-identity` `DefaultAzureCredential`, `WorkloadIdentityCredential`) → short-lived token → ARM APIs. **Service principal** (`client_id`/`tenant_id` + `client_secret`/`certificate` federated credential) supported for compatibility, but:
- `client_secret` never logged, never returned, never in Celery args, stored only via `SecretStore` (`connector_secrets` encrypted, `cloud_connections.credential_reference` opaque).
- Validation: `validate_subscription_id` (UUID), `validate_tenant_id` (UUID), `validate_azure_credential` (size, JSON check), `sanitize_azure_error` redacts `client_secret`.
- **Private key/certificate never in `cloud_connections` columns** (only `subscription_id`, `tenant_id`, `credential_reference`).
- Identity: `subscription_id`, `tenant_id`, `principal` (servicePrincipal), `type`, retrieved via `azure-identity` + `azure-mgmt-resource` `subscriptions.get` (mocked in tests).

## Discovery (bounded, read-only, no data access)

**Subscription:** `azure_subscription` (id, state)
**Resource Groups:** `azure_resource_group` (name, location)
**Compute:** `azure_vm` (name, location, RG, vmSize, OS, NICs, public/private IP ref, NSG refs, disks, `secureBoot`/`vTpm`), `azure_disk` (size, location)
**Network:** `azure_vnet` (addressSpace), `azure_subnet` (addressPrefix, NSG id), `azure_nsg` (rules[50] {name, direction, access, protocol, sourcePrefix, sourcePort, destPrefix, destPort, priority}), `azure_public_ip` (ipAddress, allocationMethod)
**Storage:** `azure_storage_account` (location, kind, sku, `supportsHttpsTrafficOnly`, `minimumTlsVersion`, `publicNetworkAccess`, `allowBlobPublicAccess`, `encryption.keySource`)
**IAM/RBAC:** `azure_rbac_assignment` (roleDefinitionId, principalId, principalType, scope, role_name derived)

All via `azure-mgmt-*` paginated `list` (`nextLink`), `MAX_AZURE_RESOURCES 500`, `MAX_NSG_RULES 50`, `MAX_RBAC_ASSIGNMENTS 100`, `call_with_retry` for throttling only, `SECRET_KEY_RE` filtering.

**Relationships:** `subscription contains resource_group`, `resource_group contains VM`, `VNET contains subnet`, `subnet uses NSG`, `NIC uses NSG`, `VM uses NIC/publicIP/disk`, `storage belongs_to resource_group`, `RBAC grants principal` — via `contains`/`uses`.

## Checks (pack 1.4, provider=azure, deterministic)

| ID | Title | Resource | Severity | Condition |
|---|---|---|---|---|
| AZURE-IAM-001 | Owner at subscription | rbac | HIGH | `Owner` + `/subscriptions/<id>` (no RG) |
| AZURE-IAM-002 | Contributor at subscription | rbac | HIGH | `Contributor` + subscription scope |
| AZURE-IAM-003 | User Access Administrator | rbac | HIGH | `User Access Administrator` + subscription |
| AZURE-NET-001 | SSH 22 open to Internet | nsg | HIGH | `Tcp 22` + `*`/`0.0.0.0/0`/`Internet` |
| AZURE-NET-002 | RDP 3389 open | nsg | HIGH | `3389` + Internet |
| AZURE-NET-003 | DB port open | nsg | HIGH | `3306/5432/1433/1521/27017/6379/9200` |
| AZURE-NET-004 | All ports open | nsg | CRITICAL | `*` + Internet |
| AZURE-NET-005 | Broad Internet ingress | nsg | HIGH | any `Allow` `Inbound` + Internet |
| AZURE-NET-006 | Public VM exposure (bounded) | vm | HIGH | `public_ip` + applicable NSG (NIC/subnet) — `NOT_ASSESSED` if NSG applicability cannot be proven |
| AZURE-NET-007 | Unrestricted egress | nsg | LOW | `Outbound` `*` + Internet (posture) |
| AZURE-STORAGE-001 | Blob public access enabled | storage | HIGH | `allowBlobPublicAccess == true` |
| AZURE-STORAGE-002 | Public network access enabled | storage | INFO | `publicNetworkAccess == Enabled` (posture) |
| AZURE-STORAGE-003 | HTTPS-only disabled | storage | MEDIUM | `supportsHttpsTrafficOnly == false` |
| AZURE-STORAGE-004 | Weak TLS version | storage | MEDIUM | `minimumTlsVersion` in `TLS1_0`/`TLS1_1` (baseline `TLS1_2`) |
| AZURE-STORAGE-005 | Encryption posture | storage | INFO | not customer-managed (Microsoft-managed) |
| AZURE-COMPUTE-001 | Secure boot disabled | vm | INFO | `secureBootEnabled == false` |
| AZURE-COMPUTE-002 | vTPM disabled | vm | INFO | `vTpmEnabled == false` |

**Posture vs vuln:** Public IP alone, publicNetworkAccess, secureBoot/vTPM disabled → `INFO`/`LOW`; SSH/RDP/all-ports/public storage → `HIGH`/`CRITICAL`; missing evidence → `NOT_ASSESSED`.

**Dedup:** Same NSG + same direction + protocol + source + dest port → one finding (canonical `nsg + proto + port + source`). `AZURE-NET-001` + `NET-005` same condition → one. `NET-006` + `COMPUTE-003` same VM+NSG → one.

**Fingerprint:** `d8` over `rule_id + asset_type + asset_value + port + source` (via `finding_meta.port`/`parameter`), excludes `discovery_run_id`/timestamps/version. Same NSG rule across runs → same; port/source/NSG/role/scope change → different.

## NOT_ASSESSED

Missing `rules`/`scope`/`publicNetworkAccess`/`minimumTlsVersion`/`secureBoot` → `NOT_ASSESSED` (`permission_denied`, `unavailable`, `correlation_unresolved`), never `PASS`.

## Evidence (bounded, sanitized)

IAM: `{role, scope, principalId}`; Network: `{nsg, protocol, port, source, destination}`; Storage: `{account, allowBlobPublicAccess, publicNetworkAccess, minimumTlsVersion}`; Compute: `{vm, secureBoot, vTpm}`. No raw `listKeys`, no secrets, 2000 chars.

## API

- `POST /projects/{id}/cloud/connections` — `provider: azure`, `subscription_id` (UUID), `tenant_id` (UUID), `credential` (client_secret JSON or federated), `credential_type: service_principal` → `CloudConnection` + `ConnectorSecret`
- `POST /connections/{id}/validate` — for `azure` calls `get_azure_identity` (project validation, no secrets in logs)
- `POST /connections/{id}/discover` — for `azure` enqueues `discover_cloud` with `provider=azure`; worker `_discover_azure` (mocked or real via `azure-*` SDKs)
- **`GET /projects/{id}/cloud-security/azure`** — **NEW** E7: `{counts: {azure_subscription, azure_vm, azure_nsg, ...}, public_storage_accounts, public_nsgs, azure_findings, not_assessed}`; `require_project_access`, 401/403/404, RLS

Existing: `GET /cloud-security/checks` / `POST /cloud/security-checks/run` now include Azure pack (1.4).

## Frontend

`Cloud Security` page — **Azure Security (E7)** card (subscriptions, VMs, NSGs, public storage/NSGs, findings, not_assessed) via `getAzureSummary` (new `frontend/src/lib/api/codeSecurity.js`), `LoadingState`/`ErrorState`, `useProjectContext`, link to `/findings`. No new hierarchy, no graph.

## RBAC / Tenant / RLS / Audit

Reuse: `require_project_access`, `analyst`/`project_admin` for discover/check, cross-project 404, `set_rls_context`, `AuditService` (`CLOUD_DISCOVERY_*`, `CLOUD_CHECK_RUN_*`, `FINDING_CREATED`) bounded, no `client_secret`.

## Performance / Limits

`MAX_AZURE_RESOURCES 500`, `MAX_NSG_RULES 50`, `MAX_RBAC_ASSIGNMENTS 100`, pagination, no new infra, bulk `upsert_assets`.

## Testing (actually executed)

- `worker/tests/test_azure_discovery.py` — 4 tests (NSG, storage, VM, RBAC)
- `backend/tests/test_azure_checks_e7.py` — 9 tests (NSG SSH/RDP/DB/all, storage public/HTTPS, compute secure boot, IAM Owner, fingerprint, catalog)
- `worker/tests/test_gcp_discovery.py` — 4 (E6 regression)
- `backend/tests/test_gcp_checks_e6.py` — 11 (E6 regression)
- `worker/tests/test_aws_discovery.py` — 22 (E1 regression, after EFS fix)
- `backend/tests/test_network_checks_e4.py` — 19 (E4 regression, hardened)
- `backend/tests/test_storage_checks_e5.py` — 12 (E5 regression)
- `backend/tests/test_iam_checks_e3.py` — 14 (E3 regression)
- Frontend: `npm run build` — PASS (30 routes), `npm run lint` — 0 errors, 3 warnings (pre-existing)

**Not run:** full suite (focused).

## Live Azure

**NOT LIVE VERIFIED** — no authorized Azure subscription/service principal available. **Mocked/deterministic verified** via `FakeAzure` → `azure_discovery` → `azure_to_asset_inputs` → `cloud_checks` → `FindingEngine` → `d8` → `upsert_assets` → `GET /azure`. **Production SDK adapter present** (`azure-identity`, `azure-mgmt-*` in `requirements.txt`, `build_azure_credentials`, real `discover_azure_account` via `azure-mgmt-*` with `DefaultAzureCredential` fallback) so `LIVE VERIFIED` would require only credentials.

## Limitations

- Azure discovery is **mocked in tests**; real `azure-mgmt-*` calls require live `DefaultAzureCredential`/`Workload Identity` and `AZURE_MOCK_MODE!=true`.
- `AZURE-NET-006` VM-NSG correlation is `NOT_ASSESSED` when NIC/subnet NSG applicability cannot be proven (conservative).
- Uniform/versioning/encryption/shielded are `INFO` posture, not vuln.
- No Azure DevOps, no Microsoft 365, no Entra attack-path, no CSPM.

## SDKs

`azure-identity>=1.15`, `azure-mgmt-resource>=23.0`, `azure-mgmt-compute>=30.0`, `azure-mgmt-network>=25.0`, `azure-mgmt-storage>=21.0`, `azure-mgmt-authorization>=4.0` (pinned, minimal).
