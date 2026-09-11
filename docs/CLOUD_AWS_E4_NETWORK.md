# CLOUD AWS E4 — Network Security

## Architecture

E4 extends E1/E2/E3 with deterministic network exposure analysis.

```
AWS Connection (AssumeRole, temp creds memory-only)
 -> worker/aws_discovery (regional EC2 + global)
   VPC, subnet, route_table, IGW, NAT, NACL, ENI, SG, EC2, LB (bounded)
 -> cloud_resource assets (extra JSON, sanitized, bounded)
 -> backend/cloud_checks (pack 1.2: EC2-002 + NET-001..010)
 -> FindingEngine (scanner=cloud, fingerprint d8)
 -> Risk, Dashboard, Alerts, Reports, Audit
```

No new tables; reuses `cloud_resource`/`cloud_account`, `Finding`, `AssetRelationship`.

## Discovery

Read-only EC2 APIs: `describe_vpcs`, `describe_subnets`, `describe_route_tables`, `describe_security_groups`, `describe_internet_gateways`, `describe_nat_gateways`, `describe_network_acls`, `describe_network_interfaces`, `describe_instances`, `describe_load_balancers` + `describe_listeners`.

Bounds: `MAX_TOTAL_RESOURCES 500`, `MAX_ITEMS_PER_SERVICE_CALL 100`, `MAX_SG_RULES 50`, `MAX_NACL_ENTRIES 50`, `MAX_ROUTE_ENTRIES 20`, pagination `PageSize 50`, 3 retries for throttling only.

Evidence per resource (sanitized, bounded):

- VPC: `cidr`, `ipv6_cidr`, `state`, `is_default`, `tenancy`
- Subnet: `vpc_id`, `cidr`, `ipv6_cidr`, `az`, `map_public_ip`, `available_ip`
- Route Table: `routes[]` (dest cidr/ipv6, gw, nat, tgw, state) + `associations[]` (subnet, main)
- IGW: `vpc_id`, `attachments[]`
- NAT: `vpc_id`, `subnet_id`, `state`, `connectivity_type`, `addresses[]`
- NACL: `vpc_id`, `subnet_ids`, `entries[]` (rule_number, protocol, action, egress, cidr, ports)
- SG: `vpc_id`, `ingress[]`, `egress[]` each normalized to `{protocol, from_port, to_port, cidr_v4, cidr_v6, group_ids, prefix_list_ids}` (bounded 50)
- ENI: `vpc_id`, `subnet_id`, `security_groups`, `private_ip`, `private_ips`, `public_ip`, `interface_type`
- EC2: `vpc_id`, `subnet_id`, `security_groups`, `public_ip`, `private_ip`, `imds_v2_enforced`
- LB: `vpc_id`, `subnets`, `security_groups`, `scheme`, `listeners[]`

Credentials never persisted; errors sanitized via `sanitize_aws_error`; `SECRET_KEY_RE` strips secrets.

## Evidence Model

All network evidence lives in `asset.extra_data` (`cloud_resource`). Asset identity is ARN or `cloud_resource:aws:<acct>:<region>:<service>:<type>:<id>`. Project isolation via `(project_id, asset_type, value)`.

Relationships reuse `contains`/`uses` (VPC contains subnet, subnet contains ENI, ENI uses SG, etc.) via `to_relationship_inputs`.

## Checks

Pack `1.2` (E2 1.0 + E3 1.1 + E4). All `provider=aws`, `enabled=True`.

| ID | Title | Resource | Severity | Condition |
|---|---|---|---|---|
| AWS-EC2-002 | SG allows unrestricted Internet ingress 0.0.0.0/0 | aws_security_group | HIGH | ingress with 0.0.0.0/0 or ::/0 |
| AWS-NET-001 | Internet-facing SG broad ingress | aws_security_group | HIGH | same (canonical dedup with EC2-002 → one finding per SG+proto+ports+cidr) |
| AWS-NET-002 | SSH 22 open to Internet | aws_security_group | HIGH | 22/tcp + 0.0.0.0/0 |
| AWS-NET-003 | RDP 3389 open to Internet | aws_security_group | HIGH | 3389/tcp + 0.0.0.0/0 |
| AWS-NET-004 | SG permits Internet to DB port | aws_security_group | HIGH | 3306/5432/1433/1521/27017/6379/9200 + 0.0.0.0/0 |
| AWS-NET-005 | SG allows all ports/protocols 0.0.0.0/0 | aws_security_group | CRITICAL | proto -1 + 0.0.0.0/0 |
| AWS-NET-006 | Public subnet exposure (posture) | aws_subnet | INFO | route 0.0.0.0/0 → igw- → exposure intelligence, **not a vulnerability finding** (tracked in network summary) |
| AWS-NET-007 | Public EC2 exposure | aws_ec2_instance | HIGH | public_ip + public subnet + permissive SG (bounded correlation; else NOT_ASSESSED) |
| AWS-NET-008 | Internet-facing LB permissive | aws_alb/nlb/elb | MEDIUM | scheme internet-facing + HTTP listener |
| AWS-NET-009 | NACL allows broad Internet ingress | aws_network_acl | HIGH | 0.0.0.0/0 allow -1 or all ports |
| AWS-NET-010 | SG unrestricted egress 0.0.0.0/0 all | aws_security_group | LOW | egress -1 + 0.0.0.0/0 |

EC2-002 was deferred in E2, now implemented. EC2-002 / NET-001 produce **one canonical finding** per SG+proto+ports+cidr (deduplicated).

Severity is conservative: all-port → CRITICAL, sensitive ports → HIGH, broad → HIGH, egress → LOW (default AWS). NET-006 is INFO posture, not a vulnerability.

## NOT_ASSESSED

Missing `ingress`/`egress`/`entries`/`scheme`/`routes` → `NOT_ASSESSED` with reason (`ingress unavailable`, `permission_denied`, etc.), never PASS. Cross-asset insufficient evidence also → `NOT_ASSESSED`.

## Fingerprinting

`d8_fingerprint` over `rule_id + asset_type + asset_value + title + port + source_cidr` (port/source via `finding_meta.port`/`parameter`). No scan/run IDs, no timestamps. Stable across runs and scanner version changes. Distinct for different SG, rule condition, protocol, ports, source CIDR (0.0.0.0/0 vs ::/0), resource. EC2-002/NET-001 canonical dedup uses SG+proto+ports+cidr key to emit one finding. Verified: same condition across runs → same fingerprint, version change → same, port/source/resource change → different.

## APIs

- `GET /projects/{id}/cloud-security/summary` — existing
- `GET /projects/{id}/cloud-security/network` — **new** E4: counts per type, `public_subnets`, `exposed_security_groups`, `network_findings`, `not_assessed`
- `GET /projects/{id}/cloud-security/checks` — catalog now includes 11 network checks
- `POST /projects/{id}/cloud/security-checks/run` — evaluates network checks (idempotent)
- `GET /cloud/security-checks/catalog` — pack 1.2
All `require_project_access`, 401/403/404 per RBAC, RLS via `set_rls_context`.

## RBAC / Tenant

All E4 endpoints reuse `require_project_access`; check execution requires `analyst`/`project_admin`; cross-project/tenant 404; project isolation via `project_id`.

## Audit

`CLOUD_CHECK_RUN_*` + `FINDING_CREATED` per network FAIL; no raw routes/rules in audit metadata (only `check_id`).

## Performance / Limits

Same caps as E1/E3; no new services; bulk persistence; `MAX_EVAL_ASSETS 500`; helper functions pure, no recursion.

## Testing (actually executed)

- `worker/tests/test_network_discovery.py` — 6 tests (SG normalize, route, NACL, VPC IPv6)
- `backend/tests/test_network_checks_e4.py` — 19 tests (EC2-002, NET-002/003/004/005/010, NACL, IPv6, internal-ref, NOT_ASSESSED, LB, catalog, NET-006 posture, fingerprint same/different, dedup)
- `worker/tests/test_iam_analysis.py` — 16 tests (E3 regression)
- `backend/tests/test_iam_checks_e3.py` — 14 tests (E3 regression)
- `worker/tests/test_aws_discovery.py` — 22 tests (E1 regression)
- Existing E2 cloud regression: previously verified; not rerun during E4 hardening.
- Frontend build: `npm run build` — PASS (30 routes); `npm run lint` — 0 errors, 3 warnings (pre-existing).

## Live AWS

**NOT LIVE VERIFIED** — no authorized AWS account/role available. **Mocked/deterministic verified** via `FakeClient`/`FakePaginator` + real `aws_discovery` + `cloud_checks.evaluate_asset` + `d8_fingerprint` + persistence path. No mutation, no resource creation.

## Limitations (remaining)

- Public subnet (NET-006) is posture/exposure, not a vulnerability finding; tracked in `network summary` (`public_subnets`, `exposed_security_groups`), not as a MEDIUM finding.
- Public subnet and EC2 cross-asset correlation is bounded deterministic (IGW route + SG), not full graph (F1 deferred); insufficient evidence → NOT_ASSESSED.
- NACL requires `describe_network_acls` permission; else NOT_ASSESSED.
- Egress default is LOW informational, not CRITICAL; EC2-002/NET-001 deduplicated to one canonical finding per SG+proto+ports+cidr.

## Future

E5 storage, CSPM, attack-path graph (E9) will consume this E4 intelligence.
