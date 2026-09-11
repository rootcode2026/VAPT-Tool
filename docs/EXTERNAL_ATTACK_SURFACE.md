# EXTERNAL ATTACK SURFACE E15 — Intelligence

## Architecture

```
ExternalScope (org/project)
  └─ ExternalScopeEntry (DOMAIN/SUBDOMAIN/IP/CIDR/URL, AUTHORIZED/PENDING/REJECTED)
        ↓
  DiscoveryProvider (passive: subfinder/DNS, active: nmap/http/TLS/Nuclei)
        ↓ (bounded, SSRF protected, authorized scope only)
  Asset Intelligence (Asset, AssetRelationship)
        ↓
  Ownership Confidence (CONFIRMED/HIGH/MEDIUM/LOW/UNKNOWN/REJECTED)
        ↓
  Exposure Classification (INTERNET_FACING_*)
        ↓
  Change Detection (D1/D2 reuse, run-scoped, idempotent)
        ↓
  Correlation (E12), Exposure (E11), Attack Paths (E9), Investigation (E13), Validation (E14)
```

No graph DB, no AI, no dark-web, no arbitrary Internet scanning. Passive first, active only for AUTHORIZED entries, via existing ScannerRegistry/WorkerPool.

## Scope Model

**ExternalScope**: id, organization_id, project_id, name, description, status (active/archived), created_by, created_at/updated_at. 10 max per project.

**ExternalScopeEntry**: id, external_scope_id FK CASCADE, entry_type (DOMAIN/SUBDOMAIN/IP/CIDR/URL), value (500, normalized), authorization_status (AUTHORIZED/PENDING/REJECTED), ownership_confidence (CONFIRMED etc), source, notes. CIDR tightly bounded: minimum /24 (256 IPs), max 256 IPs, value length 500, 50 entries/scope. Only `AUTHORIZED` used for active discovery.

## Ownership Confidence

Deterministic:

- `CONFIRMED`: exact match to AUTHORIZED scope entry
- `HIGH_CONFIDENCE`: subdomain of AUTHORIZED domain
- `MEDIUM_CONFIDENCE`: DNS/cert relationship
- `LOW_CONFIDENCE`/`UNKNOWN`: ambiguous
- `REJECTED`: analyst rejected

Evidence: explicit scope, DNS, cert SAN, cloud metadata, project asset, repository relationship. UNKNOWN/LOW never auto-authorized for active scan (candidate only).

## Passive Discovery

Reuses existing discovery: Subfinder, DNS, certificate metadata, Asset Intelligence, cloud assets, repository metadata. Provider-neutral interface `ExternalDiscoveryProvider` (discover_domains/subdomains/ips/urls, health). Initially reuses scanner output, no expensive external integration.

## Active Discovery (bounded, authorized only)

- `QUICK`: passive, DNS, HTTP reachability, minimal TLS
- `WEB`: passive + HTTP/HTTPS + TLS + tech fingerprint + safe Nuclei (authorized)
- `FULL`: WEB + bounded Nmap (10 ports/target, 20 targets/run)

Active MUST: derive from AUTHORIZED scope, reject private/metadata targets, SSRF checks (parse hostname/IP, resolve, validate all resolved IPs, reject loopback/link-local/multicast/unspecified/private, metadata 169.254.169.254, re-check before connect, validate redirects, DNS rebinding protection, timeouts, response-size limits, target-count/port limits, scan duration, isolated workspaces 0700, DockerRunner, worker capacity, audit). No arbitrary commands.

## SSRF / Network Safety (15 checks)

1. Parse safely, 2. Resolve DNS, 3. Validate ALL addresses, 4. Reject loopback, 5. Reject link-local, 6. Reject multicast, 7. Reject unspecified, 8. Reject private where external not authorized, 9. Reject metadata endpoints, 10. Re-check before connect, 11. Validate redirects (no private), 12. Prevent rebinding, 13. Connection timeout, 14. Total timeout, 15. Response-size limit. Never allow `localhost`, `127.0.0.0/8`, `::1`, RFC1918, link-local, metadata, Unix sockets, arbitrary internal names. No internal mode in E15.

## External Asset Model (reuse Asset Intelligence)

Reuse `Asset` canonical types: `domain`, `subdomain`, `ip`, `ipv6`, `url`, `port`, `service`, `technology`, `hostname`, `certificate`. Add external metadata via `extra_data`: `exposure_type`, `ownership_confidence`, `first_external_seen`, `last_external_seen`, `externally_reachable`, `discovery_sources`, `authorization_state`, `scope_id`, `exposure_metadata`.

Relationships via `AssetRelationship`: `domain resolves_to ip`, `domain points_to subdomain`, `subdomain serves url`, `ip exposes port`, `port runs service`, `url uses technology`, `certificate observed_on url`. No graph DB.

## Exposure Classification

Deterministic, evidence-based:

- `INTERNET_FACING_DOMAIN`, `SUBDOMAIN`, `IP`, `SERVICE`, `WEB_APP`, `API`, `ADMIN_INTERFACE`, `REMOTE_ACCESS` (22/3389), `DATABASE` (3306/5432/1433), `UNKNOWN_EXTERNAL_ASSET`

Port finding preserves protocol, port, service, source, scanner, timestamp, evidence.

## Shadow / Unknown Assets

Distinction: `KNOWN_ASSET` (confirmed) vs `DISCOVERED_CANDIDATE` (subdomain/cert/DNS/IP/redirect/tech/cloud/repo relationship) vs `UNKNOWN_ASSET`. Candidate != confirmed. UI shows “Possible organization asset — ownership requires analyst verification.” Actions: Confirm, Reject, Review. Candidates never auto-authorized.

## Change Detection (reuse D1/D2)

Run-scoped observations, idempotent, `ASSET_FIRST_SEEN`, `LAST_SEEN`, `DISAPPEARED`, `DNS_CHANGED`, `IP_CHANGED`, `PORT_OPENED/CLOSED`, `SERVICE_CHANGED`, `TECHNOLOGY_CHANGED`, `TLS_CHANGED`, etc. Uses existing `asset_change_event` / `monitoring_change_events` patterns. Failed/partial run does **not** cause false disappearance (partial preserves successful observations).

## Finding Correlation (reuse FindingEngine + E12)

External asset `api.example.com` with existing finding `API authentication weakness` → `SAME_ASSET` via E12. `203.0.113.10:443` with AWS LB → `SAME_EXPOSURE`. `admin.example.com` with critical vuln → `EXTERNAL_EXPOSURE_RELATED` via E12. No duplicate finding engine.

## E11 Integration

External exposure becomes input to `E11` exposure intelligence (externally reachable, sensitive service, critical finding, attack path relation, newly exposed, unknown ownership, etc.). No second risk engine; deterministic E11 score (no AI, no business impact unless metadata exists).

## E9 Attack Path Integration

If externally discovered asset connects to cloud assets/findings/relationships, expose relationship (e.g., `Internet → api.example.com → public IP → AWS LB → private resource`). No second attack-path engine; if E9 cannot model, expose as context and document limitation.

## E13 Investigation Integration

Analyst can start investigation from external asset, newly discovered asset, high-risk finding, exposure, change. Investigation context includes external asset, ownership evidence, discovery evidence, findings, correlations, exposure score, changes, related attack paths, validation/retest. Reuse E13, no duplicate system.

## E14 Validation Integration

E15 must not directly execute validation. For confirmed authorized external asset, analyst may initiate E14 validation via authorized workflow (target derived from approved asset, E14 SSRF/authorization still enforced). Unknown/shadow assets cannot bypass E14.

## Discovery Run Model

`ExternalDiscoveryRun`: id, organization_id, project_id, external_scope_id, status `QUEUED/RUNNING/COMPLETED/PARTIAL/FAILED/CANCELLED`, profile `QUICK/WEB/FULL`, started_at, completed_at, assets_discovered/changed/new/removed, findings_created, error_count, partial, failure_reason, created_by, created_at. Statuses: partial preserves successful, not fully successful.

## Profiles & Limits

- `QUICK`: passive, minimal
- `WEB`: passive + HTTP/TLS + tech + safe Nuclei
- `FULL`: WEB + bounded Nmap

Limits (safe defaults, configurable via code, not user arbitrary overrides):
`MAX_SCOPE_ENTRIES 50`, `MAX_DISCOVERED_ASSETS 200`, `MAX_ACTIVE_TARGETS 20`, `MAX_PORTS_PER_TARGET 10`, `MAX_CIDR_PREFIX 24`, `MAX_CIDR_IPS 256`, `MAX_SUBDOMAINS 100`, `MAX_RESPONSE_BYTES 1M`, etc. Tenant quotas via existing entitlement (not billing system).

## Multi-tenancy / RBAC

- `external_scope.read` / `external_scope.write` → `viewer` read, `project_admin` manage scopes
- `external_discovery.read` / `run` → `viewer` read, `analyst`/`project_admin` run
- `external_asset.read` / `review` / `authorize` / `reject` → `viewer` read, `analyst` review/confirm/reject

Enforce organization isolation, project isolation, IDOR, RLS, audit. Viewer cannot modify scope or authorize.

## Audit Logging

Audit: scope created/updated, entry authorized/rejected, discovery started/completed/partial/failed, active scan initiated, candidate created, asset confirmed/rejected, validation initiated, unauthorized/SSRF blocked, rate-limit, scope violation prevented. Never log secrets/tokens/private keys/credentials.

## API

- `GET /external-attack-surface` → summary
- `GET /summary` → summary
- `GET /assets?asset_type=&ownership=&limit` → bounded
- `GET /assets/{asset_id}` → detail
- `GET /assets/{asset_id}/changes` → changes (D2)
- `GET /candidates?limit` → candidate assets
- `POST /candidates/{asset_id}/confirm` → confirm (analyst)
- `POST /candidates/{asset_id}/reject` → reject
- `POST /scopes` → create scope (project_admin)
- `GET /scopes` → list scopes
- `PATCH /scopes/{scope_id}` → update
- `POST /scopes/{scope_id}/entries` → add entry (project_admin, CIDR/SSRF validated)
- `PATCH /entries/{entry_id}` → update auth/confidence (analyst/project_admin)
- `POST /discover` body `{external_scope_id, profile}` → create run (analyst)
- `GET /runs?limit` → list runs
- `GET /runs/{run_id}` → run detail

All project-scoped, bounded pagination, 401/403/404/400 safe errors, `require_project_access`, `set_rls_context`.

## Frontend

Route `/projects/[projectId]/external-attack-surface`:

- **SUMMARY**: total external, confirmed, candidate, newly discovered, changed, exposed services, critical/high findings
- **SCOPE MANAGEMENT**: create scope, add AUTHORIZED entries, list scopes
- **DISCOVERY**: Run QUICK/WEB/FULL (bounded)
- **CANDIDATE REVIEW**: list candidates with Confirm/Reject (clearly marked not confirmed)
- **ASSET TABLE**: asset | type | exposure | ownership confidence | status | risk | first seen | last seen — filters: confirmed/candidate/unknown/newly/changed/high risk/domain/IP/URL/service
- **DETAIL PAGE**: asset identity, ownership evidence, discovery sources, DNS, IPs, ports, services, technologies, TLS, findings, correlations, exposure, attack paths, change history, investigation, validation/retest

UX principle: **“What's exposed and what changed?”** — prioritize newly exposed, critical/high, unknown candidates, significant changes.

## Database

Alembic `e15a1b2c3d4e_add_external_attack_surface_e15`: creates `external_scopes`, `external_scope_entries`, `external_discovery_runs` with FKs, indexes, tenant-safe constraints, RLS compatibility, reversible upgrade/downgrade. Do not duplicate Asset data; external assets reuse `assets` + `asset_relationships`.

## Idempotency

Canonical asset identity: domain lowercased, IP normalized, URL normalized, port asset+protocol+port. Repeated discovery with same scope does not create duplicate assets (unique `project_id, asset_type, value`). Uses existing Asset Intelligence normalization.

## Data Correlation

Discovery sources overlapping (subfinder, DNS, Nmap, HTTP, TLS) form one coherent asset context via relationships, not five unrelated assets. Preserve source provenance in `discovery_sources`.

## Scanner Failure Handling

One scanner failing → `PARTIAL` (not `FAILED`) unless no meaningful discovery succeeded. Distinguish scanner/target/parser/worker/scope/network/timeout/authorization failures via existing taxonomy.

## Worker / Capacity

Use existing worker pools, capacity manager, reserved buffer, failover, retries, idempotency. No second scheduler. Every invocation preserves scanner, version, digest, profile, run ID, target, scope, workspace, tenant context.

## Security Testing

Cover scope unauthorized, entry active scan, CIDR/target limits, cross-project/tenant, SSRF (localhost, loopback, private, link-local, metadata, IPv6, redirect, DNS rebinding, malformed), viewer vs analyst vs admin, IDOR, assets normalization/dedup, ownership/candidate, change detection, scanner registry/version provenance, workspace/Docker, capacity/failover, FindingEngine, E11/E12/E13/E14, audit, secrets.

## Test Execution

Resource-efficient: focused E15 unit/security/API/integration, migration upgrade/downgrade, E11/E12/E13/E14 regressions, lint, build. Full suite only if fast.

## Runtime Verification

Synthetic flow with owned/authorized test domain (no arbitrary Internet scan): create org/project, authorized scope, add domain, block private target, passive discovery mock, persist assets, verify normalization/dedup/ownership, create candidate, confirm, bounded active discovery mock, correlate with findings, generate change, verify E11/E12/E13/E14, audit, cross-tenant denied. Clearly mark MOCK vs LIVE.

## Performance / Bounds

Indexed queries, bounded pagination, no N+1, no unbounded traversal, no ES/Neo4j/Kafka.

## Limitations

- Passive discovery initially reuses existing scanner output (no expensive provider ecosystem)
- Active discovery requires authorized scope, bounded (20 targets, 10 ports)
- Ownership HIGH/MEDIUM not fully automated (requires analyst verification for UNKNOWN)
- No dark-web, no full ASM, no AI discovery

## Production Hardening

- Tighten CIDR limits per tenant, rate limits, concurrency, timeouts, response-size, redirects, DNS results, subdomains, certificate names (configurable, not user arbitrary)
- Integrate tenant quotas with entitlement if available (no billing system in E15)
- Ensure audit retention, RLS policies for external_* tables

## Non-Goals

Arbitrary Internet scanning, exploitation, credential attacks, brute force, persistence, lateral movement, privilege escalation, stealth, DoS, dark-web, SIEM/SOAR, compliance automation, arbitrary crawling, massive distributed scanning, new cloud provider, graph DB, AI discovery, autonomous exploitation.
