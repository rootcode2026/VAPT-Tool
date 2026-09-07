# Scanner Control Plane — C1 & C2 (P14.1 + P14.2 + C1/C2)

## Scanner Registry (C1)

- **Source:** `SCANNER_CATALOG` (15 entries, `key`/`name`/`category`/`family`/`description`/`capabilities`/`profiles`/`requires_workspace`/`execution_type`/`timeout`/`default_image`) + `ScannerDefinition` (DB, `scanner_key` unique, `display_name`, `category`, `family`, `enabled`, `current_version`, `capabilities`, `supported_profiles`, `requires_workspace`, `execution_type`, `timeout_seconds`, `default_image`).
- **Identity:** Stable `key` (`nmap`, `nuclei`, etc., 15), deterministic, independent of `image`/`digest`/`container ID`, `version` separate, `display_name` for UI, `id` UUID for DB.
- **Execution:** `ScannerRegistry` (in-memory, `BaseScanner` instances, `register`/`get`/`list` via `metadata()`) remains execution source of truth; `SCANNER_CATALOG` is control-plane metadata; `ScannerDefinition` is platform-global, seeded via `seed_definitions`, not tenant-isolated, `FORCE RLS` not applied (platform-global, Super Admin only).
- **Image/digest:** `default_image` (`vapt-tool-nmap`, `vapt-sast:latest` etc.), `image_digest` nullable (128), `image_ref` + `image_digest` in `ScannerVersion`, `get_catalog` returns `default_image`, `list_scanners` DB fallback to catalog, `:latest` not treated as immutable, `image + digest` preferred for deployment.
- **Channel:** `stable`/`candidate` (C1 default all `stable`, `SCANNER_CATALOG` `channel` not yet, `ScannerVersion.channel` default `candidate`, `DOCUMENTED_STABLE_VERSIONS` are `stable`, no promotion logic (C3)).
- **Enabled/disabled:** `ScannerDefinition.enabled` (bool, default True), `get_eligible_scanners(profile, db)` filters `enabled` false, disabled not in `scanners_for_profile`, historical scans still reference `scanner_key` (not deleted).

## Version Registry (C2)

- **Model:** `ScannerVersion` (`definition_id` FK CASCADE, `version` 50, `channel` 20 (`stable`/`candidate`), `image_ref` 255, `image_digest` 128, `compatibility` JSON, `release_notes` Text, `health_status` 20 (`unknown`/`healthy`/`degraded`/`unhealthy`/`disabled`), `lifecycle_status` 20 (`draft`/`candidate`/`stable`/`deprecated`/`disabled`), `enabled` bool, `approved` bool, `deprecated` bool, `approved_at`/`deprecated_at`, `parser_version` 50, `output_format_version` 20, `created_at`/`updated_at`, `unique(definition_id, version)`, indexes on `lifecycle_status`/`enabled`).
- **Identity:** `scanner_key` + `version` unique, `id` UUID PK, `version` separate from `scanner_key`, `image_ref` + `image_digest` for immutable deployment, `version` not UUID, no `latest` auto.
- **Lifecycle:** `draft` → `candidate` → `stable` → `deprecated`/`disabled`, `channel` vs `lifecycle_status` distinct, `enabled`/`approved`/`deprecated` booleans, `approved_at`/`deprecated_at`, not deleting old versions.
- **Channel:** `stable`/`candidate` via `ScannerVersion.channel`, default `candidate`, no promotion automation (C3).
- **Approval:** Explicit `approved` bool, `approved_at`, not `exists` = `approved`, `DRAFT`→`CANDIDATE`→`TESTED`→`APPROVED`→`STABLE`→`DEPRECATED` prepared, no auto-approve.
- **Current version:** `ScannerDefinition.current_version` references `ScannerVersion.version` (string), not `id`, single source of truth, `seed_definitions` sets `current_version` from `DOCUMENTED_STABLE_VERSIONS` (6 AppSec: `sast` 1.75.0, `sca` 1.9.2, `secrets` 8.30.1, `container` 0.66.0, `iac` 3.3.16, `api` 1.0.0, `sqlmap` 1.8.5, others `null`/`unknown`), no two sources.
- **Compatibility:** `compatibility` JSON (`target_types`, `profiles`, `execution_type`, `workspace`, `parser_version`, `output_format`), `parser_version`/`output_format_version` for parser compatibility, not overengineered.
- **Registration:** `POST /api/v1/scanners/{key}/versions` (Super Admin, `scanners.manage`, validates `scanner exists`, `version` format, `image_ref` via `validate_image_ref`, `digest` 128, `channel` `stable`/`candidate`, rejects `command`/`shell`/`volumes`/`privileged`/`host_path`/`docker_socket`, metadata only, no execution, `SCANNER_REGISTERED` audit).
- **Validation:** `scanner exists`, `version` non-empty, `image_ref` valid (no `;`/`&`/`|`/`$`/`\``), `digest` `sha256:` 64 hex, `channel` valid, `profile`/`target_types` valid, `unique` 409, `validate_channel`/`validate_version` reused from C1.
- **Image trust:** `approved` registry, `image_ref` + `image_digest` for `vapt-*`, `signature`/`provenance`/`SBOM` prepared for C5/C8, no pull/scan yet.
- **List:** `GET /api/v1/scanners/{key}/versions` (Super Admin, `scanners.read`, filters `channel`/`lifecycle`/`enabled`/`approved`/`deprecated`, pagination 20, bounded), `GET /api/v1/scanners/{key}/versions/{version}` (same), no unlimited.
- **Admin:** `PATCH /scanners/{key}` `enabled` bool (Super Admin, `SCANNER_ENABLED`/`DISABLED` audit), `POST /versions` register, `PATCH` `enabled`/`deprecated` (Super Admin), no `upgrade`/`downgrade`/`rollback`/`canary` (C3-C8).
- **RBAC:** `scanners.read` (all auth), `scanners.manage` (super_admin), normal project users cannot mutate global versions, `require_super_admin` for `POST /versions`, `PATCH`.
- **Tenant:** Platform-global, not tenant-isolated, no `organization_id` on `ScannerVersion`, `Company A`/`B` share same versions, future tenant policies will be tenant-isolated (not in C2).
- **RLS:** No tenant RLS on `scanner_versions` (platform-global, correct), `scanner_definitions` also not RLS, future tenant `scanner_policies` will have `project_id` RLS.
- **Audit:** `SCANNER_REGISTERED`, `SCANNER_VERSION_CHANGED`, `SCANNER_VERSION_ENABLED`/`DISABLED`/`DEPRECATED` (actor, `scanner_key`, `version`, `image`, `digest`, `old`/`new`, `reason`, `request_id`/`correlation_id`), no `UPGRADE`/`ROLLBACK`/`CANARY` (not implemented).

## Version Selection

- `resolve_scanner_version(scanner_key, version=None, channel=None)` → verifies `scanner exists`, `version exists`, `enabled` true, `approved` if required, returns `image_ref`/`image_digest` immutable, rejects `latest` auto, deterministic.

## Execution Integration

- `ScannerManager` → `registry.get` → `scanner.scan`, `ScannerPipeline` unchanged, `DockerRunner` unchanged (`image` + `digest` via `SCANNER_CATALOG` `default_image` for now, future C5 will use `resolve_scanner_version` → `DockerRunner` with `image_ref` + `digest`), `in-process` (`http_fingerprint`) unchanged, `get_eligible_scanners` filters `enabled`/`failed`/`unhealthy`.

## Historical Provenance

- `scans` now has `scanner_version` (50) + `scanner_image_digest` (128) nullable, for `Scan` history (`scanner_key` + `version` + `digest`), old scans `NULL`/`unknown`, not fabricated, `finding` provenance via `scan_id` → `scanner_version`.

## Tests

- 8 tests: `all_scanners_registered` (15), `stable_ids` (15 keys), `metadata_available` (6 fields), `duplicate_rejected` (DB unique), `unknown_rejected` (None), `enabled_excluded` (disabled not in `quick`), `api_requires_auth` (401), `api_returns_scanners_when_authed` (200, ≥14, `nmap`). All 8 passed.

## Limitations

- No `sqlmap` UI yet, `health` always `unknown` until C4, `image_digest` null until C2, `candidate` channel not used, `worker_pools` not yet wired.
