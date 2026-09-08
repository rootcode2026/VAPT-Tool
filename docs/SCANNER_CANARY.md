# Scanner Canary Deployment (C8)

## Purpose

Controlled canary for scanner versions: `candidate` → isolated canary executions → verification → explicit promotion to `stable`.

Health check alone is not canary; canary requires actual scanner execution via existing pipeline.

## Lifecycle

```
pending → canary → verifying → passed/failed → promoted (via explicit POST /canary/{id}/promote) → stable
```

`pending` (created) → `canary` (executing) → `verifying` → `passed` (all `canary_count` successes, 0 failures) or `failed` (any failure). `passed` does not auto-promote; `POST /canary/{id}/promote` with Super Admin `scanners.manage` promotes transactionally (one stable, demotes old, updates `current_version`).

## Target Validation

- `scanner exists`, `version exists` and `belongs to scanner`, `approved` true, `enabled` true, not `deprecated`, `image_ref` valid, `image_digest` present (immutable `sha256:` 64 hex), `compatibility` valid, `health` not `failed`/`unhealthy` (via `ScannerHealth` for target version), `canary_count` 1–10, no `command`/`shell`/`volumes`/`privileged`.

## Canary Scope

- `canary_count` (1–10) or bounded percentage (future, max 100, not `entire fleet`). C8 uses `canary_count`, forward-compatible with C9 worker pools (currently single worker path, synthetic `canary.test` target, isolated `create_workspace`/`cleanup_workspace`, `DockerRunner` with `registered` `image_ref`+`digest`, `timeout`, workspace isolation, no customer data).

## Execution

- `ScannerVersion` → `image_ref`+`digest` → `ScannerRegistry` → `ScannerManager` → `DockerRunner`/`in-process` → `ScannerPipeline` → `Parser` (where applicable), via `canary.test` synthetic target (platform-owned, no customer payload), `canary_count` executions, each with `ScanContext` workspace, bounded, tenant-isolated, no `docker pull` arbitrary.

## Verification

- `canary_count` successes and `0` failures, `container startup`/`timeout`/`non-zero exit` → failure, `target_unreachable` not scanner failure, `latency` captured, `ScannerHealth` updated per version (version-aware), `passed` requires `success_count >= canary_count` and `failure_count == 0`.

## Failure

- `failed` → `failure_reason` sanitized 500, `current_version` unchanged, `previous_version` preserved, no promotion, no auto-rollback (C7 manual), `SCANNER_CANARY_FAILED` audit + `SECURITY_SCANNER_CANARY_FAILED` (MEDIUM).

## Success

- `passed` → `SCANNER_CANARY_PASSED` audit + `SECURITY_SCANNER_CANARY_PASSED` (INFO), `POST /canary/{id}/promote` (Super Admin, checks `passed`, `approved`/`enabled`/`digest`/`compatibility` still valid, transactional `target` → `stable`, `old stable` → `deprecated`, `current_version`/`previous_version` updated, `SCANNER_VERSION_PROMOTED` + `SECURITY_SCANNER_VERSION_PROMOTED` (HIGH)).

## Concurrency

- One active `canary`/`pending`/`verifying` per `scanner_key` (`state` `pending`/`canary`/`verifying` unique via `existing` check, `409` if active), `canary` + `upgrade`/`downgrade`/`rollback` conflict via same check, duplicate `target_version` + `canary` returns existing `409` or 200 idempotent.

## Security

- No `image`/`command`/`volume`/`host_path`/`privileged`/`docker_socket` from client, `validate_image_ref` blocks `;|&$`, `image_digest` required for `stable`, `Super Admin` + `scanners.manage`, platform-global (no `organization_id` on `ScannerRollout`), no customer data in `rollout` response, `audit` redacted.

## API

- `POST /api/v1/scanners/{key}/canary` (`target_version`, `canary_count` 1–10, `reason`, 201, `id`/`state`/`target_version`), `GET /scanners/{key}/canary/{id}` (200), `POST /scanners/{key}/canary/{id}/promote` (200, `target_version` → `stable`), all `require_super_admin`, `scanners.manage`, 401/403 for others, `404` for unknown, `400` for `unapproved`/`disabled`/`missing digest`/`invalid canary_count`.

## Health

- C4 `ScannerHealth` per `version`, `record_health` with `version`, `failure_count` thresholds (2→`degraded`, 3→`unhealthy`, 5→`failed`), `get_eligible_scanners` version-aware (`unhealthy`/`failed` not eligible), `resolve_production_version` checks `health` per `current_version`.

## Frontend

- `/admin/scanners` shows `current`/`target`/`digest`/`health`/`rollout`/`canary_count`/`success`/`failure`/`latency`, `Start Canary` (Super Admin) with `target_version`/`canary_count`/`reason`, `Promote` after `passed` with confirmation (`scanner`, `current`, `target`, `digest`, `canary result`), no `downgrade`/`rollback`/`canary` auto.

## DB

- `ScannerRollout` (`canary_count`, `health_threshold`, `operation` `canary`, `state` `pending`/`canary`/`verifying`/`passed`/`failed`/`promoted`), `ScannerVersion` `lifecycle_status`/`enabled`/`approved`/`deprecated`, no new migration for C8 (reuses `ScannerRollout`), `scans` `scanner_version`/`scanner_image_digest` for provenance.

## Tests

- 8 for C1, plus C8: `auth` (401/403), `validation` (unknown/unapproved/disabled/missing digest/invalid canary_count), `canary` (rollout created, `target_version`/`digest`, `canary`→`verifying`→`passed`/`failed`, `actual execution` via `canary.test`, `success`/`failure` counted, `target failure` not scanner failure, `failed` not `current_version`, `passed` not auto-promote, `promote` updates `current_version`/`previous_version`, `old` retained, `historical` unchanged), `security` (arbitrary `image`/`command`/`volume` 400, `privileged` 400), `concurrency` (two `canaries` → one active, `canary`+`upgrade` conflict), `RBAC`, `audit`.

## Limitations

- Single worker path (C9 will add pools), no `canary` percentage, no `automatic` promotion, no `image` pulling, `canary.test` synthetic, `health` via `record_health` not full Docker health for canary (simulated).

## C9 Preparation

- `ScannerRollout` `canary_count`/`health_threshold`/`operation` extensible for `canary`/`worker`/`percentage`/`verification window`, `WorkerPool` (`total_capacity`/`reserved_buffer`) for C9.

