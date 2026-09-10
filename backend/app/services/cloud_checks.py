"""E2 AWS security-check engine — deterministic evaluation of persisted evidence.

Provider-neutral structure (check packs per provider); AWS pack only in E2.
Evaluation is OFFLINE over persisted E1 asset metadata: no AWS API calls, no
credentials, no network. Missing evidence yields NOT_ASSESSED — never PASS,
never FAIL. Findings flow into the existing Findings table with
scanner="cloud" (reusing dashboard/alert/report integrations).
"""

from __future__ import annotations

import json as _json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

CHECK_PACK_VERSION = "1.0"

SEVERITY_SCORES = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}

RESULT_PASS = "passed"
RESULT_FAIL = "failed"
RESULT_NOT_ASSESSED = "not_assessed"
RESULT_ERROR = "error"

PAB_FLAGS = (
    "pab_blockpublicacls",
    "pab_ignorepublicacls",
    "pab_blockpublicpolicy",
    "pab_restrictpublicbuckets",
)

AWS_CHECKS: list[dict[str, Any]] = [
    {
        "check_id": "AWS-EC2-001",
        "title": "EC2 instance allows IMDSv1 (metadata service not restricted to IMDSv2)",
        "description": "Instance Metadata Service Version 1 is susceptible to SSRF-based credential theft. Require IMDSv2 (HttpTokens=required) or disable the metadata endpoint.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_ec2_instance"],
        "severity": "high",
        "category": "compute-hardening",
        "remediation": "Set MetadataOptions HttpTokens to required (IMDSv2 only) or disable the metadata endpoint for the instance.",
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["imds_v2_enforced"],
    },
    {
        "check_id": "AWS-RDS-001",
        "title": "RDS instance publicly accessible",
        "description": "A publicly accessible database accepts connections from the internet, exposing it to brute-force and exploitation.",
        "provider": "aws",
        "service": "rds",
        "resource_types": ["aws_rds_instance"],
        "severity": "critical",
        "category": "database-exposure",
        "remediation": "Disable public accessibility for the RDS instance and restrict access to private networks/security groups.",
        "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["publicly_accessible"],
    },
    {
        "check_id": "AWS-RDS-002",
        "title": "RDS storage encryption disabled",
        "description": "Unencrypted database storage exposes data-at-rest to snapshot/volume theft.",
        "provider": "aws",
        "service": "rds",
        "resource_types": ["aws_rds_instance"],
        "severity": "high",
        "category": "database-encryption",
        "remediation": "Enable storage encryption for the RDS instance (requires snapshot restore for existing instances).",
        "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["storage_encrypted"],
    },
    {
        "check_id": "AWS-S3-001",
        "title": "S3 bucket public-access-block disabled",
        "description": "A disabled S3 Block Public Access control allows bucket/object policies or ACLs to grant public access.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "high",
        "category": "storage-exposure",
        "remediation": "Enable all S3 Block Public Access settings for the bucket.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["pab_blockpublicacls", "pab_ignorepublicacls", "pab_blockpublicpolicy", "pab_restrictpublicbuckets"],
    },
    {
        "check_id": "AWS-S3-002",
        "title": "S3 bucket default encryption not configured",
        "description": "No default server-side encryption configuration exists for the bucket.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "medium",
        "category": "storage-encryption",
        "remediation": "Configure default server-side encryption (SSE-S3 or SSE-KMS) for the bucket.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encryption"],
    },
    {
        "check_id": "AWS-ELB-001",
        "title": "Internet-facing load balancer exposes plaintext HTTP listener",
        "description": "An internet-facing load balancer with an HTTP listener serves unencrypted traffic that can be intercepted or downgraded.",
        "provider": "aws",
        "service": "elbv2",
        "resource_types": ["aws_alb", "aws_nlb", "aws_elb"],
        "severity": "medium",
        "category": "network-encryption",
        "remediation": "Replace the HTTP listener with HTTPS (or redirect HTTP to HTTPS) on the internet-facing load balancer.",
        "references": ["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["listeners", "scheme"],
    },
    {
        "check_id": "AWS-LAMBDA-001",
        "title": "Lambda function URL allows unauthenticated access",
        "description": "A Lambda function URL with AuthType NONE is publicly invocable without AWS authentication.",
        "provider": "aws",
        "service": "lambda",
        "resource_types": ["aws_lambda_function"],
        "severity": "high",
        "category": "serverless-exposure",
        "remediation": "Set the function URL auth type to AWS_IAM or remove the public function URL.",
        "references": ["https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["function_urls"],
    },
]

# Declared but intentionally not evaluated: evidence lives in E3/E4/E5 scope.
DEFERRED_CHECKS: dict[str, str] = {
    "AWS-EC2-002": "Requires security-group ingress rule bodies (E4 network analysis).",
}


def list_catalog(provider: str | None = None) -> list[dict]:
    checks = [c for c in AWS_CHECKS if c.get("enabled")]
    if provider:
        checks = [c for c in checks if c.get("provider") == provider.strip().lower()]
    return checks


def get_check(check_id: str) -> dict | None:
    wanted = str(check_id or "").strip().upper()
    for check in AWS_CHECKS:
        if str(check.get("check_id", "")).upper() == wanted:
            return check
    return None


def _not_assessed(reason: str) -> tuple[str, None, str]:
    return (RESULT_NOT_ASSESSED, None, reason)


def _evidence_base(check: dict, asset_meta: dict, discovery_run_id: str | None) -> dict:
    return {
        "check_id": check["check_id"],
        "check_version": check.get("version"),
        "resource": asset_meta.get("value") or asset_meta.get("resource_id"),
        "region": asset_meta.get("region"),
        "account_id": asset_meta.get("account_id"),
        "discovery_run_id": discovery_run_id,
        "observed_at": asset_meta.get("observed_at"),
    }


def evaluate_asset(check: dict, asset_meta: dict, discovery_run_id: str | None = None) -> tuple[str, dict | None, str]:
    """Evaluate one check against one asset's persisted metadata.

    Returns (result, evidence|None, note). Pure function: no I/O, no AWS calls.
    Missing evidence yields NOT_ASSESSED — never PASS, never FAIL.
    """
    check_id = check.get("check_id")
    extra = asset_meta.get("extra") if isinstance(asset_meta.get("extra"), dict) else {}
    try:
        if check_id == "AWS-EC2-001":
            enforced = extra.get("imds_v2_enforced")
            if enforced is True:
                return (RESULT_PASS, None, "IMDSv2 enforced or metadata endpoint disabled")
            if enforced is False:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "imds_v2_enforced", "observed": False, "expected": True})
                return (RESULT_FAIL, evidence, "IMDSv1 allowed (HttpTokens optional)")
            return _not_assessed("instance metadata options unavailable")
        if check_id == "AWS-RDS-001":
            public = extra.get("publicly_accessible")
            if public is True:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "publicly_accessible", "observed": True, "expected": False})
                return (RESULT_FAIL, evidence, "RDS instance publicly accessible")
            if public is False:
                return (RESULT_PASS, None, "RDS instance not publicly accessible")
            return _not_assessed("public accessibility unknown")
        if check_id == "AWS-RDS-002":
            encrypted = extra.get("storage_encrypted")
            if encrypted is True:
                return (RESULT_PASS, None, "RDS storage encrypted")
            if encrypted is False:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "storage_encrypted", "observed": False, "expected": True})
                return (RESULT_FAIL, evidence, "RDS storage encryption disabled")
            return _not_assessed("storage encryption unknown")
        if check_id == "AWS-S3-001":
            flags = {flag: extra.get(flag) for flag in PAB_FLAGS}
            if all(value is True for value in flags.values()):
                return (RESULT_PASS, None, "all Block Public Access controls enabled")
            disabled = sorted(k for k, v in flags.items() if v is False)
            if disabled:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "public_access_block", "observed": {k: flags[k] for k in disabled},
                                 "expected": "all Block Public Access controls enabled"})
                return (RESULT_FAIL, evidence, f"Block Public Access disabled: {', '.join(disabled)}")
            return _not_assessed("public access block configuration unavailable")
        if check_id == "AWS-S3-002":
            encryption = extra.get("encryption")
            if isinstance(encryption, str) and encryption:
                return (RESULT_PASS, None, f"default encryption configured ({encryption})")
            code = str(extra.get("encryption_error_code") or "")
            if code in ("NoSuchEncryptionConfiguration", "ServerSideEncryptionConfigurationNotFoundError"):
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "encryption", "observed": None, "expected": "default SSE configured"})
                return (RESULT_FAIL, evidence, "no default bucket encryption configured")
            return _not_assessed("encryption configuration unknown")
        if check_id == "AWS-ELB-001":
            listeners = extra.get("listeners")
            if not isinstance(listeners, list) or not listeners:
                if extra.get("listener_error"):
                    return _not_assessed("listener configuration unavailable")
                return _not_assessed("no listener evidence")
            http_ports = sorted({l.get("port") for l in listeners
                                 if isinstance(l, dict) and str(l.get("protocol") or "").upper() == "HTTP"
                                 and isinstance(l.get("port"), int)})
            if http_ports and str(asset_meta.get("scheme") or extra.get("scheme") or "").lower() == "internet-facing":
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "listeners", "observed": http_ports, "expected": "HTTPS only"})
                return (RESULT_FAIL, evidence, f"internet-facing LB with plaintext HTTP listener(s) on {http_ports}")
            return (RESULT_PASS, None, "no plaintext HTTP listener on internet-facing LB")
        if check_id == "AWS-LAMBDA-001":
            if "function_urls" not in extra:
                return _not_assessed("function URL configuration unavailable")
            if extra.get("url_error"):
                return _not_assessed("function URL configuration unavailable")
            urls = extra.get("function_urls") or []
            public = sorted({u.get("url") for u in urls if isinstance(u, dict)
                             and str(u.get("auth") or "").upper() == "NONE" and u.get("url")})
            if public:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "function_url_auth", "observed": "NONE", "expected": "AWS_IAM"})
                return (RESULT_FAIL, evidence, "Lambda function URL allows unauthenticated access")
            return (RESULT_PASS, None, "no unauthenticated function URLs")
    except Exception as exc:
        return (RESULT_ERROR, None, f"evaluation error: {str(exc)[:200]}")
    return (RESULT_ERROR, None, f"unknown check: {check_id}")


# ---------------------------------------------------------------------------
# Run evaluation + finding persistence (existing Findings table, scanner cloud)
# ---------------------------------------------------------------------------

MAX_EVAL_ASSETS = 500
MAX_EXISTING_FINDINGS = 500


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _finding_proxy(title: str, check_id: str, asset_value: str, asset_id: str):
    """Fingerprint input mirroring persisted finding metadata (backend d8 fn).

    asset_id must be set: d8_finding_input only reads asset_type/asset_value
    from metadata when the finding carries an asset identity.
    """
    return SimpleNamespace(
        title=title,
        cve=None,
        cwe=None,
        evidence=None,
        asset_id=asset_id,
        extra_data={"rule_id": check_id, "asset_type": "cloud_resource", "asset_value": asset_value},
    )


def _existing_fingerprints(db: Session, project_id: str) -> set[str]:
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.services import finding_lifecycle as lc

    rows = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .filter(Asset.project_id == project_id, Finding.scanner == "cloud")
        .order_by(Finding.created_at.desc())
        .limit(MAX_EXISTING_FINDINGS)
        .all()
    )
    fps: set[str] = set()
    for row in rows:
        try:
            fps.add(lc.d8_fingerprint(lc.d8_finding_input(row)))
        except Exception:
            continue
    return fps


def run_evaluation(db: Session, project, connection, discovery_run, actor_user_id: str | None = None):
    """Evaluate one discovery run; create findings for FAILs. Idempotent per run.

    Returns (CloudCheckRun, created: bool). Repeat calls for the same discovery
    run return the existing run without new findings (UNIQUE constraint).
    Findings never auto-resolve: absent conditions leave existing rows alone
    (D8 owns verification/resolution).
    """
    from app.models.asset import Asset
    from app.models.cloud_check import CloudCheckRun
    from app.models.finding import Finding
    from app.services import finding_lifecycle as lc
    from app.services.audit import (
        EVENT_CLOUD_CHECK_RUN_COMPLETED,
        EVENT_CLOUD_CHECK_RUN_FAILED,
        EVENT_CLOUD_CHECK_RUN_PARTIAL,
        EVENT_CLOUD_CHECK_RUN_REQUESTED,
        EVENT_FINDING_CREATED,
        RESOURCE_CLOUD_CHECK_RUN,
        RESOURCE_FINDING,
        RESULT_SUCCESS,
        AuditService,
    )

    existing = (
        db.query(CloudCheckRun)
        .filter(CloudCheckRun.discovery_run_id == discovery_run.id)
        .first()
    )
    if existing is not None:
        return existing, False
    if str(getattr(discovery_run, "status", "") or "").lower() not in ("completed", "partial"):
        raise ValueError("Discovery run has no terminal evidence to evaluate")

    now = _utcnow_naive()
    run = CloudCheckRun(
        id=str(uuid.uuid4()),
        organization_id=project.organization_id,
        project_id=project.id,
        connection_id=connection.id,
        discovery_run_id=discovery_run.id,
        status="running",
        check_pack_version=CHECK_PACK_VERSION,
        requested_by=actor_user_id,
        started_at=now,
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(CloudCheckRun)
            .filter(CloudCheckRun.discovery_run_id == discovery_run.id)
            .first()
        )
        return existing, False
    AuditService.record(
        db, event_type=EVENT_CLOUD_CHECK_RUN_REQUESTED, action=EVENT_CLOUD_CHECK_RUN_REQUESTED,
        result=RESULT_SUCCESS, actor_user_id=actor_user_id, organization_id=project.organization_id,
        project_id=project.id, resource_type=RESOURCE_CLOUD_CHECK_RUN, resource_id=run.id,
        metadata={"discovery_run_id": discovery_run.id, "connection_id": connection.id},
    )

    assets = (
        db.query(Asset)
        .filter(Asset.project_id == project.id, Asset.asset_type.in_(["cloud_account", "cloud_resource"]))
        .order_by(Asset.value)
        .limit(MAX_EVAL_ASSETS)
        .all()
    )
    known_fps = _existing_fingerprints(db, project.id)
    counts = {"passed": 0, "failed": 0, "not_assessed": 0, "errors": 0}
    breakdown: dict[str, dict[str, int]] = {}
    findings_created = 0
    evaluated = 0

    for asset in assets:
        meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
        asset_meta = dict(meta)
        asset_meta["value"] = asset.value
        for check in list_catalog(provider="aws"):
            if asset_meta.get("resource_type") not in (check.get("resource_types") or []):
                continue
            evaluated += 1
            entry = breakdown.setdefault(check["check_id"], {"passed": 0, "failed": 0, "not_assessed": 0, "errors": 0})
            result, evidence, note = evaluate_asset(check, asset_meta, discovery_run.id)
            if result == RESULT_PASS:
                counts["passed"] += 1
                entry["passed"] += 1
            elif result == RESULT_FAIL:
                counts["failed"] += 1
                entry["failed"] += 1
                title = f"{check['check_id']}: {check['title']}"
                fingerprint = lc.d8_fingerprint(
                    lc.d8_finding_input(_finding_proxy(title, check["check_id"], asset.value, asset.id)))
                if fingerprint in known_fps:
                    continue
                known_fps.add(fingerprint)
                finding_meta = {
                    "rule_id": check["check_id"],
                    "check_id": check["check_id"],
                    "check_version": check.get("version"),
                    "provider": "aws",
                    "service": check.get("service"),
                    "resource_type": asset_meta.get("resource_type"),
                    "resource_id": str(asset_meta.get("resource_id") or "")[:500],
                    "arn": str(asset_meta.get("arn") or "")[:1024] or None,
                    "region": asset_meta.get("region"),
                    "account_id": asset_meta.get("account_id"),
                    "asset_type": "cloud_resource",
                    "asset_value": asset.value,
                    "discovery_run_id": discovery_run.id,
                    "connection_id": connection.id,
                    "observed_at": asset_meta.get("observed_at"),
                    "confidence_score": 90,
                    "confidence_level": "high",
                }
                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_id=None,
                    target_id=None,
                    scanner="cloud",
                    title=title[:500],
                    description=f"{check.get('description', '')} Evidence: {note}"[:2000],
                    severity=str(check.get("severity", "medium")).lower(),
                    score=int(SEVERITY_SCORES.get(str(check.get("severity", "medium")).lower(), 50)),
                    status="open",
                    evidence=_json.dumps(evidence, sort_keys=True)[:2000] if evidence else None,
                    remediation=str(check.get("remediation") or "")[:2000] or None,
                    cve=None,
                    cwe=None,
                    asset_id=asset.id,
                    extra_data=finding_meta,
                )
                db.add(finding)
                findings_created += 1
                AuditService.record(
                    db, event_type=EVENT_FINDING_CREATED, action=EVENT_FINDING_CREATED,
                    result=RESULT_SUCCESS, actor_user_id=actor_user_id, organization_id=project.organization_id,
                    project_id=project.id, resource_type=RESOURCE_FINDING, resource_id=finding.id,
                    metadata={"check_id": check["check_id"], "discovery_run_id": discovery_run.id},
                )
            elif result == RESULT_NOT_ASSESSED:
                counts["not_assessed"] += 1
                entry["not_assessed"] += 1
            else:
                counts["errors"] += 1
                entry["errors"] += 1

    run.checks_executed = len(list_catalog(provider="aws"))
    run.resources_evaluated = evaluated
    run.passed = counts["passed"]
    run.failed = counts["failed"]
    run.not_assessed = counts["not_assessed"]
    run.errors = counts["errors"]
    run.findings_created = findings_created
    run.breakdown = breakdown
    run.finished_at = _utcnow_naive()
    if counts["errors"]:
        run.status = "partial"
        run_event, run_result = EVENT_CLOUD_CHECK_RUN_PARTIAL, RESULT_SUCCESS
    else:
        run.status = "completed"
        run_event, run_result = EVENT_CLOUD_CHECK_RUN_COMPLETED, RESULT_SUCCESS
    AuditService.record(
        db, event_type=run_event, action=run_event, result=run_result,
        actor_user_id=actor_user_id, organization_id=project.organization_id,
        project_id=project.id, resource_type=RESOURCE_CLOUD_CHECK_RUN, resource_id=run.id,
        metadata={"discovery_run_id": discovery_run.id, "failed": counts["failed"],
                  "passed": counts["passed"], "not_assessed": counts["not_assessed"],
                  "findings_created": findings_created},
    )
    db.commit()
    db.refresh(run)
    return run, True
