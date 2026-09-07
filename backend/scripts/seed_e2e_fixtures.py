"""Test-only E2E fixture seeder for the VAPT-Tool platform.

WARNING: This script creates test-only data (deterministic UUIDs + the
@test.local domain). It MUST NEVER run in production and MUST NEVER be
registered on any route.

Guards (all must hold, unless --force is used for local iteration):
  * ENVIRONMENT != "production"
  * E2E_SEED_ENABLED == "true"
  * DATABASE_URL is a PostgreSQL URL (never an isolated SQLite test DB)

Idempotent: rows are upserted by deterministic fixture UUIDs, so re-running
does not duplicate data. --purge deletes ONLY fixture-owned rows.

Usage (inside the backend container / repo root):
    docker compose run --rm --no-deps -e E2E_SEED_ENABLED=true backend \
        python scripts/seed_e2e_fixtures.py            # seed
    docker compose run --rm --no-deps -e E2E_SEED_ENABLED=true backend \
        python scripts/seed_e2e_fixtures.py --purge    # remove fixtures
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ---- path bootstrap ---------------------------------------------------------
_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# ---- guards -----------------------------------------------------------------
E2E_SEED_PASSWORD = "E2eTestPass!2026"  # test-only credential, never reused


def _guard() -> None:
    if os.environ.get("ENVIRONMENT", "").strip().lower() == "production":
        _die("Refusing to seed E2E fixtures: ENVIRONMENT is production.")
    if os.environ.get("E2E_SEED_ENABLED", "").strip().lower() != "true" and "--force" not in sys.argv:
        _die(
            "Refusing to seed E2E fixtures: E2E_SEED_ENABLED != true. "
            "Set E2E_SEED_ENABLED=true (or pass --force for local iteration)."
        )
    url = os.environ.get("DATABASE_URL", "")
    if not url.lower().startswith("postgresql://"):
        _die("Refusing to seed E2E fixtures: DATABASE_URL is not PostgreSQL.")


def _die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


# ---- deterministic fixture identifiers --------------------------------------
# All belong to the reserved namespace e2eaaaaa-0000-4000-8000-xxxxxxxxxxxx.
ORG_A_ID = "e2eaaaaa-0000-4000-8000-000000000001"
ORG_B_ID = "e2eaaaaa-0000-4000-8000-000000000002"

PROJECT_A1_ID = "e2eaaaaa-0000-4000-8000-0000000000a1"  # "E2E Alpha One"
PROJECT_A2_ID = "e2eaaaaa-0000-4000-8000-0000000000a2"  # "E2E Alpha Two"
PROJECT_B1_ID = "e2eaaaaa-0000-4000-8000-0000000000b1"  # "E2E Beta One"

USER_SUPER_ADMIN = "e2eaaaaa-0000-4000-8000-000000000101"  # platform super_admin (org B home)
USER_ORG_ADMIN = "e2eaaaaa-0000-4000-8000-000000000102"    # org A org_admin + project_admin A1/A2
USER_PROJECT_ADMIN = "e2eaaaaa-0000-4000-8000-000000000103"  # org A member; project_admin A1 only
USER_ANALYST = "e2eaaaaa-0000-4000-8000-000000000104"      # org A member; analyst A1 only
USER_VIEWER = "e2eaaaaa-0000-4000-8000-000000000105"       # org A member; viewer A1 only
USER_MEMBER_B = "e2eaaaaa-0000-4000-8000-000000000106"     # org B member; analyst B1
USER_PWRESET = "e2eaaaaa-0000-4000-8000-000000000107"      # org A member; dedicated for password-reset E2E (no storageState reuse)
USER_ONBOARD = "e2eaaaaa-0000-4000-8000-000000000108"      # org A member; dedicated for onboarding E2E

TARGET_A1_ID = "e2eaaaaa-0000-4000-8000-0000000000t1"
TARGET_A2_ID = "e2eaaaaa-0000-4000-8000-0000000000t2"
TARGET_B1_ID = "e2eaaaaa-0000-4000-8000-0000000000t3"

SCAN_A1_ID = "e2eaaaaa-0000-4000-8000-0000000000s1"
SCAN_A2_ID = "e2eaaaaa-0000-4000-8000-0000000000s3"
SCAN_B1_ID = "e2eaaaaa-0000-4000-8000-0000000000s2"

ASSET_A1_ID = "e2eaaaaa-0000-4000-8000-0000000000x1"  # dns e2e-alpha.example.test
ASSET_A2_ID = "e2eaaaaa-0000-4000-8000-0000000000x2"  # webapp http://e2e-alpha.example.test/
ASSET_B1_ID = "e2eaaaaa-0000-4000-8000-0000000000x3"  # dns e2e-beta.example.test

FINDING_F_CRIT = "e2eaaaaa-0000-4000-8000-0000000000f1"
FINDING_F_HIGH = "e2eaaaaa-0000-4000-8000-0000000000f2"
FINDING_F_MED = "e2eaaaaa-0000-4000-8000-0000000000f3"
FINDING_F_LOW = "e2eaaaaa-0000-4000-8000-0000000000f4"
FINDING_F_INFO = "e2eaaaaa-0000-4000-8000-0000000000f5"
FINDING_F_XSS = "e2eaaaaa-0000-4000-8000-0000000000f6"
FINDING_F_B1 = "e2eaaaaa-0000-4000-8000-0000000000f7"

REPORT_A1_ID = "e2eaaaaa-0000-4000-8000-0000000000r1"
REPORT_B1_ID = "e2eaaaaa-0000-4000-8000-0000000000r2"

FIXTURE_USER_IDS = {
    USER_SUPER_ADMIN, USER_ORG_ADMIN, USER_PROJECT_ADMIN,
    USER_ANALYST, USER_VIEWER, USER_MEMBER_B, USER_PWRESET, USER_ONBOARD,
}
FIXTURE_ORG_IDS = {ORG_A_ID, ORG_B_ID}
FIXTURE_PROJECT_IDS = {PROJECT_A1_ID, PROJECT_A2_ID, PROJECT_B1_ID}
FIXTURE_TARGET_IDS = {TARGET_A1_ID, TARGET_A2_ID, TARGET_B1_ID}
FIXTURE_SCAN_IDS = {SCAN_A1_ID, SCAN_A2_ID, SCAN_B1_ID}
FIXTURE_ASSET_IDS = {ASSET_A1_ID, ASSET_A2_ID, ASSET_B1_ID}
FIXTURE_FINDING_IDS = {
    FINDING_F_CRIT, FINDING_F_HIGH, FINDING_F_MED,
    FINDING_F_LOW, FINDING_F_INFO, FINDING_F_XSS, FINDING_F_B1,
}
FIXTURE_REPORT_IDS = {REPORT_A1_ID, REPORT_B1_ID}

XSS_PAYLOAD_TITLE = 'E2E XSS <img src=x onerror="window.__E2E_XSS_FIRED__=1"> Title'


def _users() -> dict[str, dict]:
    return {
        USER_SUPER_ADMIN: {
            "email": "e2e.superadmin@test.local",
            "org": ORG_B_ID,
            "role": "super_admin",
            "status": "active",
        },
        USER_ORG_ADMIN: {
            "email": "e2e.orgadmin@test.local",
            "org": ORG_A_ID,
            "role": "member",
            "status": "active",
        },
        USER_PROJECT_ADMIN: {
            "email": "e2e.projectadmin@test.local",
            "org": ORG_A_ID,
            "role": "member",
            "status": "active",
        },
        USER_ANALYST: {
            "email": "e2e.analyst@test.local",
            "org": ORG_A_ID,
            "role": "member",
            "status": "active",
        },
        USER_VIEWER: {
            "email": "e2e.viewer@test.local",
            "org": ORG_A_ID,
            "role": "member",
            "status": "active",
        },
        USER_MEMBER_B: {
            "email": "e2e.memberb@test.local",
            "org": ORG_B_ID,
            "role": "member",
            "status": "active",
        },
        USER_PWRESET: {
            "email": "e2e.pwreset@test.local",
            "org": ORG_A_ID,
            "role": "member",
            "status": "active",
        },
        USER_ONBOARD: {
            "email": "e2e.onboard@test.local",
            "org": ORG_A_ID,
            "role": "member",
            "status": "active",
        },
    }


def _org_memberships() -> dict[tuple[str, str], str]:
    """(org_id, user_id) -> role"""
    return {
        (ORG_A_ID, USER_ORG_ADMIN): "org_admin",
        (ORG_A_ID, USER_PROJECT_ADMIN): "member",
        (ORG_A_ID, USER_ANALYST): "member",
        (ORG_A_ID, USER_VIEWER): "member",
        (ORG_A_ID, USER_PWRESET): "member",
        (ORG_A_ID, USER_ONBOARD): "member",
        (ORG_B_ID, USER_MEMBER_B): "member",
    }


def _project_memberships() -> dict[tuple[str, str], str]:
    """(project_id, user_id) -> role"""
    return {
        (PROJECT_A1_ID, USER_ORG_ADMIN): "project_admin",
        (PROJECT_A1_ID, USER_PROJECT_ADMIN): "project_admin",
        (PROJECT_A1_ID, USER_ANALYST): "analyst",
        (PROJECT_A1_ID, USER_VIEWER): "viewer",
        (PROJECT_A1_ID, USER_PWRESET): "analyst",
        (PROJECT_A1_ID, USER_ONBOARD): "analyst",
        (PROJECT_A2_ID, USER_ORG_ADMIN): "project_admin",
        (PROJECT_B1_ID, USER_MEMBER_B): "analyst",
    }


def _seed(engine) -> None:
    from sqlalchemy.orm import Session

    from app.core.security import hash_password
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.organization import Organization
    from app.models.organization_membership import OrganizationMembership
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    from app.models.report import Report
    from app.models.scan import Scan
    from app.models.target import Target
    from app.models.user import User

    session = Session(bind=engine)

    def get_or_create(model, pk: str) -> object:
        row = session.get(model, pk)
        if row is None:
            row = model(id=pk)
            session.add(row)
        return row

    # organizations -----------------------------------------------------------
    for org_id, name, slug, status in [
        (ORG_A_ID, "E2E Organization Alpha", "e2e-org-alpha", "active"),
        (ORG_B_ID, "E2E Organization Beta", "e2e-org-beta", "active"),
    ]:
        org = get_or_create(Organization, org_id)
        org.name = name
        org.slug = slug
        org.status = status

    session.flush()

    # users ------------------------------------------------------------------
    password_hash = hash_password(E2E_SEED_PASSWORD)
    for user_id, cfg in _users().items():
        user = get_or_create(User, user_id)
        user.email = cfg["email"]
        user.password_hash = password_hash
        user.organization_id = cfg["org"]
        user.role = cfg["role"]
        user.status = cfg["status"]

    session.flush()

    # memberships -------------------------------------------------------------
    for (org_id, user_id), role in _org_memberships().items():
        row = (
            session.query(OrganizationMembership)
            .filter_by(organization_id=org_id, user_id=user_id)
            .first()
        )
        if row is None:
            row = OrganizationMembership(organization_id=org_id, user_id=user_id)
            session.add(row)
        row.role = role
        row.status = "active"

    session.flush()

    # projects ----------------------------------------------------------------
    for proj_id, org_id, name, description in [
        (PROJECT_A1_ID, ORG_A_ID, "E2E Alpha One", "Deterministic E2E fixture project A1 (org A)."),
        (PROJECT_A2_ID, ORG_A_ID, "E2E Alpha Two", "Deterministic E2E fixture project A2 (org A)."),
        (PROJECT_B1_ID, ORG_B_ID, "E2E Beta One", "Deterministic E2E fixture project B1 (org B)."),
    ]:
        proj = get_or_create(Project, proj_id)
        proj.organization_id = org_id
        proj.name = name
        proj.description = description

    session.flush()

    for (project_id, user_id), role in _project_memberships().items():
        row = (
            session.query(ProjectMembership)
            .filter_by(project_id=project_id, user_id=user_id)
            .first()
        )
        if row is None:
            row = ProjectMembership(project_id=project_id, user_id=user_id)
            session.add(row)
        row.role = role
        row.status = "active"

    session.flush()

    # targets -----------------------------------------------------------------
    for tgt_id, proj_id, value, ttype in [
        (TARGET_A1_ID, PROJECT_A1_ID, "e2e-alpha.example.test", "domain"),
        (TARGET_A2_ID, PROJECT_A2_ID, "e2e-alpha-two.example.test", "domain"),
        (TARGET_B1_ID, PROJECT_B1_ID, "e2e-beta.example.test", "domain"),
    ]:
        tgt = get_or_create(Target, tgt_id)
        tgt.project_id = proj_id
        tgt.value = value
        tgt.target_type = ttype
        tgt.is_active = True

    session.flush()

    # scans -------------------------------------------------------------------
    for scan_id, target_id, profile, status, phase, progress, risk_score, risk_grade, risk_level in [
        (SCAN_A1_ID, TARGET_A1_ID, "quick", "completed", "completed", 100, 55, "C", "medium"),
        (SCAN_A2_ID, TARGET_A2_ID, "quick", "completed", "completed", 100, 20, "E", "low"),
        (SCAN_B1_ID, TARGET_B1_ID, "quick", "completed", "completed", 100, 30, "D", "low"),
    ]:
        scan = get_or_create(Scan, scan_id)
        scan.target_id = target_id
        scan.profile = profile
        scan.status = status
        scan.phase = phase
        scan.progress = progress
        scan.risk_score = risk_score
        scan.risk_grade = risk_grade
        scan.risk_level = risk_level

    session.flush()

    # assets ------------------------------------------------------------------
    for asset_id, proj_id, scan_id, atype, value, criticality in [
        (ASSET_A1_ID, PROJECT_A1_ID, SCAN_A1_ID, "dns", "e2e-alpha.example.test", "high"),
        (ASSET_A2_ID, PROJECT_A1_ID, SCAN_A1_ID, "webapp", "http://e2e-alpha.example.test/", "medium"),
        (ASSET_B1_ID, PROJECT_B1_ID, SCAN_B1_ID, "dns", "e2e-beta.example.test", "low"),
    ]:
        asset = get_or_create(Asset, asset_id)
        asset.project_id = proj_id
        asset.first_seen_scan_id = scan_id
        asset.last_seen_scan_id = scan_id
        asset.asset_type = atype
        asset.value = value
        asset.status = "active"
        asset.criticality = criticality
        asset.owner_user_id = None

    session.flush()

    # findings ----------------------------------------------------------------
    find_specs = [
        {
            "id": FINDING_F_CRIT, "scan_id": SCAN_A1_ID, "target_id": TARGET_A1_ID,
            "scanner": "nuclei", "title": "E2E Critical SQL Injection",
            "severity": "critical", "score": 95, "status": "open",
            "cwe": "CWE-89", "asset_id": ASSET_A2_ID,
        },
        {
            "id": FINDING_F_HIGH, "scan_id": SCAN_A1_ID, "target_id": TARGET_A1_ID,
            "scanner": "nmap", "title": "E2E High Open Port Exposure",
            "severity": "high", "score": 80, "status": "confirmed",
            "cwe": None, "asset_id": ASSET_A1_ID,
        },
        {
            "id": FINDING_F_MED, "scan_id": SCAN_A1_ID, "target_id": TARGET_A1_ID,
            "scanner": "zap", "title": "E2E Medium XSS",
            "severity": "medium", "score": 55, "status": "open",
            "cwe": "CWE-79", "asset_id": ASSET_A2_ID,
        },
        {
            "id": FINDING_F_LOW, "scan_id": SCAN_A1_ID, "target_id": TARGET_A1_ID,
            "scanner": "nikto", "title": "E2E Low Information Disclosure",
            "severity": "low", "score": 20, "status": "open",
            "cwe": None, "asset_id": None,
        },
        {
            "id": FINDING_F_INFO, "scan_id": SCAN_A1_ID, "target_id": TARGET_A1_ID,
            "scanner": "nmap", "title": "E2E Info Service Banner",
            "severity": "info", "score": 5, "status": "open",
            "cwe": None, "asset_id": None,
        },
        {
            "id": FINDING_F_XSS, "scan_id": SCAN_A1_ID, "target_id": TARGET_A1_ID,
            "scanner": "zap", "title": XSS_PAYLOAD_TITLE,
            "severity": "high", "score": 70, "status": "open",
            "cwe": "CWE-79", "asset_id": ASSET_A2_ID,
        },
        {
            "id": FINDING_F_B1, "scan_id": SCAN_B1_ID, "target_id": TARGET_B1_ID,
            "scanner": "nuclei", "title": "E2E Beta Medium Finding",
            "severity": "medium", "score": 60, "status": "open",
            "cwe": None, "asset_id": ASSET_B1_ID,
        },
    ]
    for spec in find_specs:
        finding = get_or_create(Finding, spec["id"])
        finding.scan_id = spec["scan_id"]
        finding.target_id = spec["target_id"]
        finding.scanner = spec["scanner"]
        finding.title = spec["title"]
        finding.description = (
            "E2E fixture finding. Deterministic test data — safe to delete."
        )
        finding.severity = spec["severity"]
        finding.score = spec["score"]
        finding.status = spec["status"]
        finding.cwe = spec["cwe"]
        finding.cve = None
        finding.asset_id = spec["asset_id"]
        finding.evidence = "Deterministic E2E fixture — no real exploit was performed."
        finding.remediation = "Not applicable for fixture data."
        finding.assigned_to = None
        finding.owner_user_id = None
        finding.severity_override = None

    session.flush()

    # reports -----------------------------------------------------------------
    for report_id, org_id, proj_id, title, summary in [
        (
            REPORT_A1_ID, ORG_A_ID, PROJECT_A1_ID,
            "E2E Executive Security Report",
            {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1, "total": 6},
        ),
        (
            REPORT_B1_ID, ORG_B_ID, PROJECT_B1_ID,
            "E2E Beta Executive Report",
            {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1},
        ),
    ]:
        report = get_or_create(Report, report_id)
        report.organization_id = org_id
        report.project_id = proj_id
        report.report_type = "executive_security"
        report.title = title
        report.status = "completed"
        report.generated_by = USER_ANALYST if org_id == ORG_A_ID else USER_MEMBER_B
        report.parameters = {"format": "executive_security", "style": "modern"}
        report.summary = summary
        report.content = {"sections": [{"title": "Executive Summary", "body": "Fixture report content."}]}
        report.data_snapshot = {"fixture": True}
        report.version = "1.0"

    session.commit()
    counts = {
        "organizations": 2,
        "users": 6,
        "projects": 3,
        "targets": 3,
        "scans": 3,
        "assets": 3,
        "findings": 7,
        "reports": 2,
    }
    print("[e2e-seed] E2E fixtures seeded:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"[e2e-seed] All fixture users share the test-only password: {E2E_SEED_PASSWORD}")


def _purge(engine) -> None:
    from sqlalchemy.orm import Session

    from app.models.finding import (
        Finding, FindingComment, FindingHistory, FindingRiskAcceptance,
        FindingSLA, FindingTag,
    )
    from app.models.organization import Organization
    from app.models.organization_membership import OrganizationMembership
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    from app.models.report import Report
    from app.models.scan import Scan
    from app.models.target import Target
    from app.models.user import User
    from app.models.asset import Asset

    session = Session(bind=engine)

    # Findings first (they reference scans/targets/assets)
    for model in (FindingTag, FindingComment, FindingHistory, FindingSLA, FindingRiskAcceptance):
        try:
            session.query(model).filter(model.finding_id.in_(FIXTURE_FINDING_IDS)).delete(synchronize_session=False)
        except Exception:
            session.rollback()
    session.query(Finding).filter(
        (Finding.scan_id.in_(FIXTURE_SCAN_IDS)) | (Finding.target_id.in_(FIXTURE_TARGET_IDS))
    ).delete(synchronize_session=False)

    # Assets reference scans
    session.query(Asset).filter(Asset.project_id.in_(FIXTURE_PROJECT_IDS)).delete(synchronize_session=False)
    # Scans reference targets
    session.query(Scan).filter(Scan.target_id.in_(FIXTURE_TARGET_IDS)).delete(synchronize_session=False)
    # Targets reference projects
    session.query(Target).filter(Target.id.in_(FIXTURE_TARGET_IDS)).delete(synchronize_session=False)
    # Reports
    session.query(Report).filter(Report.id.in_(FIXTURE_REPORT_IDS)).delete(synchronize_session=False)
    # Memberships
    session.query(ProjectMembership).filter(
        (ProjectMembership.project_id.in_(FIXTURE_PROJECT_IDS))
        | (ProjectMembership.user_id.in_(FIXTURE_USER_IDS))
    ).delete(synchronize_session=False)
    session.query(OrganizationMembership).filter(
        (OrganizationMembership.organization_id.in_(FIXTURE_ORG_IDS))
        | (OrganizationMembership.user_id.in_(FIXTURE_USER_IDS))
    ).delete(synchronize_session=False)
    # Projects
    session.query(Project).filter(Project.id.in_(FIXTURE_PROJECT_IDS)).delete(synchronize_session=False)
    # Users
    session.query(User).filter(User.id.in_(FIXTURE_USER_IDS)).delete(synchronize_session=False)
    # Organizations
    session.query(Organization).filter(Organization.id.in_(FIXTURE_ORG_IDS)).delete(synchronize_session=False)

    session.commit()
    print("[e2e-seed] E2E fixtures purged (only fixture-owned rows removed).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed/purge deterministic E2E fixtures.")
    parser.add_argument(
        "--purge",
        action="store_true",
        help="Remove fixture-owned rows instead of seeding.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass E2E_SEED_ENABLED guard (still blocked in production).",
    )
    args = parser.parse_args()

    _guard()

    from app.db.database import engine

    try:
        if args.purge:
            _purge(engine)
        else:
            _seed(engine)
    except Exception as exc:  # noqa: BLE001 - CLI should fail loudly
        print(f"ERROR: seeding failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()