"""
Project membership backfill service — safe, deterministic, idempotent.

Classifies existing projects into:
- SAFE_TO_BACKFILL: authoritative evidence for a specific user (currently none, because
  project creator is not stored)
- AMBIGUOUS: has activity (targets/scans/assets) but no authoritative user
- NO_EVIDENCE: no activity and no membership
- ALREADY_BACKFILLED: has explicit memberships

For SAFE_TO_BACKFILL it would create explicit memberships with minimum justified role.
For AMBIGUOUS and NO_EVIDENCE it does NOT fabricate — reports for manual assignment.

This service is the administrative process for transitioning from fallback to explicit
membership. It supports --dry-run (default) and --apply (no-op for ambiguous).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.asset import Asset


@dataclass
class ProjectBackfillItem:
    project_id: str
    organization_id: str
    classification: str  # SAFE_TO_BACKFILL | AMBIGUOUS | NO_EVIDENCE | ALREADY_BACKFILLED
    candidate_user_id: str | None
    candidate_role: str | None
    reason: str
    confidence: str


@dataclass
class BackfillReport:
    total_projects: int
    already_backfilled: int
    safe_to_backfill: int
    ambiguous: int
    no_evidence: int
    items: list[ProjectBackfillItem]
    applied: int  # number of memberships actually created (0 for dry-run or when none safe)


def _classify_project(db: Session, project: Project) -> ProjectBackfillItem:
    # Check if already has explicit memberships
    has_explicit = db.query(ProjectMembership).filter(ProjectMembership.project_id == project.id).first() is not None
    if has_explicit:
        return ProjectBackfillItem(
            project_id=project.id,
            organization_id=project.organization_id,
            classification="ALREADY_BACKFILLED",
            candidate_user_id=None,
            candidate_role=None,
            reason="Has explicit project_membership rows",
            confidence="high",
        )

    # Check for activity: targets, scans, assets
    has_targets = db.query(Target).filter(Target.project_id == project.id).first() is not None
    # For scans: via target
    has_scans = (
        db.query(Scan)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project.id)
        .first()
        is not None
    )
    has_assets = db.query(Asset).filter(Asset.project_id == project.id).first() is not None
    has_activity = has_targets or has_scans or has_assets

    if has_activity:
        # No authoritative creator, so cannot safely determine who should be member
        return ProjectBackfillItem(
            project_id=project.id,
            organization_id=project.organization_id,
            classification="AMBIGUOUS",
            candidate_user_id=None,
            candidate_role=None,
            reason="Has activity (targets/scans/assets) but no stored creator/audit; manual assignment required",
            confidence="low",
        )
    else:
        return ProjectBackfillItem(
            project_id=project.id,
            organization_id=project.organization_id,
            classification="NO_EVIDENCE",
            candidate_user_id=None,
            candidate_role=None,
            reason="No activity and no explicit membership; manual assignment required if access needed",
            confidence="low",
        )


def backfill_project_memberships(db: Session, dry_run: bool = True) -> BackfillReport:
    """
    Inspect all projects and classify them. If dry_run is False, create memberships
    for SAFE_TO_BACKFILL only (currently none, so no writes). Idempotent and
    does not overwrite existing memberships.
    """
    projects = db.query(Project).all()
    items: list[ProjectBackfillItem] = []
    safe = 0
    ambiguous = 0
    no_evidence = 0
    already = 0
    applied = 0

    for proj in projects:
        item = _classify_project(db, proj)
        items.append(item)
        if item.classification == "ALREADY_BACKFILLED":
            already += 1
        elif item.classification == "SAFE_TO_BACKFILL":
            safe += 1
            if not dry_run and item.candidate_user_id and item.candidate_role:
                # Check not exists (idempotent)
                exists = (
                    db.query(ProjectMembership)
                    .filter(ProjectMembership.project_id == proj.id, ProjectMembership.user_id == item.candidate_user_id)
                    .first()
                )
                if not exists:
                    db.add(
                        ProjectMembership(
                            id=str(uuid.uuid4()),
                            project_id=proj.id,
                            user_id=item.candidate_user_id,
                            role=item.candidate_role,
                            status="active",
                        )
                    )
                    applied += 1
        elif item.classification == "AMBIGUOUS":
            ambiguous += 1
        elif item.classification == "NO_EVIDENCE":
            no_evidence += 1

    if not dry_run and applied > 0:
        db.commit()
    # No commit for dry-run; ensure no side effects
    return BackfillReport(
        total_projects=len(projects),
        already_backfilled=already,
        safe_to_backfill=safe,
        ambiguous=ambiguous,
        no_evidence=no_evidence,
        items=items,
        applied=applied,
    )


def run_backfill_cli(dry_run: bool = True) -> None:
    """CLI entry point for manual execution."""
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        report = backfill_project_memberships(db, dry_run=dry_run)
        print(f"Total projects: {report.total_projects}")
        print(f"Already backfilled: {report.already_backfilled}")
        print(f"Safe to backfill: {report.safe_to_backfill}")
        print(f"Ambiguous: {report.ambiguous}")
        print(f"No evidence: {report.no_evidence}")
        print(f"Applied: {report.applied} (dry_run={dry_run})")
        for it in report.items:
            print(
                f"  {it.project_id[:8]} org={it.organization_id[:8]} class={it.classification} "
                f"candidate={it.candidate_user_id} role={it.candidate_role} reason={it.reason}"
            )
        if dry_run:
            print("\nDry-run complete. Run with --apply to create memberships for SAFE_TO_BACKFILL (currently none).")
        else:
            print("\nApply complete.")
    finally:
        db.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Project membership backfill (safe, idempotent)")
    parser.add_argument("--apply", action="store_true", help="Actually create memberships for SAFE_TO_BACKFILL")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (default)")
    args = parser.parse_args()
    # Default is dry-run unless --apply is given
    dry = not args.apply
    run_backfill_cli(dry_run=dry)
