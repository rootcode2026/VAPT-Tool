import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.project import Project
from app.models.target import Target
from app.models.user import User
from app.schemas.target import TargetCreate, TargetResponse


router = APIRouter(
    prefix="/api/v1/targets",
    tags=["Targets"],
)


@router.post(
    "",
    response_model=TargetResponse,
)
def create_target(
    data: TargetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify target is placed into a project the caller may access.
    require_project_access(data.project_id, db, current_user)

    target = Target(
        id=str(uuid.uuid4()),
        project_id=data.project_id,
        value=data.value,
        target_type=data.target_type,
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    return target


@router.get(
    "",
    response_model=list[TargetResponse],
)
def get_targets(
    project_id: str | None = Query(default=None, description="Filter by project"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Org-scoped by default; optional project filter is verified.
    if project_id is not None:
        require_project_access(project_id, db, current_user)
        return db.query(Target).filter(Target.project_id == project_id).all()
    return (
        db.query(Target)
        .join(Project, Project.id == Target.project_id)
        .filter(Project.organization_id == current_user.organization_id)
        .all()
    )


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
)
def get_target(
    target_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if not target:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )
    # Verify the target's project belongs to the caller's organization.
    require_project_access(target.project_id, db, current_user)

    return target


@router.delete(
    "/{target_id}",
)
def delete_target(
    target_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id)
        .first()
    )

    if not target:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )
    require_project_access(target.project_id, db, current_user)

    db.delete(target)
    db.commit()

    return {
        "message": "Target deleted successfully",
    }