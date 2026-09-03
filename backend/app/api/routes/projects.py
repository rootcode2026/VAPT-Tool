import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models.project import Project
from app.models.target import Target
from app.models.user import User
from app.schemas.project import (
    ProjectCreate,
    ProjectResponse,
)


router = APIRouter(
    prefix="/api/v1/projects",
    tags=["Projects"],
)


# ---------------------------------------------------------
# CREATE PROJECT
# ---------------------------------------------------------

@router.post(
    "",
    response_model=ProjectResponse,
)
def create_project(
    data: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = Project(
        id=str(uuid.uuid4()),
        organization_id=current_user.organization_id,
        name=data.name,
        description=data.description,
    )

    db.add(project)
    db.commit()
    db.refresh(project)

    return project


# ---------------------------------------------------------
# GET ALL PROJECTS
# ---------------------------------------------------------

@router.get(
    "",
    response_model=list[ProjectResponse],
)
def get_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Project)
        .filter(Project.organization_id == current_user.organization_id)
        .order_by(Project.name.asc())
        .all()
    )


# ---------------------------------------------------------
# GET SINGLE PROJECT
# ---------------------------------------------------------

@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.organization_id == current_user.organization_id,
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return project


# ---------------------------------------------------------
# DELETE PROJECT
# ---------------------------------------------------------

@router.delete(
    "/{project_id}"
)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.organization_id == current_user.organization_id,
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    # -----------------------------------------------------
    # Check whether project has targets
    # -----------------------------------------------------

    target_count = (
        db.query(Target)
        .filter(
            Target.project_id == project_id
        )
        .count()
    )

    if target_count > 0:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot delete project because it has "
                f"{target_count} target(s). "
                "Remove the targets before deleting "
                "the project."
            ),
        )

    # -----------------------------------------------------
    # Delete project
    # -----------------------------------------------------

    db.delete(project)
    db.commit()

    return {
        "message": "Project deleted successfully",
    }