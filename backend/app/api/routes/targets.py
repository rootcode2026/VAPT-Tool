import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.target import Target
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
):
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
    db: Session = Depends(get_db),
):
    return db.query(Target).all()


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
)
def get_target(
    target_id: str,
    db: Session = Depends(get_db),
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

    return target


@router.delete(
    "/{target_id}",
)
def delete_target(
    target_id: str,
    db: Session = Depends(get_db),
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

    db.delete(target)
    db.commit()

    return {
        "message": "Target deleted successfully",
    }