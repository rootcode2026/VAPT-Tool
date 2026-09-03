import re
import uuid

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User


def _org_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "organization"


def bootstrap_auth_user(db: Session) -> None:
    email = settings.AUTH_BOOTSTRAP_EMAIL.lower()
    password = settings.AUTH_BOOTSTRAP_PASSWORD

    if not email or not password:
        return

    existing = db.query(User).filter(User.email == email).first()
    if existing is not None:
        return

    org = db.query(Organization).order_by(Organization.name.asc()).first()
    if org is None:
        org = Organization(
            id=str(uuid.uuid4()),
            name=settings.AUTH_BOOTSTRAP_ORG_NAME,
            slug=_org_slug(settings.AUTH_BOOTSTRAP_ORG_NAME),
        )
        db.add(org)
        db.flush()

    user = User(
        id=str(uuid.uuid4()),
        organization_id=org.id,
        email=email,
        password_hash=hash_password(password),
        role="admin",
    )
    db.add(user)
    db.commit()
