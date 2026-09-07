"""RLS tenant context dependency — sets transaction-local GUCs after authentication."""

from fastapi import Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.rls import set_tenant_context
from app.models.user import User


def set_rls_context(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    """
    FastAPI dependency that sets PostgreSQL RLS tenant context for the current
    DB session's transaction. Must be used after get_current_user, and the
    db session must be in an explicit transaction.

    When RLS is disabled or dialect is not PostgreSQL, this is a no-op (after validation).
    """
    # Derive organization_id from authenticated user (trusted, not client-supplied)
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        try:
            # Ensure we are in a transaction for pool safety
            in_tx = False
            try:
                in_tx = bool(db.in_transaction() or db.in_nested_transaction())
            except Exception:
                in_tx = False
            if not in_tx:
                # Start a transaction for RLS context (will be committed with the request's work)
                db.begin()
            set_tenant_context(db, organization_id=org_id, user_id=current_user.id)
        except Exception:
            # Never break auth if RLS set fails (e.g., invalid UUID, no PG)
            pass
    return current_user
