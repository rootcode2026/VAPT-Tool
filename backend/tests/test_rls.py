"""
RLS foundation tests — preparation only, default-off.

SQLite is the default test dialect (existing project pattern).
PostgreSQL integration tests are optional and skipped when PG is unavailable;
they must not be claimed as verified when only SQLite ran.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db import rls
from app.db.base import Base


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sqlite_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return engine, Session()


def _valid_uuid() -> str:
    return str(uuid.uuid4())


def _pg_available() -> bool:
    """Return True if we can connect to the configured PostgreSQL."""
    url = getattr(settings, "DATABASE_URL", "")
    if not url or "postgres" not in url:
        return False
    try:
        from sqlalchemy import create_engine as _ce

        eng = _ce(url, connect_args={"connect_timeout": 2})
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        eng.dispose()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 1. Configuration — RLS must be OFF by default
# ---------------------------------------------------------------------------

def test_rls_disabled_by_default():
    # Default must be false — never silently enabled.
    assert rls.is_rls_enabled() is False
    assert settings.RLS_ENABLED is False


def test_rls_enabled_flag_respects_env(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    assert rls.is_rls_enabled() is True
    monkeypatch.setattr(settings, "RLS_ENABLED", False)
    assert rls.is_rls_enabled() is False


# ---------------------------------------------------------------------------
# 2. Validation
# ---------------------------------------------------------------------------

def test_validate_accepts_valid_uuids():
    for kind in ("organization_id", "project_id", "user_id"):
        v = _valid_uuid()
        assert rls.validate_context_value(v, kind) == v.lower()
        # With surrounding whitespace
        assert rls.validate_context_value(f"  {v}  ", kind) == v.lower()


def test_validate_rejects_invalid_uuids():
    invalid = [
        "",
        "   ",
        None,
        "not-a-uuid",
        "123",
        "'; DROP TABLE projects; --",
        "app.current_organization_id",
        "00000000-0000-0000-0000-00000000000",  # too short
        "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
        "../etc/passwd",
        "1'; SET LOCAL app.current_organization_id='other' --",
    ]
    for val in invalid:
        with pytest.raises(ValueError):
            rls.validate_context_value(val, "organization_id")


def test_validate_rejects_empty_project():
    with pytest.raises(ValueError):
        rls.validate_context_value("", "project_id")


def test_validate_rejects_unknown_kind():
    with pytest.raises(ValueError, match="Unknown context kind"):
        rls.validate_context_value(_valid_uuid(), "unknown_kind")


def test_validate_missing_org_raises():
    with pytest.raises(ValueError):
        rls.validate_context_value(None, "organization_id")
    with pytest.raises(ValueError):
        # type: ignore — test None handling
        rls.set_tenant_context(MagicMock(), organization_id=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 3. RLS disabled / SQLite no-op behavior (validation still runs)
# ---------------------------------------------------------------------------

def test_set_noop_when_disabled_even_with_valid_uuid():
    _, db = _sqlite_session()
    org = _valid_uuid()
    # Should not raise and should not attempt PG-specific execute to fail.
    rls.set_tenant_context(db, organization_id=org)
    # No exception, no RLS effect — existing behavior unchanged.
    db.close()


def test_set_noop_on_sqlite_even_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    _, db = _sqlite_session()
    org = _valid_uuid()
    proj = _valid_uuid()
    uid = _valid_uuid()
    # SQLite dialect -> no-op after validation, must not raise.
    rls.set_tenant_context(db, organization_id=org, project_id=proj, user_id=uid)
    # get_current_tenant_context on SQLite returns Nones
    ctx = rls.get_current_tenant_context(db)
    assert ctx == {"organization_id": None, "project_id": None, "user_id": None}
    monkeypatch.setattr(settings, "RLS_ENABLED", False)
    db.close()


def test_clear_noop_when_disabled():
    _, db = _sqlite_session()
    rls.clear_tenant_context(db)
    db.close()


def test_get_context_sqlite_returns_nones():
    _, db = _sqlite_session()
    ctx = rls.get_current_tenant_context(db)
    assert ctx == {"organization_id": None, "project_id": None, "user_id": None}
    db.close()


# ---------------------------------------------------------------------------
# 4. Malicious input cannot alter SQL — validation before execute
# ---------------------------------------------------------------------------

def test_malicious_input_rejected_before_execute(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    _, db = _sqlite_session()
    # Patch _is_postgresql to simulate PG so execute would be attempted if validation passed.
    # But validation must reject injection strings first.
    malicious = "'; SET LOCAL app.current_organization_id='attacker' --"
    with patch.object(rls, "_is_postgresql", return_value=True):
        mock_execute = MagicMock()
        db.execute = mock_execute  # type: ignore[method-assign]
        with pytest.raises(ValueError):
            rls.set_tenant_context(db, organization_id=malicious)
        mock_execute.assert_not_called()
    monkeypatch.setattr(settings, "RLS_ENABLED", False)
    db.close()


def test_untrusted_request_data_must_be_validated():
    # Simulates api route taking org_id from query param without verification.
    # Helper must reject raw client values that are not UUIDs that passed
    # require_project_access / get_current_user.
    fake_client_org = "attacker-chosen-org-id"
    _, db = _sqlite_session()
    with pytest.raises(ValueError):
        rls.set_tenant_context(db, organization_id=fake_client_org)
    db.close()


# ---------------------------------------------------------------------------
# 5. Transaction-local / pool safety — mocked PostgreSQL
# ---------------------------------------------------------------------------

def test_set_requires_transaction_when_postgres(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    mock_db = MagicMock()
    mock_db.bind.dialect.name = "postgresql"
    mock_db.in_transaction.return_value = False
    mock_db.in_nested_transaction.return_value = False
    # Ensure _is_postgresql sees postgresql
    with patch.object(rls, "_is_postgresql", return_value=True):
        with pytest.raises(RuntimeError, match="must be called inside an explicit transaction"):
            rls.set_tenant_context(mock_db, organization_id=_valid_uuid())
    monkeypatch.setattr(settings, "RLS_ENABLED", False)


def test_set_succeeds_in_transaction_postgres_mock(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    org = _valid_uuid()
    proj = _valid_uuid()
    uid = _valid_uuid()
    mock_db = MagicMock()
    mock_db.bind.dialect.name = "postgresql"
    mock_db.in_transaction.return_value = True
    mock_db.in_nested_transaction.return_value = False
    with patch.object(rls, "_is_postgresql", return_value=True):
        rls.set_tenant_context(mock_db, organization_id=org, project_id=proj, user_id=uid)
        # Must use parameterized set_config, never string interpolation.
        assert mock_db.execute.call_count == 3
        for call in mock_db.execute.call_args_list:
            args, kwargs = call
            sql_text = str(args[0])
            assert "set_config" in sql_text
            assert ":k" in sql_text and ":v" in sql_text
            # Params contain trusted GUC key and validated UUID
            params = args[1] if len(args) > 1 else kwargs
            assert params["k"] in (rls.RLS_GUC_ORG, rls.RLS_GUC_PROJECT, rls.RLS_GUC_USER)
            # No raw tenant value interpolated into SQL string
            assert org not in sql_text and proj not in sql_text and uid not in sql_text
    monkeypatch.setattr(settings, "RLS_ENABLED", False)


def test_set_with_org_only_calls_once(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    org = _valid_uuid()
    mock_db = MagicMock()
    mock_db.in_transaction.return_value = True
    mock_db.in_nested_transaction.return_value = False
    with patch.object(rls, "_is_postgresql", return_value=True):
        rls.set_tenant_context(mock_db, organization_id=org)
        assert mock_db.execute.call_count == 1
    monkeypatch.setattr(settings, "RLS_ENABLED", False)


def test_set_config_uses_parameterized_query(monkeypatch):
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    org = _valid_uuid()
    mock_db = MagicMock()
    mock_db.in_transaction.return_value = True
    mock_db.in_nested_transaction.return_value = False
    # Even if org contains SQL special chars, it must be rejected by validation,
    # but if it were somehow valid, it must still be passed as bound param.
    with patch.object(rls, "_is_postgresql", return_value=True):
        rls.set_tenant_context(mock_db, organization_id=org)
        sql = str(mock_db.execute.call_args[0][0])
        assert "SELECT set_config(:k, :v, true)" in sql
    monkeypatch.setattr(settings, "RLS_ENABLED", False)


# ---------------------------------------------------------------------------
# 6. Context does not leak — mocked pool isolation
# ---------------------------------------------------------------------------

def test_context_does_not_leak_between_transactions_mock(monkeypatch):
    """
    Simulate QueuePool reuse: two sequential transactions on same engine must not
    share context. On PG, COMMIT clears SET LOCAL; we verify helper is called
    per-transaction and get_current_tenant_context would be empty after commit.
    """
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    org_a = _valid_uuid()
    org_b = _valid_uuid()

    # First transaction
    mock_db = MagicMock()
    mock_db.in_transaction.return_value = True
    # get_current_tenant_context will be mocked to return set value then None after commit.
    with patch.object(rls, "_is_postgresql", return_value=True):
        rls.set_tenant_context(mock_db, organization_id=org_a)
        first_calls = mock_db.execute.call_count
        # Simulate COMMIT clearing — after commit, a new transaction should not see org_a.
        # We verify the second transaction sets org_b independently.
        mock_db2 = MagicMock()
        mock_db2.in_transaction.return_value = True
        with patch.object(rls, "_is_postgresql", return_value=True):
            rls.set_tenant_context(mock_db2, organization_id=org_b)
            # Each transaction had exactly one set_config for org
            assert mock_db.execute.call_count == 1
            assert mock_db2.execute.call_count == 1
            # The values must differ — no leak of org_a into second tx
            assert mock_db.execute.call_args[0][1]["v"] == org_a
            assert mock_db2.execute.call_args[0][1]["v"] == org_b
    monkeypatch.setattr(settings, "RLS_ENABLED", False)


def test_context_does_not_leak_between_pooled_connections_sqlite(monkeypatch):
    """
    SQLite variant: even though helper is no-op on sqlite, two sessions from same
    engine (simulating pooled connections) must remain independent. This verifies
    the existing project pattern of SessionLocal(close) returning clean connections.
    """
    monkeypatch.setattr(settings, "RLS_ENABLED", True)
    engine, _ = _sqlite_session()
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db_a = Session()
    db_b = Session()
    org_a = _valid_uuid()
    org_b = _valid_uuid()
    # Both are no-ops on sqlite, but they must not interfere — no shared state in helper.
    rls.set_tenant_context(db_a, organization_id=org_a)
    rls.set_tenant_context(db_b, organization_id=org_b)
    # Both contexts are None on sqlite (no PG GUCs)
    assert rls.get_current_tenant_context(db_a) == {"organization_id": None, "project_id": None, "user_id": None}
    assert rls.get_current_tenant_context(db_b) == {"organization_id": None, "project_id": None, "user_id": None}
    db_a.close()
    db_b.close()
    engine.dispose()
    monkeypatch.setattr(settings, "RLS_ENABLED", False)


# ---------------------------------------------------------------------------
# 7. Optional PostgreSQL integration (real transaction-local verification)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL not available — integration unverified")
def test_postgres_transaction_local_and_pool_isolation():
    """
    Real PG verification: SET LOCAL via set_config(..., true) is transaction-local
    and does not leak across pooled connections or after COMMIT.
    This test is skipped when PG is not reachable; do not claim PG verification
    from SQLite alone.
    """
    # Use the real DATABASE_URL engine — QueuePool
    from sqlalchemy import create_engine as _ce

    engine = _ce(settings.DATABASE_URL, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    # Enable RLS for this test via monkeypatch-like direct set
    orig = settings.RLS_ENABLED
    settings.RLS_ENABLED = True  # type: ignore[attr-defined]
    try:
        org_a = _valid_uuid()
        org_b = _valid_uuid()

        # Transaction 1: set and verify inside
        db = Session()
        with db.begin():
            rls.set_tenant_context(db, organization_id=org_a)
            ctx = rls.get_current_tenant_context(db)
            assert ctx["organization_id"] == org_a.lower()
        # After COMMIT, context must be cleared
        with db.begin():
            ctx2 = rls.get_current_tenant_context(db)
            assert ctx2["organization_id"] is None
        db.close()

        # Pooled connection reuse: new session from same engine must not see org_a
        db2 = Session()
        with db2.begin():
            ctx3 = rls.get_current_tenant_context(db2)
            assert ctx3["organization_id"] is None
            rls.set_tenant_context(db2, organization_id=org_b)
            ctx4 = rls.get_current_tenant_context(db2)
            assert ctx4["organization_id"] == org_b.lower()
        with db2.begin():
            assert rls.get_current_tenant_context(db2)["organization_id"] is None
        db2.close()
        engine.dispose()
    finally:
        settings.RLS_ENABLED = orig  # type: ignore[attr-defined]
