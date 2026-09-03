import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.db.base import Base
from app.db.database import get_db
from app.main import app
from app.models.organization import Organization
from app.models.user import User


def test_password_hash_round_trip():
    hashed = hash_password("correct-password")
    assert hashed != "correct-password"
    assert verify_password("correct-password", hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_access_token_round_trip():
    token = create_access_token("user-123")
    assert decode_access_token(token) == "user-123"


def _auth_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(
        bind=engine,
        tables=[Organization.__table__, User.__table__],
    )

    db = TestingSession()
    org = Organization(
        id=str(uuid.uuid4()),
        name="Example Org",
        slug="example-org",
    )
    user = User(
        id=str(uuid.uuid4()),
        organization_id=org.id,
        email="analyst@example.com",
        password_hash=hash_password("valid-password"),
        role="admin",
    )
    db.add_all([org, user])
    email = "analyst@example.com"
    db.commit()
    db.close()

    def override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client, email


def test_login_rejects_invalid_credentials():
    client, email = _auth_client()
    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "not-the-password"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password."
    finally:
        app.dependency_overrides.clear()


def test_login_and_me_succeed_with_valid_credentials():
    client, email = _auth_client()
    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "valid-password"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["user"]["email"] == email
        assert body["user"]["organization_name"] == "Example Org"
        assert "access_token" in body

        me = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert me.status_code == 200
        assert me.json()["email"] == email

        denied = client.get("/api/v1/projects")
        assert denied.status_code == 401
    finally:
        app.dependency_overrides.clear()
