"""
Membership management tests for strict RBAC enforcement.

Covers organization and project membership APIs, role assignment security,
self-escalation, cross-organization, last-admin protection, and permission enforcement.
"""

import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.database import get_db
from app.main import app


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255), unique=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="member")


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_membership_org_user"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(50), default="member")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class ProjectMembership(Base):
    __tablename__ = "project_memberships"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_membership_project_user"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    value: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(default=True)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    profile: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="queued")
    phase: Mapped[str] = mapped_column(String(50), default="queued")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_grade: Mapped[str | None] = mapped_column(String(1), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    progress: Mapped[int] = mapped_column(Integer, default=0)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "asset_type", "value", name="uq_assets_project_type_value"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(20), default="active")
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    scanner: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(20), default="info")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanResult(Base):
    __tablename__ = "scan_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    scanner: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="pending")
    raw_output: Mapped[str] = mapped_column(Text, default="")
    attempt: Mapped[int] = mapped_column(Integer, default=1)


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = TestingSession()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    user_member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@org-a.test", password_hash=pwd, role="member")
    user_org_admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@org-a.test", password_hash=pwd, role="admin")
    user_viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@org-a.test", password_hash=pwd, role="member")
    user_analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@org-a.test", password_hash=pwd, role="member")
    user_super = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@platform.test", password_hash=pwd, role="super_admin")
    user_member_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="member-b@org-b.test", password_hash=pwd, role="member")
    user_org_admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@org-b.test", password_hash=pwd, role="admin")
    db.add_all([user_member_a, user_org_admin_a, user_viewer_a, user_analyst_a, user_super, user_member_b, user_org_admin_b])
    db.flush()
    for u, role in [
        (user_member_a, "member"),
        (user_org_admin_a, "org_admin"),
        (user_viewer_a, "member"),
        (user_analyst_a, "member"),
        (user_super, "member"),
        (user_member_b, "member"),
        (user_org_admin_b, "org_admin"),
    ]:
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=u.organization_id, user_id=u.id, role=role))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Project A1")
    proj_a2 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Project A2")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Project B1")
    db.add_all([proj_a1, proj_a2, proj_b1])
    db.flush()
    # Project memberships: viewer-a is viewer on A1, analyst-a is analyst on A1, admin-a is project_admin on A1
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=user_viewer_a.id, role="viewer"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=user_analyst_a.id, role="analyst"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=user_org_admin_a.id, role="project_admin"))
    # member-a has no explicit membership on A1 -> fallback analyst via org
    target_a1 = Target(id=str(uuid.uuid4()), project_id=proj_a1.id, value="a1.example.com", target_type="domain")
    target_b1 = Target(id=str(uuid.uuid4()), project_id=proj_b1.id, value="b1.example.com", target_type="domain")
    db.add_all([target_a1, target_b1])
    db.flush()
    scan_a1 = Scan(id=str(uuid.uuid4()), target_id=target_a1.id, profile="quick", status="completed")
    db.add(scan_a1)
    db.flush()
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [user_member_a, user_org_admin_a, user_viewer_a, user_analyst_a, user_super, user_member_b, user_org_admin_b]}
    return engine, TestingSession, app, tokens, {
        "org_a": org_a, "org_b": org_b,
        "proj_a1": proj_a1, "proj_a2": proj_a2, "proj_b1": proj_b1,
        "target_a1": target_a1, "target_b1": target_b1,
        "user_member_a": user_member_a, "user_org_admin_a": user_org_admin_a,
        "user_viewer_a": user_viewer_a, "user_analyst_a": user_analyst_a,
        "user_super": user_super, "user_member_b": user_member_b, "user_org_admin_b": user_org_admin_b,
    }


def _client(TestingSession):
    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[get_db] = override
    return TestClient(app)


# ---------------------------------------------------------------------------
# Organization membership
# ---------------------------------------------------------------------------

def test_org_admin_can_list_members():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.get(f"/api/v1/organizations/{objs['org_a'].id}/members", headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 200
        assert len(resp.json()) >= 2
    finally:
        app.dependency_overrides.clear()


def test_member_cannot_list_members():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.get(f"/api/v1/organizations/{objs['org_a'].id}/members", headers={"Authorization": f"Bearer {tokens['member-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_org_admin_can_add_member():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # Create a new user in DB directly for adding
        new_user_id = str(uuid.uuid4())
        # Insert via direct DB
        from sqlalchemy import create_engine as _ce
        # Use TestingSession to add user
        db = TestingSession()
        new_user = User(id=new_user_id, organization_id=objs["org_a"].id, email="newuser@org-a.test", password_hash=hash_password("x"), role="member")
        db.add(new_user)
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_user_id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 201, resp.text
    finally:
        app.dependency_overrides.clear()


def test_member_cannot_add_member():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new2@org-a.test", password_hash=hash_password("x"), role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['member-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_duplicate_org_membership_rejected():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # user_member_a already member of org_a
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": objs["user_member_a"].id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 409
    finally:
        app.dependency_overrides.clear()


def test_cross_org_membership_denied():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.get(f"/api/v1/organizations/{objs['org_b'].id}/members", headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 403
        # Try to add member of org A to org B via org A admin -> should be 403 (cannot manage B)
        resp2 = client.post(f"/api/v1/organizations/{objs['org_b'].id}/members", json={"user_id": objs["user_member_a"].id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp2.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_known_uuid_cannot_bypass_org_boundary():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.get(f"/api/v1/organizations/{objs['org_b'].id}/members", headers={"Authorization": f"Bearer {tokens['member-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Role assignment security
# ---------------------------------------------------------------------------

def test_member_cannot_grant_org_admin():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new3@org-a.test", password_hash=hash_password("x"), role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_id, "role": "org_admin"}, headers={"Authorization": f"Bearer {tokens['member-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_viewer_cannot_grant_project_admin():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new4@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": new_id, "role": "project_admin"}, headers={"Authorization": f"Bearer {tokens['viewer-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_grant_project_admin():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new5@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": new_id, "role": "project_admin"}, headers={"Authorization": f"Bearer {tokens['analyst-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_cannot_grant_super_admin():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new6@org-a.test", password_hash=hash_password("x"), role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_id, "role": "super_admin"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code in (400, 403)
    finally:
        app.dependency_overrides.clear()


def test_user_cannot_escalate_own_role():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # viewer tries to promote self to analyst/project_admin
        resp = client.patch(f"/api/v1/projects/{objs['proj_a1'].id}/members/{objs['user_viewer_a'].id}", json={"role": "project_admin"}, headers={"Authorization": f"Bearer {tokens['viewer-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Last admin protection
# ---------------------------------------------------------------------------

def test_cannot_remove_last_org_admin():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # org_a has only one org_admin (admin-a), try to delete -> 409
        resp = client.delete(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['user_org_admin_a'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 409
        # Try to demote
        resp2 = client.patch(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['user_org_admin_a'].id}", json={"role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp2.status_code == 409
    finally:
        app.dependency_overrides.clear()


def test_can_remove_org_admin_when_another_exists():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # Add second org_admin
        second_admin_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=second_admin_id, organization_id=objs["org_a"].id, email="admin2@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=second_admin_id, role="org_admin"))
        db.commit()
        db.close()
        second_token = create_access_token(second_admin_id)
        # Now first admin can be removed
        resp = client.delete(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['user_org_admin_a'].id}", headers={"Authorization": f"Bearer {second_token}"})
        assert resp.status_code == 204
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Project membership
# ---------------------------------------------------------------------------

def test_project_admin_can_manage_members():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new7@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": new_id, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 201
    finally:
        app.dependency_overrides.clear()


def test_project_admin_cannot_manage_another_project():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new8@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member"))
        db.commit()
        db.close()
        # viewer-a is viewer on A1, not on A2; try to add to A2 -> should be 403 (requires project_admin on A2)
        resp = client.post(f"/api/v1/projects/{objs['proj_a2'].id}/members", json={"user_id": new_id, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['viewer-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_org_admin_can_manage_projects_in_org():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new9@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member"))
        db.commit()
        db.close()
        # org_admin of A can manage A2 even without explicit project membership
        resp = client.post(f"/api/v1/projects/{objs['proj_a2'].id}/members", json={"user_id": new_id, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 201
    finally:
        app.dependency_overrides.clear()


def test_cross_org_project_membership_denied():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # Try to add user from org B to project in org A -> should 403 because target user not in org A
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": objs["user_member_b"].id, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_duplicate_project_membership_rejected():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # viewer-a already member of A1
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": objs["user_viewer_a"].id, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 409
    finally:
        app.dependency_overrides.clear()


def test_invalid_project_role_rejected():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        new_id = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="new10@org-a.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": new_id, "role": "invalid_role"}, headers={"Authorization": f"Bearer {tokens['admin-a@org-a.test']}"})
        assert resp.status_code == 400
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Permission enforcement
# ---------------------------------------------------------------------------

def test_project_create_requires_org_admin():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "NewProj", "description": ""}, headers={"Authorization": f"Bearer {tokens['member-a@org-a.test']}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_ingestion_viewer_denied_analyst_allowed():
    _, TestingSession, _, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # viewer on A1 should be denied
        resp = client.post("/api/v1/ingestions/prepare", data={"project_id": objs["proj_a1"].id}, files={"file": ("test.zip", b"PK\x03\x04", "application/zip")}, headers={"Authorization": f"Bearer {tokens['viewer-a@org-a.test']}"})
        assert resp.status_code == 403
        # analyst should be allowed (will be 400 for empty archive, but not 403)
        resp2 = client.post("/api/v1/ingestions/prepare", data={"project_id": objs["proj_a1"].id}, files={"file": ("test2.zip", b"PK\x03\x04", "application/zip")}, headers={"Authorization": f"Bearer {tokens['analyst-a@org-a.test']}"})
        assert resp2.status_code != 403
    finally:
        app.dependency_overrides.clear()
