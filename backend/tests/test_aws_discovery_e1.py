"""E1 AWS live discovery tests — validation, STS identity, config, redaction,
API lifecycle, RBAC/IDOR isolation, audit, bounds. AWS SDK calls are faked;
no credentials or network required."""

import sys
import types
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import JSON as _JSON
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

import app.models.organization  # noqa
import app.models.user  # noqa
import app.models.organization_membership  # noqa
import app.models.project  # noqa
import app.models.project_membership  # noqa
import app.models.target  # noqa
import app.models.scan  # noqa
import app.models.audit_log  # noqa
import app.models.connector  # noqa
import app.models.cloud_discovery  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.connector import CloudConnection
from app.models.cloud_discovery import CloudDiscovery
from app.services.aws_connector import (
    AWSConnectorError,
    discover_regions,
    get_account_identity,
    sanitize_aws_error,
    validate_account_id,
    validate_external_id,
    validate_regions,
    validate_role_arn,
)


# --- Fake boto3 (injected via sys.modules; functions import lazily) ---

class FakeSTS:
    def __init__(self, identity=None, exc=None):
        self._identity = identity or {"Account": "123456789012",
                                      "Arn": "arn:aws:sts::123456789012:assumed-role/VAPT/x",
                                      "UserId": "AROAX"}
        self._exc = exc
        self.assume_calls = []

    def assume_role(self, **kwargs):
        self.assume_calls.append(kwargs)
        if isinstance(self._exc, Exception):
            raise self._exc
        return {"Credentials": {"AccessKeyId": "AKIAFAKE", "SecretAccessKey": "fake-secret",
                                "SessionToken": "fake-token"}}

    def get_caller_identity(self):
        return dict(self._identity)


class FakeEC2:
    def __init__(self, regions=None):
        self._regions = regions or ["us-east-1", "eu-west-1"]

    def describe_regions(self, **kwargs):
        return {"Regions": [{"RegionName": r} for r in self._regions]}


class FakeBoto3:
    sts = None
    ec2 = None

    def __init__(self, sts=None, ec2=None):
        self._sts = sts or FakeSTS()
        self._ec2 = ec2 or FakeEC2()

    def client(self, *args, **kwargs):
        # Mirrors real boto3.client(service_name, region_name, ...) calling convention.
        service = args[0] if args else kwargs.get("service_name")
        if service == "sts":
            return self._sts
        if service == "ec2":
            return self._ec2
        raise AssertionError(f"unexpected service {service}")


class FakeBotocoreConfig:
    def __init__(self, *args, **kwargs):
        pass


def _install_fake_boto3(fake):
    boto3_mod = types.ModuleType("boto3")
    boto3_mod.client = fake.client
    botocore_mod = types.ModuleType("botocore")
    config_mod = types.ModuleType("botocore.config")
    config_mod.Config = FakeBotocoreConfig
    botocore_mod.config = config_mod
    sys.modules["boto3"] = boto3_mod
    sys.modules["botocore"] = botocore_mod
    sys.modules["botocore.config"] = config_mod


def _remove_fake_boto3():
    for mod in ("boto3", "botocore", "botocore.config"):
        sys.modules.pop(mod, None)


# --- Fixture ---

def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for _tbl in list(Base.metadata.tables.values()):
        for _col in _tbl.columns:
            if _col.type.__class__.__name__ == "JSONB":
                _col.type = _JSON()
    import app.models.connector as _conn
    import app.models.cloud_discovery as _cd
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__,
        AuditLog.__table__, _conn.CloudConnection.__table__, _cd.CloudDiscovery.__table__,
        _conn.ConnectorSecret.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT,
                status TEXT, metadata TEXT, created_at DATETIME, updated_at DATETIME,
                criticality TEXT, owner_user_id TEXT, first_seen_at DATETIME,
                last_seen_at DATETIME, first_seen_scan_id TEXT, last_seen_scan_id TEXT
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-e1", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-e1", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@e1.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@e1.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@e1.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@e1.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer", status="active"))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b}
    return engine, Session, tokens, objs


def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)


def _auth(tokens, email):
    return {"Authorization": f"Bearer {tokens[email]}"}


ROLE = "arn:aws:iam::123456789012:role/VAPT-Discovery"


def _create_role_conn(client, tokens, objs, **kw):
    body = {"provider": "aws", "account_id": "123456789012", "name": "prod",
            "role_arn": ROLE, "external_id": "ext-123"}
    body.update(kw)
    return client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections",
                       json=body, headers=_auth(tokens, "admin-a@e1.test"))


# --- A/B/C: validation + identity ---

def test_e1_config_validation():
    assert validate_account_id("123456789012") == "123456789012"
    assert validate_role_arn(ROLE, "123456789012") == ROLE
    assert validate_external_id("ext-123") == "ext-123"
    assert validate_external_id(None) is None
    assert validate_regions(["us-east-1", "EU-WEST-1"]) == ["us-east-1", "eu-west-1"]
    assert validate_regions(None) is None
    for bad_account in ("123", "abcdefghijkl", "", None, "12345678901a"):
        try:
            validate_account_id(bad_account)
            raise AssertionError(f"accepted {bad_account}")
        except AWSConnectorError:
            pass
    for bad_arn in ("not-an-arn", "arn:aws:iam::123:role/x", "", None, "arn:aws:s3:::bucket"):
        try:
            validate_role_arn(bad_arn)
            raise AssertionError(f"accepted {bad_arn}")
        except AWSConnectorError:
            pass
    try:
        validate_role_arn("arn:aws:iam::999988887777:role/x", "123456789012")
        raise AssertionError("accepted mismatched account")
    except AWSConnectorError:
        pass
    try:
        validate_external_id("x" * 300)
        raise AssertionError("accepted long external id")
    except AWSConnectorError:
        pass
    try:
        validate_regions(["not-a-region"])
        raise AssertionError("accepted bad region")
    except AWSConnectorError:
        pass


def test_e1_sts_identity_parsing():
    _install_fake_boto3(FakeBoto3())
    try:
        identity = get_account_identity(ROLE, "ext-123", "123456789012")
        assert identity["account_id"] == "123456789012"
        assert identity["arn"].startswith("arn:aws:sts::")
    finally:
        _remove_fake_boto3()


def test_e1_sts_account_mismatch_rejected():
    _install_fake_boto3(FakeBoto3(sts=FakeSTS(identity={"Account": "999988887777", "Arn": "x", "UserId": "u"})))
    try:
        try:
            get_account_identity(ROLE, None, "123456789012")
            raise AssertionError("accepted mismatched account")
        except AWSConnectorError as exc:
            assert "match" in str(exc).lower()
    finally:
        _remove_fake_boto3()


def test_e1_region_discovery_from_api():
    _install_fake_boto3(FakeBoto3())
    try:
        assert discover_regions(ROLE, None) == ["us-east-1", "eu-west-1"]
    finally:
        _remove_fake_boto3()


# --- D: redaction ---

def test_e1_error_redaction():
    assert sanitize_aws_error(Exception("failed: SecretAccessKey=AKIAIOSFODNN7EXAMPLE")) == "AWS operation failed"
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitize_aws_error(Exception("SecretAccessKey=AKIAIOSFODNN7EXAMPLE"))
    short = sanitize_aws_error(Exception("AccessDenied for operation"))
    assert "AccessDenied" in short and len(short) <= 300


# --- API: create/patch/validate/discover/runs ---

def test_e1_create_role_connection():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _create_role_conn(client, tokens, objs)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["role_arn"] == ROLE and body["account_id"] == "123456789012"
        assert "external_id" not in str(body).lower().replace("has_external_id", "")
        # duplicate
        assert _create_role_conn(client, tokens, objs).status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_create_invalid_config_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert _create_role_conn(client, tokens, objs, account_id="123").status_code == 400
        assert _create_role_conn(client, tokens, objs, role_arn="bogus").status_code == 400
        assert _create_role_conn(client, tokens, objs, role_arn="arn:aws:iam::999988887777:role/x").status_code == 400
        assert _create_role_conn(client, tokens, objs, external_id="x" * 300).status_code == 400
        assert _create_role_conn(client, tokens, objs, regions=["nope"]).status_code == 400
        assert _create_role_conn(client, tokens, objs, provider="gcp").status_code in (400, 201)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_validate_live_identity():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        cid = _create_role_conn(client, tokens, objs).json()["id"]
        _install_fake_boto3(FakeBoto3())
        try:
            r = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}/validate",
                            headers=_auth(tokens, "admin-a@e1.test"))
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["valid"] is True and body["account_id"] == "123456789012"
            assert "principal_arn" in body
            assert "secret" not in str(body).lower() and "sessiontoken" not in str(body).lower()
        finally:
            _remove_fake_boto3()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_validate_failure_sanitized():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        cid = _create_role_conn(client, tokens, objs).json()["id"]

        class DeniedSTS(FakeSTS):
            def assume_role(self, **kwargs):
                err = Exception("AccessDenied")
                err.response = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
                raise err

        _install_fake_boto3(FakeBoto3(sts=DeniedSTS()))
        try:
            r = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}/validate",
                            headers=_auth(tokens, "admin-a@e1.test"))
            assert r.status_code == 400
            assert "permission denied" in r.text.lower()
        finally:
            _remove_fake_boto3()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_patch_connection():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "admin-a@e1.test")
    try:
        cid = _create_role_conn(client, tokens, objs).json()["id"]
        r = client.patch(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}",
                         json={"name": "prod-renamed", "status": "inactive"}, headers=H)
        assert r.status_code == 200 and r.json()["name"] == "prod-renamed"
        assert r.json()["status"] == "inactive"
        assert client.patch(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}",
                            json={"status": "bogus"}, headers=H).status_code == 400
        # disabled connection cannot discover
        assert client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}/discover", headers=H).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_discover_enqueues_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        cid = _create_role_conn(client, tokens, objs).json()["id"]
        with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
            r = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}/discover",
                            headers=_auth(tokens, "analyst-a@e1.test"))
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "queued" and body["discovery_id"]
            assert m.call_count == 1
            args, _ = m.call_args
            assert args[0] == "app.tasks.cloud_discovery.discover_cloud"
        # duplicate while queued
        with patch("app.core.celery.celery_app.send_task", return_value=None):
            r2 = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}/discover",
                             headers=_auth(tokens, "analyst-a@e1.test"))
            assert r2.status_code == 409
        # run visible, bounded
        runs = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/cloud-discoveries",
                          headers=_auth(tokens, "analyst-a@e1.test")).json()
        assert runs["count"] == 1
        one = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/cloud-discoveries/{body['discovery_id']}",
                         headers=_auth(tokens, "analyst-a@e1.test")).json()
        assert one["status"] == "queued" and one["connection_id"] == cid
    finally:
        fastapi_app.dependency_overrides.clear()


# --- M/N/O: isolation + RBAC ---

def test_e1_viewer_cannot_manage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        H = _auth(tokens, "viewer-a@e1.test")
        assert client.post(f"/api/v1/projects/{pid}/cloud/connections", json={"provider": "aws", "account_id": "123456789012", "role_arn": ROLE}, headers=H).status_code == 403
        cid = _create_role_conn(client, tokens, objs).json()["id"]
        assert client.post(f"/api/v1/projects/{pid}/cloud/connections/{cid}/validate", headers=H).status_code == 403
        assert client.post(f"/api/v1/projects/{pid}/cloud/connections/{cid}/discover", headers=H).status_code == 403
        assert client.patch(f"/api/v1/projects/{pid}/cloud/connections/{cid}", json={"name": "x"}, headers=H).status_code == 403
        # viewer reads fine
        assert client.get(f"/api/v1/projects/{pid}/cloud/connections", headers=H).status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_cross_project_tenant_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        cid = _create_role_conn(client, tokens, objs).json()["id"]
        # other tenant cannot read
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections", headers=_auth(tokens, "admin-b@e1.test")).status_code == 404
        # cross-project connection id
        assert client.get(f"/api/v1/projects/{objs['proj_b1'].id}/cloud/connections/{cid}", headers=_auth(tokens, "admin-b@e1.test")).status_code == 404
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/cloud-discoveries", headers=_auth(tokens, "admin-b@e1.test")).status_code == 404
        assert client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections", json={"provider": "aws", "account_id": "1", "role_arn": ROLE}, headers=_auth(tokens, "admin-a@e1.test")).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_auth_required():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        assert client.get(f"/api/v1/projects/{pid}/cloud/connections").status_code in (401, 403)
        assert client.get(f"/api/v1/projects/{pid}/cloud/cloud-discoveries").status_code in (401, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


# --- P/Q/R: audit, bounds, leakage ---

def test_e1_audit_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        cid = _create_role_conn(client, tokens, objs).json()["id"]
        with patch("app.core.celery.celery_app.send_task", return_value=None):
            client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/connections/{cid}/discover",
                        headers=_auth(tokens, "admin-a@e1.test"))
        s = Session()
        try:
            rows = s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).all()
            types = {r.event_type for r in rows}
            assert "CLOUD_CONNECTION_CREATED" in types
            assert "CLOUD_DISCOVERY_QUEUED" in types
            import json as _json
            for r in rows:
                blob = _json.dumps(getattr(r, "extra_data", None) or {})
                assert "AKIA" not in blob and "SessionToken" not in blob and "secret" not in blob.lower()
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_cloud_assets_api_returns_metadata():
    # Regression: cloud asset serialization must use the mapped metadata
    # attribute (SQLAlchemy MetaData leaked into responses -> RecursionError).
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        s = Session()
        try:
            s.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata) VALUES (:id, :proj, 'cloud_resource', :val, 'active', :meta)"),
                      {"id": str(uuid.uuid4()), "proj": objs["proj_a1"].id,
                       "val": "cloud_resource:aws:123456789012:us-east-1:ec2:aws_ec2_instance:i-1",
                       "meta": '{"provider": "aws"}'})
            s.commit()
        finally:
            s.close()
        r = client.get(f"/api/v1/cloud/assets?project_id={objs['proj_a1'].id}",
                       headers=_auth(tokens, "analyst-a@e1.test"))
        assert r.status_code == 200, r.text
        items = r.json()["assets"]
        assert len(items) == 1
        assert items[0]["metadata"] == {"provider": "aws"}
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e1_response_bounds():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _create_role_conn(client, tokens, objs, name="n" * 500, regions=["us-east-1"] * 40)
        assert r.status_code == 201
        assert len(r.json()["name"]) <= 255
        q = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/cloud-discoveries?limit=500",
                       headers=_auth(tokens, "analyst-a@e1.test")).json()
        assert q["count"] <= 200
    finally:
        fastapi_app.dependency_overrides.clear()
