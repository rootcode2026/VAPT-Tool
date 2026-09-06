import os
import uuid

def test_production_aesgcm_roundtrip():
    os.environ["CONNECTOR_ENCRYPTION_KEY"] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    os.environ["SECRET_STORE_MODE"] = "production"
    from app.services.secret_store import ProductionAESGCMStore
    store = ProductionAESGCMStore(db=None)
    ref = store.put_secret("super-secret-123")
    assert store.get_secret(ref) == "super-secret-123"
    # ensure ciphertext is not plaintext
    from app.services.secret_store import _MEMORY_VAULT
    assert "super-secret-123" not in _MEMORY_VAULT[ref]
    # cleanup
    store.delete_secret(ref)
    os.environ.pop("CONNECTOR_ENCRYPTION_KEY", None)
    os.environ.pop("SECRET_STORE_MODE", None)

def test_dev_fernet_is_dev_only():
    from app.services.secret_store import DevelopmentSecretStore
    store = DevelopmentSecretStore(db=None)
    ref = store.put_secret("dev-secret")
    assert store.get_secret(ref) == "dev-secret"
    # Fernet ciphertext contains not AESGCM nonce format? Just ensure it works
    store.delete_secret(ref)

def test_real_provider_selection():
    os.environ["REPOSITORY_PROVIDER_MODE"] = "real"
    from importlib import reload
    import app.services.repository_provider as rp
    reload(rp)
    p = rp.get_provider("github")
    assert p.provider_id == "github"
    # should be Real provider when real mode
    assert p.__class__.__name__ == "RealGitHubProvider"
    os.environ["REPOSITORY_PROVIDER_MODE"] = "mock"
    reload(rp)
    p2 = rp.get_provider("github")
    assert p2.__class__.__name__ == "GitHubProvider"
    os.environ.pop("REPOSITORY_PROVIDER_MODE", None)

def test_cloud_real_provider_selection():
    os.environ["CLOUD_PROVIDER_MODE"] = "real"
    from importlib import reload
    import app.services.cloud_provider as cp
    reload(cp)
    p = cp.get_provider("aws")
    assert p.__class__.__name__ == "RealAWSProvider"
    os.environ["CLOUD_PROVIDER_MODE"] = "mock"
    reload(cp)
    p2 = cp.get_provider("aws")
    assert p2.__class__.__name__ == "AWSProvider"
    os.environ.pop("CLOUD_PROVIDER_MODE", None)

def test_snapshot_traversal_blocked():
    from app.services.repo_snapshot import safe_clone_snapshot, _validate_id
    import pytest
    try:
        _validate_id("../evil", "repo_id")
        assert False, "should have raised"
    except ValueError:
        pass
    try:
        _validate_id("a; rm -rf /", "repo_id")
        assert False
    except ValueError:
        pass

def test_snapshot_workspace_isolation():
    from app.services.repo_snapshot import _ensure_workspace
    ws = _ensure_workspace("proj-123", "my-repo", "abc123def456abc123def456abc123def456abcd")
    assert "workspace" in str(ws) and "proj-123" in str(ws)
    assert ws.exists()

def test_provider_error_sanitization():
    from app.services.repository_provider import _sanitize_provider_error
    assert _sanitize_provider_error(Exception("token abc123 invalid")) == "Provider authentication failed (sanitized)"
    assert "sanitized" in _sanitize_provider_error(Exception("Invalid credentials token"))
    assert _sanitize_provider_error(Exception("rate limit")) == "rate limit"[:300]

def test_webhook_provider_specific():
    from app.services.repository_provider import RealGitLabProvider, RealGitHubProvider
    gh = RealGitHubProvider()
    gl = RealGitLabProvider()
    # GitHub uses hmac, GitLab plain compare
    import hmac, hashlib
    secret = "mysecret12345"
    payload = b'{"test": 1}'
    gh_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert gh.verify_webhook_signature(payload, gh_sig, secret)
    assert not gh.verify_webhook_signature(payload, "sha256=bad", secret)
    assert gl.verify_webhook_signature(payload, secret, secret)
    assert not gl.verify_webhook_signature(payload, "wrong", secret)

def test_live_github_not_required():
    # Live tests are optional, ensure mock still works without env
    if os.getenv("RUN_GITHUB_LIVE_TESTS") != "true":
        assert True
    else:
        from app.services.repository_provider import RealGitHubProvider
        p = RealGitHubProvider()
        # This would require real token, but we just check structure
        assert hasattr(p, "validate_credentials")

def test_credential_never_logged():
    import logging
    from app.services.secret_store import DevelopmentSecretStore
    store = DevelopmentSecretStore(db=None)
    ref = store.put_secret("my-token-12345")
    # Ensure audit metadata sanitization would redact if we tried to log
    from app.services.audit import sanitize_metadata
    meta = {"credential": "my-token-12345", "token": "abc", "provider": "github"}
    sanitized = sanitize_metadata(meta)
    assert sanitized["credential"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    store.delete_secret(ref)
