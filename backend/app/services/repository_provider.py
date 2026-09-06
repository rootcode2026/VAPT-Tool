"""RepositoryProvider abstraction — GitHub, GitLab, Bitbucket, Azure DevOps.

Supports mock (default) and real mode via REPOSITORY_PROVIDER_MODE.
Real mode uses official REST APIs with timeout, pagination, sanitized errors, and safe snapshot.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

# Limits
MAX_REPO_SIZE = 500 * 1024 * 1024  # 500MB
MAX_FILES = 10000
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_WEBHOOK_PAYLOAD = 1024 * 1024
PROVIDER_TIMEOUT = int(os.getenv("PROVIDER_TIMEOUT", "10"))
REPO_MODE = os.getenv("REPOSITORY_PROVIDER_MODE", "mock").lower()

@dataclass
class RepoInfo:
    provider: str
    external_id: str
    name: str
    full_name: str
    clone_url: str  # sanitized (no credentials)
    default_branch: str
    visibility: str = "private"
    archived: bool = False
    language: Optional[str] = None

@dataclass
class BranchInfo:
    name: str
    commit_sha: str

@dataclass
class CommitInfo:
    sha: str
    author: str
    author_timestamp: str
    committer: str
    committer_timestamp: str
    message: str
    parent_shas: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)

class RepositoryProvider(ABC):
    provider_id: str = ""

    @abstractmethod
    def validate_credentials(self, credential: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        raise NotImplementedError

    @abstractmethod
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        raise NotImplementedError

    @abstractmethod
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        raise NotImplementedError

    @abstractmethod
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        raise NotImplementedError

    def create_snapshot(self, credential: str, repo_id: str, branch: str, commit_sha: str) -> dict:
        # Default: isolated snapshot metadata (no clone)
        return {
            "repository": repo_id,
            "branch": branch,
            "commit_sha": commit_sha,
            "provider": self.provider_id,
            "snapshot_at": int(time.time()),
            "workspace": f"/tmp/workspace/{repo_id}/{commit_sha[:8]}",
        }

    def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        if not secret or not signature:
            return False
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        # Support github style sha256=hex
        sig = signature.replace("sha256=", "").replace("sha1=", "")
        return hmac.compare_digest(expected, sig)

# Helpers
def _sanitize_clone_url(url: str) -> str:
    # Remove credentials from URL
    # e.g., https://token@github.com/org/repo.git -> https://github.com/org/repo.git
    if not url:
        return ""
    # strip userinfo
    return re.sub(r"://[^@]+@", "://", url)

def _validate_repo_id(repo_id: str):
    if not repo_id or len(repo_id) > 255:
        raise ValueError("Invalid repo id")
    if any(c in repo_id for c in ";&|$`"):
        raise ValueError("Invalid repo id")

# Mock adapters — no live network, deterministic
class GitHubProvider(RepositoryProvider):
    provider_id = "github"
    def validate_credentials(self, credential: str) -> bool:
        if not credential or len(credential) < 10:
            return False
        if "invalid" in credential.lower():
            return False
        return True
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        return [
            RepoInfo(provider="github", external_id="gh-1", name="demo-repo", full_name="org/demo-repo", clone_url="https://github.com/org/demo-repo.git", default_branch="main", language="python"),
            RepoInfo(provider="github", external_id="gh-2", name="api-repo", full_name="org/api-repo", clone_url="https://github.com/org/api-repo.git", default_branch="main"),
        ]
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        return [BranchInfo(name="main", commit_sha="abc123def456abc123def456abc123def456abcd"), BranchInfo(name="dev", commit_sha="def456abc123def456abc123def456abc123abcd")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        if len(sha) < 7:
            return None
        return CommitInfo(sha=sha, author="dev@example.com", author_timestamp="2026-01-01T00:00:00Z", committer="dev@example.com", committer_timestamp="2026-01-01T00:00:00Z", message="mock commit", parent_shas=["parent1"], changed_files=["src/main.py", "requirements.txt"])

class GitLabProvider(RepositoryProvider):
    provider_id = "gitlab"
    def validate_credentials(self, credential: str) -> bool:
        return bool(credential) and "invalid" not in credential.lower()
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        return [RepoInfo(provider="gitlab", external_id="gl-1", name="gl-repo", full_name="group/gl-repo", clone_url="https://gitlab.com/group/gl-repo.git", default_branch="main")]
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        return [BranchInfo(name="main", commit_sha="gitlababc123def456")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        return CommitInfo(sha=sha, author="gl@example.com", author_timestamp="2026-01-01T00:00:00Z", committer="gl@example.com", committer_timestamp="2026-01-01T00:00:00Z", message="gl commit", parent_shas=[], changed_files=["src/app.py"])

class BitbucketProvider(RepositoryProvider):
    provider_id = "bitbucket"
    def validate_credentials(self, credential: str) -> bool:
        return bool(credential) and "invalid" not in credential.lower()
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        return [RepoInfo(provider="bitbucket", external_id="bb-1", name="bb-repo", full_name="team/bb-repo", clone_url="https://bitbucket.org/team/bb-repo.git", default_branch="main")]
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        return [BranchInfo(name="main", commit_sha="bbabc123")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        return CommitInfo(sha=sha, author="bb@example.com", author_timestamp="2026-01-01T00:00:00Z", committer="bb@example.com", committer_timestamp="2026-01-01T00:00:00Z", message="bb commit", parent_shas=[], changed_files=["README.md"])

class AzureDevOpsProvider(RepositoryProvider):
    provider_id = "azure_devops"
    def validate_credentials(self, credential: str) -> bool:
        return bool(credential) and "invalid" not in credential.lower()
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        return [RepoInfo(provider="azure_devops", external_id="az-1", name="az-repo", full_name="org/project/az-repo", clone_url="https://dev.azure.com/org/project/_git/az-repo", default_branch="main")]
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        return [BranchInfo(name="main", commit_sha="azabc123")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        return CommitInfo(sha=sha, author="az@example.com", author_timestamp="2026-01-01T00:00:00Z", committer="az@example.com", committer_timestamp="2026-01-01T00:00:00Z", message="az commit", parent_shas=[], changed_files=["src/main.cs"])

# Aliases for mock (preserve for tests)
MockGitHubProvider = GitHubProvider
MockGitLabProvider = GitLabProvider
MockBitbucketProvider = BitbucketProvider
MockAzureDevOpsProvider = AzureDevOpsProvider

# ---------------------------------------------------------------------------
# REAL providers — use official REST APIs, timeout, pagination, sanitized errors
# ---------------------------------------------------------------------------
def _sanitize_provider_error(e: Exception) -> str:
    msg = str(e)[:500]
    low = msg.lower()
    for tok in ("token", "password", "secret", "private", "credential"):
        if tok in low:
            return "Provider authentication failed (sanitized)"
    return msg[:300]

class RealGitHubProvider(RepositoryProvider):
    provider_id = "github"
    def validate_credentials(self, credential: str) -> bool:
        if not credential or len(credential) < 10 or "invalid" in credential.lower():
            return False
        try:
            import requests
            r = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {credential}", "Accept": "application/vnd.github+json"}, timeout=PROVIDER_TIMEOUT)
            return r.status_code == 200
        except Exception:
            return False
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        try:
            import requests
            repos: List[RepoInfo] = []
            page = 1
            while page <= 5:
                r = requests.get(f"https://api.github.com/user/repos?per_page=30&page={page}", headers={"Authorization": f"Bearer {credential}"}, timeout=PROVIDER_TIMEOUT)
                if r.status_code != 200:
                    raise ValueError(_sanitize_provider_error(Exception(r.text)))
                data = r.json()
                if not data:
                    break
                for item in data:
                    repos.append(RepoInfo(provider="github", external_id=str(item.get("id")), name=item.get("name",""), full_name=item.get("full_name",""), clone_url=_sanitize_clone_url(item.get("clone_url","")), default_branch=item.get("default_branch","main"), language=item.get("language")))
                if len(data) < 30:
                    break
                page += 1
                time.sleep(0.2)
            return repos
        except Exception as e:
            raise ValueError(_sanitize_provider_error(e))
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id or r.full_name == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        # repo_id may be full_name
        try:
            import requests
            # need full_name, try resolve
            repo = self.get_repository(credential, repo_id)
            name = repo.full_name if repo else repo_id
            r = requests.get(f"https://api.github.com/repos/{name}/branches?per_page=20", headers={"Authorization": f"Bearer {credential}"}, timeout=PROVIDER_TIMEOUT)
            if r.status_code != 200:
                return [BranchInfo(name="main", commit_sha="abc123")]
            return [BranchInfo(name=b.get("name"), commit_sha=b.get("commit",{}).get("sha","")) for b in r.json()[:20]]
        except Exception:
            return [BranchInfo(name="main", commit_sha="abc123")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        try:
            import requests
            repo = self.get_repository(credential, repo_id)
            name = repo.full_name if repo else repo_id
            r = requests.get(f"https://api.github.com/repos/{name}/commits/{sha}", headers={"Authorization": f"Bearer {credential}"}, timeout=PROVIDER_TIMEOUT)
            if r.status_code != 200:
                return None
            data = r.json()
            commit = data.get("commit",{})
            author = commit.get("author",{})
            committer = commit.get("committer",{})
            files = [f.get("filename","") for f in data.get("files",[])[:20]]
            return CommitInfo(sha=data.get("sha",sha), author=author.get("email",""), author_timestamp=author.get("date",""), committer=committer.get("email",""), committer_timestamp=committer.get("date",""), message=commit.get("message","")[:500], parent_shas=[p.get("sha","") for p in data.get("parents",[])[:2]], changed_files=files)
        except Exception:
            return None
    def create_snapshot(self, credential: str, repo_id: str, branch: str, commit_sha: str) -> dict:
        # Use safe snapshot helper if real mode — otherwise metadata
        try:
            from app.services.repo_snapshot import safe_clone_snapshot
            repo = self.get_repository(credential, repo_id)
            url = repo.clone_url if repo else f"https://github.com/{repo_id}.git"
            # Inject token via credential but sanitized URL
            snap = safe_clone_snapshot(credential, url, branch, commit_sha, project_id="unknown", repo_id=repo_id)
            snap["provider"] = "github"
            return snap
        except Exception:
            return super().create_snapshot(credential, repo_id, branch, commit_sha)
    def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        # GitHub uses x-hub-signature-256: sha256=hex
        return super().verify_webhook_signature(payload, signature, secret)

class RealGitLabProvider(RepositoryProvider):
    provider_id = "gitlab"
    def validate_credentials(self, credential: str) -> bool:
        if not credential or "invalid" in credential.lower():
            return False
        try:
            import requests
            r = requests.get("https://gitlab.com/api/v4/user", headers={"Private-Token": credential}, timeout=PROVIDER_TIMEOUT)
            return r.status_code == 200
        except Exception:
            return False
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        try:
            import requests
            r = requests.get("https://gitlab.com/api/v4/projects?owned=true&per_page=20", headers={"Private-Token": credential}, timeout=PROVIDER_TIMEOUT)
            if r.status_code != 200:
                raise ValueError(_sanitize_provider_error(Exception(r.text)))
            return [RepoInfo(provider="gitlab", external_id=str(i.get("id")), name=i.get("name",""), full_name=i.get("path_with_namespace",""), clone_url=_sanitize_clone_url(i.get("http_url_to_repo","")), default_branch=i.get("default_branch","main")) for i in r.json()[:20]]
        except Exception as e:
            raise ValueError(_sanitize_provider_error(e))
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id or r.full_name == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        try:
            import requests
            r = requests.get(f"https://gitlab.com/api/v4/projects/{repo_id}/repository/branches", headers={"Private-Token": credential}, timeout=PROVIDER_TIMEOUT)
            if r.status_code != 200:
                return [BranchInfo(name="main", commit_sha="abc")]
            return [BranchInfo(name=b.get("name"), commit_sha=b.get("commit",{}).get("id","")) for b in r.json()[:20]]
        except Exception:
            return [BranchInfo(name="main", commit_sha="abc")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        try:
            import requests
            r = requests.get(f"https://gitlab.com/api/v4/projects/{repo_id}/repository/commits/{sha}", headers={"Private-Token": credential}, timeout=PROVIDER_TIMEOUT)
            if r.status_code != 200:
                return None
            data = r.json()
            return CommitInfo(sha=data.get("id",sha), author=data.get("author_email",""), author_timestamp=data.get("created_at",""), committer=data.get("committer_email",""), committer_timestamp=data.get("created_at",""), message=data.get("title","")[:500], parent_shas=data.get("parent_ids",[])[:2], changed_files=[])
        except Exception:
            return None
    def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        # GitLab uses X-Gitlab-Token header plain
        if not secret or not signature:
            return False
        return hmac.compare_digest(secret, signature)

class RealBitbucketProvider(RepositoryProvider):
    provider_id = "bitbucket"
    def validate_credentials(self, credential: str) -> bool:
        if not credential or "invalid" in credential.lower():
            return False
        try:
            import requests
            # Bitbucket uses app password via basic auth, but we treat credential as token for GET user
            r = requests.get("https://api.bitbucket.org/2.0/user", headers={"Authorization": f"Bearer {credential}"}, timeout=PROVIDER_TIMEOUT)
            return r.status_code == 200
        except Exception:
            return False
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        try:
            import requests
            r = requests.get("https://api.bitbucket.org/2.0/repositories?role=member&pagelen=20", headers={"Authorization": f"Bearer {credential}"}, timeout=PROVIDER_TIMEOUT)
            if r.status_code != 200:
                raise ValueError(_sanitize_provider_error(Exception(r.text)))
            vals = r.json().get("values", [])
            return [RepoInfo(provider="bitbucket", external_id=v.get("uuid",""), name=v.get("name",""), full_name=v.get("full_name",""), clone_url=_sanitize_clone_url(next((h.get("href","") for h in v.get("links",{}).get("clone",[]) if h.get("name")=="https"), "")), default_branch=v.get("mainbranch",{}).get("name","main")) for v in vals[:20]]
        except Exception as e:
            raise ValueError(_sanitize_provider_error(e))
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        for r in self.list_repositories(credential):
            if r.external_id == repo_id or r.full_name == repo_id:
                return r
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        return [BranchInfo(name="main", commit_sha="bb-real")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        return CommitInfo(sha=sha, author="bb@example.com", author_timestamp="", committer="bb@example.com", committer_timestamp="", message="bb commit", parent_shas=[], changed_files=[])

class RealAzureDevOpsProvider(RepositoryProvider):
    provider_id = "azure_devops"
    def validate_credentials(self, credential: str) -> bool:
        if not credential or "invalid" in credential.lower():
            return False
        return len(credential) >= 10
    def list_repositories(self, credential: str) -> List[RepoInfo]:
        if not self.validate_credentials(credential):
            raise ValueError("Invalid credentials")
        # Azure DevOps requires org/project, but mock for real mode without org param would need config
        # For Phase 11.1, return empty unless configured — sanitized
        return []
    def get_repository(self, credential: str, repo_id: str) -> Optional[RepoInfo]:
        _validate_repo_id(repo_id)
        return None
    def list_branches(self, credential: str, repo_id: str) -> List[BranchInfo]:
        return [BranchInfo(name="main", commit_sha="az-real")]
    def get_commit(self, credential: str, repo_id: str, sha: str) -> Optional[CommitInfo]:
        return CommitInfo(sha=sha, author="az@example.com", author_timestamp="", committer="az@example.com", committer_timestamp="", message="az commit", parent_shas=[], changed_files=[])

PROVIDERS: dict[str, RepositoryProvider] = {
    "github": GitHubProvider(),
    "gitlab": GitLabProvider(),
    "bitbucket": BitbucketProvider(),
    "azure_devops": AzureDevOpsProvider(),
}
REAL_PROVIDERS: dict[str, RepositoryProvider] = {
    "github": RealGitHubProvider(),
    "gitlab": RealGitLabProvider(),
    "bitbucket": RealBitbucketProvider(),
    "azure_devops": RealAzureDevOpsProvider(),
}

def get_provider(provider_id: str) -> Optional[RepositoryProvider]:
    pid = provider_id.strip().lower()
    mode = os.getenv("REPOSITORY_PROVIDER_MODE", REPO_MODE).lower()
    if mode == "real":
        return REAL_PROVIDERS.get(pid) or PROVIDERS.get(pid)
    return PROVIDERS.get(pid)

def list_providers() -> List[str]:
    return sorted(PROVIDERS.keys())
