"""RepositoryProvider abstraction — GitHub, GitLab, Bitbucket, Azure DevOps."""
from __future__ import annotations

import hashlib
import hmac
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

PROVIDERS: dict[str, RepositoryProvider] = {
    "github": GitHubProvider(),
    "gitlab": GitLabProvider(),
    "bitbucket": BitbucketProvider(),
    "azure_devops": AzureDevOpsProvider(),
}

def get_provider(provider_id: str) -> Optional[RepositoryProvider]:
    return PROVIDERS.get(provider_id.strip().lower())

def list_providers() -> List[str]:
    return sorted(PROVIDERS.keys())
