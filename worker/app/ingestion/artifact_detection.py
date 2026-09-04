"""Lightweight deterministic artifact detection for ingestion."""

from pathlib import Path

# Language extensions
LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cc": "C++",
    ".hh": "C++",
    ".cs": "C#",
    ".rb": "Ruby",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".m": "Objective-C",
}

# Dependency manifests (exact filename match, case-sensitive where appropriate)
DEPENDENCY_MANIFESTS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "pnpm-lock.yml": "pnpm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "composer.json": "composer",
    "composer.lock": "composer",
}

# Secrets/config candidates
SECRETS_CANDIDATES = {
    ".env": "env",
    ".env.example": "env",
    ".env.local": "env",
    ".env.development": "env",
    ".env.production": "env",
    ".env.test": "env",
}

# IaC indicators
IAC_EXTENSIONS = {".tf", ".yaml", ".yml", ".json"}
IAC_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "docker-compose.json"}
# CloudFormation often has template.yaml with Resources

# API specs
API_SPEC_NAMES = {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml", "api.json", "api.yaml", "api.yml"}

# Repo metadata
REPO_METADATA = {".git", ".github", ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile", ".circleci"}


def detect_artifacts(workspace: Path) -> dict:
    """Walk workspace and detect artifact categories deterministically.

    Returns:
        {
            "languages": {language: count},
            "dependency_manifests": {filename: count},
            "secrets_candidates": {filename: count},
            "iac_files": {filepath: type},
            "api_specs": {filepath: type},
            "repo_metadata": {name: count},
            "total_files": int,
            "source_files": int,
            "config_files": int,
        }
    """
    languages: dict[str, int] = {}
    dependency_manifests: dict[str, int] = {}
    secrets_candidates: dict[str, int] = {}
    iac_files: dict[str, int] = {}
    api_specs: dict[str, int] = {}
    repo_metadata: dict[str, int] = {}
    total_files = 0
    source_files = 0
    config_files = 0

    ignored_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".cache", "vendor", ".tox"}

    for p in workspace.rglob("*"):
        if not p.is_file():
            continue
        # Skip ignored dirs
        if any(part in ignored_dirs for part in p.parts):
            # But still count .git as repo metadata if it's .git itself
            if p.name == ".git" or ".git" in p.parts:
                pass
            else:
                # Check if file is inside ignored but is manifest? Still skip for language but count manifests?
                # For determinism, skip ignored dirs entirely except for repo metadata
                continue
        # Skip symlinks that are not regular files? We already filtered is_file, but symlink to file is_file true
        # For artifact detection, we count the symlink target if it resolves inside workspace
        try:
            p.resolve().relative_to(workspace.resolve())
        except ValueError:
            continue

        total_files += 1
        name = p.name
        suffix = p.suffix.lower()
        rel = str(p.relative_to(workspace))

        # Language detection by extension
        lang = LANGUAGE_MAP.get(suffix)
        if lang:
            languages[lang] = languages.get(lang, 0) + 1
            source_files += 1
        elif suffix in (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"):
            config_files += 1

        # Dependency manifests (exact filename)
        if name in DEPENDENCY_MANIFESTS:
            dependency_manifests[name] = dependency_manifests.get(name, 0) + 1
        # Also check for pnpm-lock.yaml variant already covered
        if name.lower() in ("pnpm-lock.yaml", "pnpm-lock.yml"):
            dependency_manifests[name] = dependency_manifests.get(name, 0) + 1

        # Secrets/config candidates
        if name in SECRETS_CANDIDATES or name.startswith(".env"):
            secrets_candidates[name] = secrets_candidates.get(name, 0) + 1
        elif "config" in name.lower() or "credential" in name.lower() or "secret" in name.lower():
            # Avoid over-matching: only if file is likely config
            if suffix in (".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".txt", ".cfg"):
                secrets_candidates[name] = secrets_candidates.get(name, 0) + 1
        # Private key-like
        if name.lower() in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "private.key", "server.key") or name.endswith(".pem") or name.endswith(".key"):
            secrets_candidates[name] = secrets_candidates.get(name, 0) + 1

        # IaC detection
        if suffix == ".tf":
            iac_files[rel] = iac_files.get(rel, 0) + 1
        elif name in IAC_FILENAMES:
            iac_files[rel] = iac_files.get(rel, 0) + 1
        elif suffix in (".yaml", ".yml") and "k8s" in name.lower() or "kubernetes" in name.lower():
            iac_files[rel] = iac_files.get(rel, 0) + 1
        elif suffix in (".yaml", ".yml", ".json"):
            # Heuristic: check content for IaC markers? Lightweight: check filename contains template
            if "template" in name.lower() and "cloudformation" in rel.lower():
                iac_files[rel] = iac_files.get(rel, 0) + 1
            # Dockerfile is already handled

        # API specs
        if name.lower() in API_SPEC_NAMES:
            api_specs[rel] = api_specs.get(rel, 0) + 1
        elif suffix in (".json", ".yaml", ".yml") and ("openapi" in name.lower() or "swagger" in name.lower()):
            api_specs[rel] = api_specs.get(rel, 0) + 1
        else:
            # Content check for API spec: look for openapi/swagger marker in first 2KB
            if suffix in (".json", ".yaml", ".yml"):
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")[:2000].lower()
                    if '"openapi"' in text or '"swagger"' in text or "openapi:" in text or "swagger:" in text:
                        if rel not in api_specs:
                            api_specs[rel] = 1
                except Exception:
                    pass

        # Repo metadata
        if name in REPO_METADATA or name.startswith(".git"):
            repo_metadata[name] = repo_metadata.get(name, 0) + 1
        if ".git" in p.parts:
            repo_metadata[".git"] = repo_metadata.get(".git", 0) + 1

    # Normalize: sort for determinism
    return {
        "languages": dict(sorted(languages.items())),
        "dependency_manifests": dict(sorted(dependency_manifests.items())),
        "secrets_candidates": dict(sorted(secrets_candidates.items())),
        "iac_files": dict(sorted(iac_files.items())),
        "api_specs": dict(sorted(api_specs.items())),
        "repo_metadata": dict(sorted(repo_metadata.items())),
        "total_files": total_files,
        "source_files": source_files,
        "config_files": config_files,
    }


def summarize_artifact_types(detection: dict) -> list[str]:
    """Return list of artifact type categories detected."""
    types = []
    if detection.get("languages"):
        types.append("source_code")
    if detection.get("dependency_manifests"):
        types.append("dependency_manifest")
    if detection.get("secrets_candidates"):
        types.append("secrets_candidate")
    if detection.get("iac_files"):
        types.append("iac")
    if detection.get("api_specs"):
        types.append("api_spec")
    if detection.get("repo_metadata"):
        types.append("repository_metadata")
    return sorted(types)
