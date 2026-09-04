"""Scanner routing — deterministic recommendation based on detected artifacts."""

from typing import List, Dict


def recommend_scanners(detection: dict, has_container_image: bool = False) -> Dict[str, List[str]]:
    """Return scan plan recommendation.

    Returns:
        {
            "recommended": ["sast", ...],
            "reasons": {scanner: reason},
            "all_scanners": [...],  # for reference
        }
    """
    recommended: List[str] = []
    reasons: Dict[str, str] = {}

    languages = detection.get("languages", {})
    manifests = detection.get("dependency_manifests", {})
    secrets = detection.get("secrets_candidates", {})
    iac_files = detection.get("iac_files", {})
    api_specs = detection.get("api_specs", {})

    # SAST: source files
    if languages:
        # Check if any supported SAST language present
        supported = {"Python", "JavaScript", "TypeScript", "Java", "Go"}
        if any(lang in supported for lang in languages):
            recommended.append("sast")
            reasons["sast"] = f"Source files detected: {', '.join(sorted(languages.keys())[:5])}"

    # SCA: dependency manifests
    if manifests:
        recommended.append("sca")
        reasons["sca"] = f"Dependency manifests: {', '.join(sorted(manifests.keys())[:5])}"

    # Secrets: .env/config/credential candidates
    if secrets:
        recommended.append("secrets")
        reasons["secrets"] = f"Secrets candidates: {', '.join(sorted(secrets.keys())[:5])}"

    # IaC: Terraform/K8s/Dockerfile etc.
    if iac_files:
        recommended.append("iac")
        reasons["iac"] = f"IaC files: {len(iac_files)} file(s) e.g. {next(iter(iac_files))}"

    # API: OpenAPI/Swagger
    if api_specs:
        recommended.append("api")
        reasons["api"] = f"API specs: {', '.join(list(api_specs.keys())[:3])}"

    # Container: image reference provided separately (not from artifact detection)
    if has_container_image:
        recommended.append("container")
        reasons["container"] = "Container image reference provided"

    # Deduplicate and sort for determinism
    recommended = sorted(set(recommended))

    return {
        "recommended": recommended,
        "reasons": reasons,
        "all_scanners": sorted(["sast", "sca", "secrets", "iac", "api", "container"]),
    }


def plan_for_profile(detection: dict) -> List[str]:
    """Legacy helper: return recommended list."""
    return recommend_scanners(detection)["recommended"]
