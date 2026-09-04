"""S7.6 Production Container Security — Trivy Docker, SARIF, no Docker socket.

Analyzes container images for OS/package vulnerabilities, misconfigurations,
and related security issues. The scanner does NOT mount the Docker socket
and does NOT run privileged. It pulls images via the Docker registry API
through the container's default network (no host socket needed), matching
the existing docker-socket-proxy isolation model (worker already uses
DOCKER_HOST=tcp://docker-socket-proxy:2375; scanner containers have no
socket mount).

Image references are strictly validated to prevent command injection.
"""

import json
import os
import re
from pathlib import Path

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.docker_runner import DockerRunner, ScannerFailureError

# ---------------------------------------------------------------------------
# Configuration — pinned Trivy
# ---------------------------------------------------------------------------

FALLBACK_ENABLED = os.getenv(
    "CONTAINER_FALLBACK_ENABLED", "false"
).lower() in ("1", "true", "yes", "on")
FALLBACK_ENGINE = "container_fallback"
PRODUCTION_ENGINE = "trivy"
PRODUCTION_VERSION = "0.66.0"

# Image-reference validation — prevent command injection
# Allowed: alphanumeric, ., -, _, /, :, @, plus optional tag/digest
# Length 1-512, no shell metachars, no whitespace, no control chars
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$")
_SHELL_FORBIDDEN = set(list(";|&$`") + ["*", "?", "~", "<", ">", "^", "(", ")", "[", "]", "{", "}", "'", '"', "\\"])
_MAX_REF_LEN = 512
_MIN_REF_LEN = 2


def _validate_image_ref(ref: str) -> str:
    """Validate and normalize container image reference.

    Returns stripped ref if valid, raises ValueError otherwise.
    Must be called before any interpolation into shell/docker commands.
    """
    if not isinstance(ref, str):
        raise ValueError("Image reference must be a string")
    cleaned = ref.strip()
    if not cleaned:
        raise ValueError("Image reference must not be empty")
    if len(cleaned) < _MIN_REF_LEN or len(cleaned) > _MAX_REF_LEN:
        raise ValueError(f"Image reference length must be {_MIN_REF_LEN}-{_MAX_REF_LEN}")
    # No whitespace or control chars
    if any(c.isspace() for c in cleaned):
        raise ValueError("Image reference must not contain whitespace")
    if any(ord(c) < 32 for c in cleaned):
        raise ValueError("Image reference contains control characters")
    # No shell metachars / control
    for ch in cleaned:
        if ch in _SHELL_FORBIDDEN:
            raise ValueError(f"Image reference contains forbidden character: {ch!r}")
        if ch == "\n" or ch == "\r":
            raise ValueError("Image reference contains newline")
    # Must match allowed charset
    if not _IMAGE_REF_RE.match(cleaned):
        raise ValueError(f"Invalid image reference format: {cleaned!r}")
    # Disallow path traversal patterns (defense-in-depth, not typical for images)
    if ".." in cleaned:
        raise ValueError("Image reference must not contain '..'")
    # Disallow leading - or . or _
    if cleaned[0] in "-._":
        raise ValueError("Image reference must not start with -._")
    # Must contain at least one alphanumeric or image name; allow tag/digest
    # Examples: alpine:3.14, myreg.example.com:5000/myimage:tag, nginx@sha256:abc...
    return cleaned


class ContainerScanner(BaseScanner):
    name = "container"
    category = "container_security"
    family = "container"
    description = "Container image security — Trivy 0.66.0 SARIF, no Docker socket, image-reference validation"
    target_types = {"container_image", "image", "docker_image"}
    input_type = "container_image"
    requires_workspace = False
    supported_profiles = {"container", "container_full"}
    output_format = "sarif"
    capabilities = {"container", "image_scan", "vulnerability", "misconfiguration", "sarif", "trivy", "cve"}
    timeout = int(os.getenv("CONTAINER_TIMEOUT", "300"))

    IMAGE = os.getenv("CONTAINER_IMAGE", "vapt-container:latest")
    FALLBACK_IMAGE = "aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e"

    def __init__(self):
        self.runner = None

    def _get_runner(self):
        if self.runner is None:
            self.runner = DockerRunner()
        return self.runner

    def _inject_provenance(self, findings: list[dict], engine: str, mode: str, image_ref: str | None = None) -> list[dict]:
        for f in findings:
            if not isinstance(f, dict):
                continue
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if not isinstance(meta, dict):
                meta = {}
            meta["execution_engine"] = engine
            meta["execution_mode"] = mode
            if engine == PRODUCTION_ENGINE:
                meta["engine_version"] = PRODUCTION_VERSION
                meta["image"] = self.IMAGE
            if image_ref:
                # Preserve image reference in metadata (not as asset value injection)
                meta["scanned_image"] = image_ref
                # Also preserve repository/tag/digest decomposition where trivially parseable
                # without fabricating values — just store original ref
                if "image" not in meta:
                    meta["image_ref"] = image_ref
            f["metadata"] = meta
            f["scanner"] = "container"
        return findings

    def _build_command(self, image_ref: str, for_fallback: bool = False) -> list[str]:
        # Trivy command — array form, no shell, no interpolation of untrusted values
        # beyond the validated image_ref as a single argv element.
        # --format sarif outputs SARIF to stdout; --quiet suppresses table logs.
        # For vapt-container (ENTRYPOINT []), command starts with "trivy".
        # For upstream fallback (ENTRYPOINT ["trivy"]), Docker would run
        # "trivy trivy image..." if we include trivy, so fallback uses ["image",...].
        base = ["image", "--format", "sarif", "--quiet", "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", image_ref]
        if for_fallback:
            return base
        return ["trivy"] + base

    def scan(self, target: str) -> str:
        # Validate image reference strictly before any execution
        image_ref = _validate_image_ref(target)

        runner = self._get_runner()
        last_exc = None

        for image in [self.IMAGE, self.FALLBACK_IMAGE]:
            is_fallback = (image == self.FALLBACK_IMAGE)
            command = self._build_command(image_ref, for_fallback=is_fallback)
            try:
                try:
                    raw = runner.run(
                        image=image,
                        command=command,
                        timeout=self.timeout,
                        scanner="container",
                        target=image_ref,
                        # No volumes, no workspace — image scan does not need host FS
                        volumes={},
                        workspace=None,
                    )
                    if not raw or not raw.strip():
                        raw = '{"version":"2.1.0","runs":[]}'
                except ScannerFailureError as e:
                    # Trivy normally exits 0 even with vulns; but handle exit 1 with SARIF
                    if getattr(e, "exit_code", None) in (0, 1) and e.stdout and '"runs"' in e.stdout:
                        raw = e.stdout
                    else:
                        raise

                # Validate SARIF is JSON with runs
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict) and "runs" in parsed:
                        from app.scanner.parsers.container_parser import ContainerParser
                        parser = ContainerParser()
                        parsed_result = parser.parse(raw)
                        parsed_result["scanner"] = "container"
                        parsed_result["findings"] = self._inject_provenance(
                            parsed_result.get("findings", []), PRODUCTION_ENGINE, "docker", image_ref
                        )
                        # Ensure container_image asset exists (scanner-level asset)
                        assets = parsed_result.get("assets", [])
                        # Add image asset if not already present
                        has_image_asset = any(
                            isinstance(a, dict) and a.get("type") == "container_image" and a.get("value") == image_ref
                            for a in assets
                        )
                        if not has_image_asset:
                            assets.append({
                                "type": "container_image",
                                "value": image_ref,
                                "metadata": {
                                    "source": "trivy",
                                    "execution_engine": PRODUCTION_ENGINE,
                                    "image_ref": image_ref,
                                },
                            })
                        parsed_result["assets"] = assets
                        parsed_result["metadata"] = parsed_result.get("metadata", {})
                        parsed_result["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                        parsed_result["metadata"]["execution_mode"] = "docker"
                        parsed_result["metadata"]["engine_version"] = PRODUCTION_VERSION
                        parsed_result["metadata"]["image"] = image
                        parsed_result["metadata"]["scanned_image"] = image_ref
                        return json.dumps(parsed_result)
                    return raw
                except json.JSONDecodeError:
                    return raw
            except Exception as exc:
                last_exc = exc
                if "not found" in str(exc).lower() and image == self.IMAGE:
                    continue
                if not FALLBACK_ENABLED:
                    # Sanitize error before surfacing (no secret leakage for container, but safe)
                    raise
                # Fallback enabled: return empty with provenance
                try:
                    result = {
                        "scanner": "container",
                        "assets": [],
                        "findings": [],
                        "errors": [],
                        "metadata": {
                            "execution_engine": FALLBACK_ENGINE,
                            "execution_mode": "fallback",
                            "scanned_image": image_ref,
                            "fallback_reason": str(exc)[:500],
                        },
                    }
                    return json.dumps(result)
                except Exception:
                    raise exc

        if last_exc:
            raise last_exc
        if FALLBACK_ENABLED:
            return json.dumps({
                "scanner": "container",
                "assets": [],
                "findings": [],
                "metadata": {"execution_engine": FALLBACK_ENGINE, "execution_mode": "fallback", "scanned_image": image_ref},
            })
        raise RuntimeError("Container scanner failed and fallback is disabled")

    def scan_with_context(self, context: ScanContext) -> str:
        # For container, context.target is the image reference; workspace is optional
        # If workspace is provided and target looks like host path, prefer image from metadata
        # Otherwise treat target as image ref (validated)
        # Support both: context.target as image, or context.metadata.get("image")
        candidate = None
        if isinstance(context, str):
            candidate = context
        else:
            # Prefer explicit image in metadata, then target, then workspace
            meta = getattr(context, "metadata", {}) or {}
            if isinstance(meta, dict) and meta.get("image"):
                candidate = str(meta["image"])
            elif context.target and isinstance(context.target, str) and context.target.strip():
                # Heuristic: if target looks like image ref (contains : or / or not a filesystem path)
                # For safety, try to validate as image; if fails, treat as invalid
                candidate = context.target.strip()
            elif context.workspace and Path(context.workspace).exists():
                # Workspace mode for container is not primary; return empty gracefully
                return json.dumps({
                    "scanner": "container",
                    "assets": [],
                    "findings": [],
                    "errors": [],
                    "metadata": {
                        "workspace": context.workspace,
                        "reason": "workspace mode not supported for container scanner — use image reference",
                        "execution_engine": PRODUCTION_ENGINE,
                        "execution_mode": "empty",
                        "engine_version": PRODUCTION_VERSION,
                    },
                })
            else:
                candidate = str(context.target) if context.target else ""

        # Validate as image ref; if validation fails and candidate looks like filesystem, return empty
        try:
            return self.scan(candidate)
        except ValueError as ve:
            # Invalid image ref — treat as user error, not scanner failure
            raise ValueError(f"Invalid container image reference: {ve}") from ve
