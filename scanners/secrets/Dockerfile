# S7.5 Production Secrets Scanner — Gitleaks
#
# Base: zricethezav/gitleaks (official Gitleaks image)
# Pinned by DIGEST (not :latest tag) for reproducible, deterministic builds.
#   image=zricethezav/gitleaks
#   digest=sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
#   version=v8.30.1 (verified via `gitleaks version` at build)
#   architecture=linux/amd64
# Non-root, offline-enabled, SARIF, workspace read-only.
# No Docker socket, no privileged, no host networking.

FROM zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

# Create non-root user — the base gitleaks image runs as root by default
RUN addgroup --system gitleaks 2>/dev/null || true && \
    adduser --system --ingroup gitleaks gitleaks 2>/dev/null || true && \
    mkdir -p /workspace /config /tmp && \
    chown -R gitleaks:gitleaks /workspace /config && \
    chmod 1777 /tmp

# Copy VAPT ruleset (offline, bundled rules)
COPY gitleaks.toml /config/gitleaks.toml

WORKDIR /workspace

# Verify the exact pinned version
RUN gitleaks version

# Run as non-root; command provided by SecretsScanner via DockerRunner (not ENTRYPOINT)
USER gitleaks
ENTRYPOINT []
CMD ["gitleaks", "--help"]
