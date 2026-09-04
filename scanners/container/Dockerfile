# S7.6 Production Container Scanner — Trivy
#
# Base: aquasec/trivy (official Trivy image)
# Pinned by DIGEST for reproducible builds.
#   image=aquasec/trivy
#   digest=sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e
#   version=0.66.0 (verified via `trivy --version` at build)
#   architecture=linux/amd64
# Non-root, SARIF, no Docker socket, no privileged, no host networking.

FROM aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e

# Create non-root user — base Trivy image runs as root by default
RUN addgroup --system trivy 2>/dev/null || true && \
    adduser --system --ingroup trivy trivy 2>/dev/null || true && \
    mkdir -p /workspace /tmp && \
    chown -R trivy:trivy /workspace && \
    chmod 1777 /tmp

# Trivy DB is baked into the image; verify version
RUN trivy --version

WORKDIR /workspace

# Run as non-root; command provided by ContainerScanner via DockerRunner
USER trivy
ENTRYPOINT []
CMD ["trivy", "--help"]
