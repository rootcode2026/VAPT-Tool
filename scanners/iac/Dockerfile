# S7.7 Production IaC Scanner — Checkov
#
# Base: bridgecrew/checkov (official Checkov image)
# Pinned by DIGEST for reproducible builds.
#   image=bridgecrew/checkov
#   digest=sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016
#   version=3.3.16 (verified via `checkov --version` at build)
#   architecture=linux/amd64
# Non-root, SARIF, no Docker socket, no privileged, no host networking.

FROM bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016

# Create non-root user — base Checkov image runs as root
RUN addgroup --system checkov 2>/dev/null || true && \
    adduser --system --ingroup checkov checkov 2>/dev/null || true && \
    mkdir -p /workspace /tmp && \
    chown -R checkov:checkov /workspace && \
    chmod 1777 /tmp

# Verify pinned version
RUN checkov --version

WORKDIR /workspace

# Run as non-root; command provided by IacScanner via DockerRunner
USER checkov
ENTRYPOINT []
CMD ["checkov", "--help"]
