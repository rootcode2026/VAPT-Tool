FROM returntocorp/semgrep:1.75.0

# SAST scanner image for VAPT — deterministic, non-root, SARIF
# Pin version for reproducibility (no latest), offline by default
# No secrets, no Docker socket, no privileged

RUN addgroup --system semgroup || true && \
    adduser --system --ingroup semgroup semuser || true && \
    mkdir -p /workspace && chown semuser:semgroup /workspace

WORKDIR /workspace

# Ensure semgrep binary is available and version pinned
RUN semgrep --version

USER semuser

# Default: scan /workspace (read-only mount from worker)
# Command is provided by SASTScanner via DockerRunner, not ENTRYPOINT
ENTRYPOINT []
CMD ["semgrep", "--help"]
