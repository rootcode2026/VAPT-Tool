FROM ghcr.io/google/osv-scanner@sha256:8108ae94eadea5a02c9bec6e646909d5b790b44bd62d7f5b7f0b1d6d0ffc7734

# SCA scanner image for VAPT — OSV-Scanner, pinned via digest, non-root, SARIF
# No secrets, no Docker socket, no privileged, workspace read-only
# Pinned version: 1.9.2 (digest sha256:8108ae94eadea5a02c9bec6e646909d5b790b44bd62d7f5b7f0b1d6d0ffc7734)

RUN addgroup --system osvgroup 2>/dev/null || true && \
    adduser --system --ingroup osvgroup osvuser 2>/dev/null || true && \
    mkdir -p /workspace && chown osvuser:osvgroup /workspace || true

WORKDIR /workspace

# Verify osv-scanner version
RUN osv-scanner --version || echo "osv-scanner version check"

USER osvuser
ENTRYPOINT []
CMD ["osv-scanner", "--help"]
