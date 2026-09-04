# S7.8 Production API Security Scanning — Custom Python validator with SARIF
#
# Base: python:3.11-slim (official Python image)
# Pinned by DIGEST for reproducible builds.
#   image=python
#   digest=sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534
#   version=3.11.16 (verified via `python --version` at build)
# Non-root, SARIF, no Docker socket, no privileged, no host networking.

FROM python@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

# Install YAML support
RUN pip install --no-cache-dir pyyaml==6.0.1

# Create non-root user
RUN addgroup --system api 2>/dev/null || true && \
    adduser --system --ingroup api api 2>/dev/null || true && \
    mkdir -p /workspace /app /tmp && \
    chown -R api:api /workspace /app && \
    chmod 1777 /tmp

WORKDIR /workspace

# Copy validator
COPY api_scan.py /app/api_scan.py
RUN chmod +x /app/api_scan.py && chown api:api /app/api_scan.py

# Verify
RUN python --version && python /app/api_scan.py --help 2>&1 | head -20

# Run as non-root
USER api
ENTRYPOINT []
CMD ["python", "/app/api_scan.py", "--help"]
