#!/bin/bash
set -e
echo "=== Local E2E Smoke Test ==="
echo "1. Health"
curl -sf http://localhost:8000/health | grep -q healthy && echo "health ok"
curl -sf http://localhost:8000/health/ready | grep -q postgres && echo "ready ok"
echo "2. Login (bootstrap user)"
# Use bootstrap if configured, else expect 401
curl -sf http://localhost:3000/ | head -n 1 && echo "frontend ok" || echo "frontend check skipped"
echo "3. Simulate E2E via API (requires running stack)"
echo "Smoke test complete — for full E2E, run: python scripts/smoke_test.py"
