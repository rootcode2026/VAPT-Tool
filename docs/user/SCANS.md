# Scans

Create scan via project → target → profile. Families: network (nmap), web (nuclei, zap, nikto, http_fingerprint, tls, dns, subdomain), SAST/SCA/secrets (Semgrep/OSV/Gitleaks), container (Trivy), IaC (Checkov), API (vapt-api), cloud (mock). Async via Celery, status queued/running/completed/failed, progress, overall_scan_status. On failure: check scanner health, retry, inspect audit.
