# Customer VAPT Report Template — Authoritative

> **Authoritative customer-facing VAPT report template:** `VAPT_Final_Report (1).docx`
> Provided by product owner. This document is the authoritative layout for customer delivery.

**Do not treat `backend/app/services/report_service.py` as the authoritative template.**
`report_service.py` is the **delivery mechanism** (generation, persistence, PDF/CSV export) that maps persisted platform data into the template structure. The DOCX defines the customer-facing structure; the service implements it.

## Template Scope (23 Sections)

The DOCX `Vulnerability Assessment and Penetration Testing Final Security Assessment Report — WEB APPLICATION & NETWORK INFRASTRUCTURE` contains:

1. Cover / Confidentiality
2. Document Control
3. Table of Contents
4. Executive Summary (4.1 Coverage, 4.2 Overall Result, 4.3 Key Management Actions)
5. Assessment Objectives
6. Scope (6.1 Web App Scope, 6.2 Test Accounts/Roles, 6.3 Network Scope)
7. Rules of Engagement
8. Assessment Methodology (8.1 Web and Network Coverage)
9. Risk Rating Methodology (9.1 Finding Status)
10. Executive Risk Summary (10.1 Web Findings, 10.2 Network Findings, 10.3 Risk Concentration)
11. Web Application VAPT Results (11.1 Summary, 11.2 Functional Areas Reviewed, 11.3 Conclusion)
12. Network VAPT Results (12.1 Summary, 12.2 Areas Reviewed, 12.3 Conclusion)
13. Detailed Web Application Findings (13.1 Common Web Finding Library)
14. Detailed Network Findings (14.1 Common Network Finding Library)
15. Positive Security Observations
16. Remediation Roadmap (16.1 Remediation Tracker)
17. Retest / Validation Summary
18. Assessment Limitations
19. Conclusion
20. Appendix A - Assets Tested
21. Appendix B - Port and Service Summary
22. Appendix C - Tools and Techniques
23. Appendix D - Evidence Handling Guidance

## Data Mapping Rules (Must Be Enforced)

- **Populate from persisted data only:** findings (`Finding`), assets (`Asset`), scans (`Scan`), monitoring/change (`AssetChangeEvent`, `MonitoringChangeEvent`), ownership (`owner_user_id`), remediation (`FindingRemediation`), retest (`FindingRetest`), validation (`SecurityValidation`), evidence (`Finding.evidence`), project/customer scope (`Project`, `Organization`), report snapshot (`Report.data_snapshot`).
- **Placeholders** `[Customer Name]`, `[Date]`, `[Finding Name]`, `[IP]`, `[URL]` etc. are **template placeholders only** — populate from engagement data when exists; otherwise render `Not assessed / Not applicable / Information not provided` — **never invent**.
- **Scanner output ≠ confirmed vulnerability.** Finding must be supported by `evidence` + `validation`/`correlation` before appearing as confirmed in customer report.
- **Evidence sanitized:** `_finding_detail_row` caps `evidence 200` / `remediation 300`, `sanitize_for_csv`, `export_pdf` escapes `()`/`\`, no raw `password/token/secret/private_key/credential/api_key/access_key` — `[REDACTED]` where applicable.
- **No credentials:** Never include active credentials, session tokens, API secrets, private keys, or unnecessary sensitive customer data.

## Finding Detail Structure (Per Template)

**Web finding:** Finding ID, Vulnerability Name, Severity, CVSS Score/Vector, Status, Affected URL, Affected Parameter/Function, OWASP/CWE, Description, Evidence/PoC, Technical Impact, Business Impact, Recommendation, References, Retest Result — mapped from `Finding.{id,title,severity,score,cve,cwe,status,asset_id,evidence,remediation}` + `FindingRetest.result` + `SecurityValidation.verdict`.

**Network finding:** Finding ID, Vulnerability Name, Severity, CVSS, Status, Affected Host, Port/Protocol, Service/Version, CVE/CWE, Description, Evidence, Technical Impact, Business Impact, Recommendation, References, Retest Result — mapped from `Finding` + `Asset (ip/port/service)` + `extra_data`.

## Current Implementation Status

- **Underlying infrastructure:** `Report` model (`report_type, title, status, parameters, summary, content, data_snapshot, version, data_as_of`), `collect_metrics`, `collect_report_snapshot` (bounded `MAX_DETAIL_FINDINGS 50`, period `MAX_PERIOD_DAYS 365`), `export_pdf` (reportlab → `_minimal_pdf` fallback with correct xref, Helvetica, ASCII-safe, `CONFIDENTIAL` footer), `GET /api/v1/reports/{id}/download/{fmt}` (`json/csv/pdf`, tenant-isolated via `require_project_access` or `organization_id`, IDOR 404, not completed 400, `Content-Disposition attachment`, audit `REPORT_DOWNLOADED`) — **VERIFIED** on host PostgreSQL 18.4 via focused tests.
- **Full 23-section customer report generation:** **IMPLEMENTED** via `report_service.py: _is_web_finding` + `_customer_vapt_sections` (23 sections mapping real persisted data per template) + `_pdf_text_lines` delegating to customer template. `export_pdf` now renders 23 sections (Cover, Document Control, TOC, Executive Summary with Coverage/Result/Actions, Objectives, Scope, Rules, Methodology, Risk Rating, Executive Risk Summary, Web/Network Results, Detailed Web/Network Findings with WEB-XXX/NET-XXX deterministic IDs, Positive Observations, Remediation Roadmap, Retest Summary, Limitations, Conclusion, Appendices A-D) with bounded sanitized data, `WEB-XXX`/`NET-XXX` stable sorted by severity, CVSS `Not available` when missing, placeholders `Not provided/Not assessed` when absent, no invented evidence/screenshots/CVSS.
- **DOCX file:** `VAPT_Final_Report (1).docx` is **not committed** to repo (provided externally, confidential). Reference retained as authoritative; do not commit the binary. PDF output implements logical structure of DOCX; exact binary `.docx` templating via `python-docx` remains **DEFERRED** (PDF is authoritative delivery per existing `GET /reports/{id}/download/pdf`; DOCX format can be added without new architecture).

## Security Preserved

- Strict RBAC `RBAC_STRICT_MODE=true`, RLS `ENABLE+FORCE` on 15+ tables, tenant isolation via `current_setting('app.current_organization_id')`, `require_project_access`.
- Audit `REPORT_CREATED/GENERATION_* /VIEWED/DOWNLOADED/CANCELLED`, sanitized.
- Evidence sanitized, bounded (`MAX_EVIDENCE_CHARS 200`).

## Payment Note

Real payment processing (Razorpay/Stripe, checkout, webhook, payment UI) is **NOT part of product** — product is licensed to companies. Only mock `PaymentProvider` remains for tests; no `RAZORPAY_*` in production.

## Next Work

DOCX binary templating via `python-docx` remains deferred (PDF with 23 sections is authoritative delivery). Keep `GET /reports/{id}/download/pdf` as delivery mechanism; add `docx` format only when exact binary preservation is proven practical without destabilizing.
