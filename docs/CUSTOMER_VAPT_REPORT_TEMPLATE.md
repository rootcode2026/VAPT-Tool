# Customer VAPT Report Template — Authoritative

> **Authoritative customer-facing VAPT report template:** `docs/templates/VAPT_Final_Report.docx` (copy of `VAPT_Final_Report (1).docx`)
> Provided by product owner. This document is the authoritative layout for customer delivery.

**"VAPT_Final_Report.docx is the authoritative customer-facing VAPT report template."**

**Do not treat `backend/app/services/report_service.py` as the authoritative template.**
`report_service.py` is the **delivery mechanism** (generation, persistence, PDF/CSV/DOCX export) that maps persisted platform data into the template structure. The DOCX defines the customer-facing structure; the service implements it. `backend/app/services/report_docx.py` populates the actual DOCX.

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

## Actual DOCX Population Architecture

- **Template path:** `docs/templates/VAPT_Final_Report.docx` (and fallback `VAPT_Final_Report (1).docx`). Never modified during generation; a copy is opened per report via `python-docx` `Document(template_path)`.
- **Entry point:** `GET /api/v1/reports/{report_id}/download/{fmt}` with `fmt=docx` → `report_service.export_docx(report, customer_name)` → `report_docx.export_docx(report, customer_name)` → DOCX bytes with `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document` and `Content-Disposition: attachment; filename="{report_type}-{id}.docx"`.
- **Dependency:** `python-docx` in `backend/requirements.txt`. Minimal; no heavy PDF conversion added.
- **PDF remains:** `export_pdf` continues to render 23-section logical PDF via `reportlab` (with `_minimal_pdf` fallback). DOCX is authoritative visual template; PDF is alternate delivery. No DOCX→PDF conversion is attempted in runtime (would require LibreOffice/heavy service); documented as limitation.
- **TOC field:** Template contains `TOC \o "1-3" \h \z \u` field (`w:instrText`). Generation preserves the field; Word updates page numbers on open (no fabricated page numbers inserted).

## Table Mappings (DOCX → Persisted Data)

All values come from real persisted data; placeholders render `Not provided / Not assessed / Not available` when absent; no invented evidence/CVSS/hosts/screenshots.

| Template Table (index) | Section | Columns | Source |
|---|---|---|---|
| 0 | Cover | CLIENT / PERIOD / DATE / VERSION / PREPARED BY | `Organization.name` (customer), `snapshot.period` (start/end), `Report.data_as_of`, `Report.version` |
| 2 | Document Control | Field / Details | customer, version, date, `VAPT Platform` for prepared/reviewed/approved |
| 3,4,6,7,11,13-17,28,31,32 | Static reference | — | Preserved as-is |
| 5 | Executive Summary Overall Result | Severity / Web / Network / Total | `web_findings`/`net_findings` counts per severity (critical/high/medium/low/info) |
| 8 | Scope Web Apps | S.No / Application / URL / Env / Testing Type | Distinct `asset_value` from web findings (fallback `Not provided`) |
| 10 | Scope Network | S.No / IP / Host / Asset Type / Env | Distinct `asset_value` from network findings |
| 12 | Testing Window | Item / Details | Period string |
| 18 | Executive Risk Web | ID / Finding / Severity / Affected Component / Status | `WEB-XXX` deterministic (sorted severity→title→id), `title`, `severity`, `asset_value`, `status` |
| 19 | Executive Risk Network | ID / Finding / Severity / Affected Host/Port / Status | `NET-XXX` similarly |
| 20,21 | Web/Network Result Summary | Severity / Count | Per-severity web/net counts + TOTAL |
| 22 | Web Finding Meta | Severity / CVSS / Vector / Status / URL / Param / OWASP/CWE | First `web_findings[0]` (extra findings inserted as cloned blocks) |
| 23 | Web Evidence | placeholder | `_sanitize_evidence(finding.evidence, 200)` with `[REDACTED]` |
| 24 | Web Retest | Date / Status / Observation | `retest_date`, `retest_result`, `retest_observation` (or `Not yet retested`) |
| 25 | Network Finding Meta | Severity / CVSS / Status / Host / Port / Service / CVE | First `net_findings[0]` |
| 26 | Network Evidence | placeholder | Sanitized evidence |
| 27 | Network Retest | Date / Status / Observation | As above |
| 29 | Remediation Tracker | ID / Finding / Severity / Owner / Target Date / Status | All findings (≤15) with `WEB/NET-XXX`, severity, owner (`Application/Infrastructure Team` or `owner_user_id`), `due_at` → `Not provided`, status |
| 30 | Retest Summary | Severity / Initial / Closed / Partially Fixed / Open / Risk Accepted | Per-severity bucketing from `status`/`retest_result` (Closed=`resolved/closed`, Partially=`reopened/partial`, Open=remaining, Risk Accepted=`accepted_risk`) |
| 33,34 | Appendix A Assets | S.No / Application/URL / Env / Status ; S.No / IP / Host / Type / Status | Distinct web/net assets (fallback `Not provided`) |
| 35 | Appendix B Ports | Host / Port / Protocol / Service / Version / Exposure | `port/protocol/service/version` from network findings (fallback `Not available/Not provided`) |
| 36 | Appendix C Tools | Category / Examples | `snapshot.methodology.scanners_observed` actually used; if none `Not assessed`; template examples not assumed |
| Other | Headers/Footers/TOC/Paragraphs | placeholders like `[Customer Name]`, `[DD-MMM-YYYY]` | Replaced via paragraph scan; header/footer version updated to `Version {version} - Final` |

**Finding identifiers:** Deterministic `WEB-XXX`/`NET-XXX` (XXX zero-padded) sorted by severity rank (critical→info), then title, then id. Stable for same dataset. Not random. Not persisted as ID change.

## Placeholder Behavior

- `[Customer Name]` / `[CUSTOMER NAME]` → `Organization.name` (or `organization_id` fallback). Upper variant for header. Global replace across paragraphs, table cells, header/footer.
- `[DD-MMM-YYYY]`, `[DD-MMM-YYYY] to [DD-MMM-YYYY]`, `[Date]` → formatted `data_as_of` / period.
- `[Finding Name]`, `[High]`, `[URL / Function]`, `[IP:Port]`, `[0]` etc. inside tables are overwritten by table population, not left as placeholder.
- Missing fields: CVSS → `Not available`, URL → `Not provided`, evidence → `Not available`, test info → `Not assessed` (never fabricated).
- Evidence sanitized to `[REDACTED]` for `password/api_key/secret/token/private_key/credential` patterns; bounded 200 chars; `MAX_REMEDIATION_CHARS 300` preserved.

## Data Mapping Rules (Must Be Enforced)

- **Populate from persisted data only:** findings (`Finding`), assets (`Asset`), scans (`Scan`), monitoring/change (`AssetChangeEvent`, `MonitoringChangeEvent`), ownership (`owner_user_id`), remediation (`FindingRemediation`), retest (`FindingRetest`), validation (`SecurityValidation`), evidence (`Finding.evidence`), project/customer scope (`Project`, `Organization`), report snapshot (`Report.data_snapshot`).
- **Placeholders** are template placeholders only — populate from engagement data when exists; otherwise render `Not assessed / Not applicable / Information not provided` — **never invent**.
- **Scanner output ≠ confirmed vulnerability.** Finding must be supported by `evidence` + `validation`/`correlation` before appearing as confirmed in customer report.
- **Evidence sanitized:** `_finding_detail_row` caps `evidence 200` / `remediation 300`, `sanitize_for_csv`, `export_pdf` escapes `()`/`\`, DOCX `_sanitize_evidence` redacts with `[REDACTED]`; no raw `password/token/secret/private_key/credential/api_key/access_key`.
- **No credentials:** Never include active credentials, session tokens, API secrets, private keys, or unnecessary sensitive customer data.

## Finding Detail Structure (Per Template)

**Web finding:** Finding ID, Vulnerability Name, Severity, CVSS Score/Vector, Status, Affected URL, Affected Parameter/Function, OWASP/CWE, Description, Evidence/PoC, Technical Impact, Business Impact, Recommendation, References, Retest Result — mapped from `Finding.{id,title,severity,score,cve,cwe,status,asset_id,evidence,remediation}` + `FindingRetest.result` + `SecurityValidation.verdict`.

**Network finding:** Finding ID, Vulnerability Name, Severity, CVSS, Status, Affected Host, Port/Protocol, Service/Version, CVE/CWE, Description, Evidence, Technical Impact, Business Impact, Recommendation, References, Retest Result — mapped from `Finding` + `Asset (ip/port/service)` + `extra_data`.

## DOCX / PDF Output Behavior

- **DOCX:** `GET /reports/{id}/download/docx` returns `application/vnd.openxmlformats-officedocument.wordprocessingml.document`. Opens in Word/LibreOffice. Preserves: table headers, column order, section order, styles, headings, header/footer, confidentiality marking (`CONFIDENTIAL`), TOC field. Master template untouched.
- **PDF:** `GET /reports/{id}/download/pdf` renders 23 sections via `reportlab` (`_minimal_pdf` fallback) with correct xref, Helvetica, ASCII-safe, `CONFIDENTIAL` footer. DOCX→PDF conversion is **not** performed in runtime (requires external converter) — documented limitation; DOCX remains authoritative for customer layout.
- **Other formats:** `json`/`csv` unchanged.

## Security Preserved

- Strict RBAC `RBAC_STRICT_MODE=true`, RLS `ENABLE+FORCE` on 15+ tables, tenant isolation via `current_setting('app.current_organization_id')`, `require_project_access`.
- Tenant isolation verified: same-tenant download allowed, cross-tenant 404, fake ID 404, incomplete (non-completed) 400, invalid format 400, sensitive evidence sanitized.
- Audit `REPORT_CREATED/GENERATION_* /VIEWED/DOWNLOADED/CANCELLED`, sanitized.
- Evidence sanitized, bounded (`MAX_EVIDENCE_CHARS 200`).

## Payment Note

Real payment processing (Razorpay/Stripe, checkout, webhook, payment UI) is **NOT part of product** — product is licensed to companies. Only mock `PaymentProvider` remains for tests; no `RAZORPAY_*` in production.

## Limitations

- DOCX generation requires `python-docx`; if template missing, download returns 500 `Report template not found`.
- Additional web/network findings beyond the first are inserted as cloned blocks before `10.1` / `11.1` library sections; layout is structurally correct but not pixel-perfect cloned styling for extra findings — acceptable for F8; first finding preserves exact template table styling.
- Port/Service appendix uses real scan/evidence port/service/version when present; otherwise `Not available`.
- Tools appendix lists only scanners actually observed in `snapshot.methodology.scanners_observed`; template example tool names are not assumed used.
- Positive Observations: verified controls only; otherwise `Not assessed — no verified positive controls in snapshot`.
- DOCX→PDF exact fidelity conversion not in runtime; use DOCX for authoritative layout, PDF for bounded alternate delivery.

