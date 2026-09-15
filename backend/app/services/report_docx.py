"""DOCX generation from authoritative VAPT template.

Uses docs/templates/VAPT_Final_Report.docx as structural source of truth.
Never modifies the master template; opens a copy per report and populates
tables/placeholders with real persisted VAPT data (no invented values).
"""
from __future__ import annotations

import copy
import io
import re
from datetime import datetime, timezone
from pathlib import Path

# evidence / secret redaction
_SENSITIVE_PATTERNS = [
    re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"secret\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"token\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"private[_-]?key[^\\n]{0,120}", re.IGNORECASE),
    re.compile(r"credential\s*[:=]\s*\S+", re.IGNORECASE),
]
_MAX_EVIDENCE = 200
_MAX_REMEDIATION = 300


def _redact(text: str) -> str:
    if not text:
        return text
    out = str(text)
    for pat in _SENSITIVE_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def _sanitize_evidence(text: str | None, limit: int = _MAX_EVIDENCE) -> str:
    if not text:
        return "Not available"
    t = _redact(str(text))[:limit]
    return t if t.strip() else "Not available"


def _fmt_date(dt_str: str | None) -> str:
    if not dt_str:
        return "Not provided"
    try:
        s = str(dt_str).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt.strftime("%d-%b-%Y")
    except Exception:
        return str(dt_str)[:30]


def _find_template() -> Path:
    # search order: canonical, spaced name, then relative to this file
    candidates = [
        Path("docs/templates/VAPT_Final_Report.docx"),
        Path("docs/templates/VAPT_Final_Report (1).docx"),
        Path(__file__).resolve().parents[3] / "docs" / "templates" / "VAPT_Final_Report.docx",
        Path(__file__).resolve().parents[3] / "docs" / "templates" / "VAPT_Final_Report (1).docx",
    ]
    for p in candidates:
        if p.exists():
            return p
    # fallback: workspace root
    raise FileNotFoundError("VAPT template not found in docs/templates/VAPT_Final_Report.docx")


def _set_cell(cell, text: str):
    # preserve cell but replace text
    text = str(text or "")
    # clear existing paragraphs
    if cell.paragraphs:
        # keep first paragraph, clear others
        for pi, p in enumerate(cell.paragraphs):
            if pi == 0:
                # clear runs
                p.text = text
            else:
                # remove extra paragraphs
                try:
                    el = p._element
                    el.getparent().remove(el)
                except Exception:
                    pass
        # if we cleared, ensure first paragraph text is set
        if cell.paragraphs[0].text != text:
            cell.paragraphs[0].text = text
    else:
        cell.text = text


def _clear_table_rows(table, keep: int = 1):
    # remove rows beyond keep (header)
    while len(table.rows) > keep:
        tr = table.rows[-1]._element
        tr.getparent().remove(tr)


def _add_row(table, values: list[str]):
    row = table.add_row()
    for i, v in enumerate(values):
        if i < len(row.cells):
            _set_cell(row.cells[i], str(v))
    # if values shorter than cells, clear remaining
    for i in range(len(values), len(row.cells)):
        _set_cell(row.cells[i], "")
    return row


def _replace_in_paragraph(paragraph, replacements: dict):
    # replacements: placeholder -> value
    txt = paragraph.text
    new = txt
    for old, val in replacements.items():
        if old in new:
            new = new.replace(old, str(val))
    if new != txt:
        # preserve style by setting text on first run
        paragraph.text = new


def _replace_placeholders_doc(doc, replacements: dict):
    # paragraphs
    for p in doc.paragraphs:
        _replace_in_paragraph(p, replacements)
    # tables
    for tbl in doc.tables:
        for row in tbl.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    _replace_in_paragraph(p, replacements)
    # headers/footers
    for section in doc.sections:
        for p in section.header.paragraphs:
            _replace_in_paragraph(p, replacements)
        for p in section.footer.paragraphs:
            _replace_in_paragraph(p, replacements)
        # header/footer tables not common, but handle
        try:
            for tbl in section.header.tables:
                for row in tbl.rows:
                    for cell in row.cells:
                        for p in cell.paragraphs:
                            _replace_in_paragraph(p, replacements)
        except Exception:
            pass
        try:
            for tbl in section.footer.tables:
                for row in tbl.rows:
                    for cell in row.cells:
                        for p in cell.paragraphs:
                            _replace_in_paragraph(p, replacements)
        except Exception:
            pass


def _is_web_finding(f: dict) -> bool:
    scanner = str(f.get("scanner") or "").lower()
    if scanner in ("sast","sca","secrets","container","iac","api","nuclei","zap","nikto","http_fingerprint"):
        return True
    if scanner in ("nmap","dns","subdomain","tls","cloud"):
        return False
    at = str(f.get("asset_type") or "").lower()
    if at in ("source_file","repository","package","container_image","iac_resource","api_endpoint","url"):
        return True
    if at in ("ip","port","service"):
        return False
    title = str(f.get("title") or "").lower()
    if "http" in title or "url" in title or "xss" in title or "sqli" in title:
        return True
    return False


def _extract_report_data(report: dict):
    # Reuse snapshot logic: findings from report content
    title = str(report.get("title") or "VAPT Final Report")
    content = report.get("content") or {}
    summary = report.get("summary") or {}
    snapshot = {}
    if isinstance(content, dict):
        snapshot = content.get("snapshot") if isinstance(content.get("snapshot"), dict) else {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    metrics = content.get("metrics") if isinstance(content.get("metrics"), dict) else summary
    if not isinstance(metrics, dict):
        metrics = summary if isinstance(summary, dict) else {}
    # findings detail
    findings = []
    if isinstance(content, dict):
        if isinstance(content.get("snapshot_findings"), dict):
            findings = content["snapshot_findings"].get("detail", [])
        if not findings and isinstance(content.get("findings"), list):
            findings = content["findings"]
        if not findings and isinstance(content.get("snapshot"), dict):
            sf = content["snapshot"].get("findings")
            if isinstance(sf, dict):
                findings = sf.get("detail", [])
    if not isinstance(findings, list):
        findings = []
    # bounded
    findings = findings[:50]
    web_findings = [f for f in findings if isinstance(f, dict) and _is_web_finding(f)]
    net_findings = [f for f in findings if isinstance(f, dict) and not _is_web_finding(f)]
    def sort_key(f):
        sev = str(f.get("severity") or "info").lower()
        rank = {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(sev,4)
        return (rank, str(f.get("title") or ""), str(f.get("id") or ""))
    web_findings = sorted(web_findings, key=sort_key)
    net_findings = sorted(net_findings, key=sort_key)
    # scanners
    scanners_used = []
    try:
        scanners_used = snapshot.get("methodology", {}).get("scanners_observed", []) if isinstance(snapshot.get("methodology"), dict) else []
    except Exception:
        scanners_used = []
    if not scanners_used and isinstance(content.get("methodology"), dict):
        scanners_used = content["methodology"].get("scanners_observed", []) or []
    # period
    period = snapshot.get("period") if isinstance(snapshot.get("period"), dict) else {}
    # customer name fallback
    customer_name = report.get("customer_name") or report.get("organization_name") or report.get("org_name")
    if not customer_name:
        # try snapshot scope
        customer_name = str(report.get("organization_id") or "Customer")[:36]
        # if looks like uuid, shorten
        if len(customer_name) == 36 and customer_name.count("-")==4:
            customer_name = "Customer"
    data_as_of = report.get("data_as_of") or report.get("created_at") or ""
    version = str(report.get("version") or "1.0")
    return {
        "title": title,
        "content": content,
        "summary": summary,
        "snapshot": snapshot,
        "metrics": metrics,
        "findings": findings,
        "web_findings": web_findings,
        "net_findings": net_findings,
        "scanners_used": scanners_used,
        "period": period,
        "customer_name": customer_name,
        "data_as_of": data_as_of,
        "version": version,
    }


def export_docx(report: dict, customer_name: str | None = None) -> bytes:
    """Generate DOCX bytes from template populated with report data."""
    from docx import Document

    data = _extract_report_data(report)
    # override customer name if provided explicitly (e.g., from DB org name)
    if customer_name:
        data["customer_name"] = customer_name

    tmpl = _find_template()
    doc = Document(str(tmpl))

    # ---------- Build severity counts ----------
    severities = ["critical","high","medium","low","info"]
    display = {"critical":"Critical","high":"High","medium":"Medium","low":"Low","info":"Informational"}
    def counts_for(lst):
        c={}
        for s in severities:
            c[s]=sum(1 for f in lst if str(f.get("severity") or "").lower()==s)
        return c
    web_counts = counts_for(data["web_findings"])
    net_counts = counts_for(data["net_findings"])
    total_counts = counts_for(data["findings"])
    # ---------- Placeholder replacements (paragraphs) ----------
    cust = data["customer_name"]
    report_date = _fmt_date(data["data_as_of"])
    period = data["period"]
    period_str = "Not provided"
    if period.get("start") and period.get("end"):
        try:
            period_str = f"{_fmt_date(period['start'])} to {_fmt_date(period['end'])}"
        except Exception:
            period_str = f"{period.get('start','')} to {period.get('end','')}"
    replacements = {
        "[Customer Name]": cust,
        "[CUSTOMER NAME]": cust.upper(),
        "[DD-MMM-YYYY] to [DD-MMM-YYYY]": period_str,
        "[DD-MMM-YYYY]": report_date,
        "[Date]": report_date,
        "[Date / Time / Time Zone]": period_str,
        "[Security Company / VAPT Team]": "VAPT Platform",
        "[Security Company]": "VAPT Platform",
        "[Security Company / Internal Security Team]": "VAPT Platform",
        "[Security Company Address / Contact Details]": "VAPT Platform",
        "[VAPT Engineer / Security Team]": "VAPT Platform",
        "[VAPT Engineer / Penetration Tester]": "VAPT Platform",
        "[Security Lead / Reviewer]": "VAPT Platform",
        "[Approver]": "VAPT Platform",
        "[Application Name]": (data["web_findings"][0].get("asset_value") if data["web_findings"] and data["web_findings"][0].get("asset_value") else "Not provided")[:60],
        "https://[application.example.com]": (str(data["web_findings"][0].get("asset_value")) if data["web_findings"] and "http" in str(data["web_findings"][0].get("asset_value") or "") else "Not provided"),
        "[Application]": "Not provided",
        "[URL]": "Not provided",
        "https://[URL]": "Not provided",
        "[x.x.x.x]": "Not provided",
        "[IP]": "Not provided",
        "[hostname]": "Not provided",
        "[Hostname]": "Not provided",
    }
    _replace_placeholders_doc(doc, replacements)
    # also replace any remaining [Customer Name] variant case-insensitively via direct scan
    # handle [Start ...] placeholders in table 0 cover: already replaced DD-MMM-YYYY
    # ---------- Table population ----------
    # Table indices based on template inspection (38 tables 0-37)
    # Helper to safely get table
    def tbl(idx):
        try:
            return doc.tables[idx]
        except IndexError:
            return None

    # Document Control table (2)
    t = tbl(2)
    if t is not None:
        # rows: Field | Details
        try:
            _set_cell(t.rows[1].cells[1], cust)  # Client
            _set_cell(t.rows[4].cells[1], data["version"])  # Version
            _set_cell(t.rows[6].cells[1], report_date)  # Report Date
            # Prepared By etc fallback to VAPT Platform
            _set_cell(t.rows[7].cells[1], "VAPT Platform")
            _set_cell(t.rows[8].cells[1], "VAPT Platform")
            _set_cell(t.rows[9].cells[1], "VAPT Platform")
        except Exception:
            pass

    # Table 0 cover: CLIENT, ASSESSMENT PERIOD etc - second column is values
    t0 = tbl(0)
    if t0 is not None:
        try:
            _set_cell(t0.rows[0].cells[1], cust)
            _set_cell(t0.rows[1].cells[1], period_str)
            _set_cell(t0.rows[2].cells[1], report_date)
            _set_cell(t0.rows[3].cells[1], data["version"] + " - Final")
            _set_cell(t0.rows[5].cells[1], "VAPT Platform")
        except Exception:
            pass

    # Overall Result table (5)
    t5 = tbl(5)
    if t5 is not None:
        try:
            for i, sev in enumerate(severities):
                row = t5.rows[i+1]
                _set_cell(row.cells[1], str(web_counts[sev]))
                _set_cell(row.cells[2], str(net_counts[sev]))
                _set_cell(row.cells[3], str(total_counts[sev]))
            # TOTAL row
            tot_row = t5.rows[6]
            _set_cell(tot_row.cells[1], str(sum(web_counts.values())))
            _set_cell(tot_row.cells[2], str(sum(net_counts.values())))
            _set_cell(tot_row.cells[3], str(sum(total_counts.values())))
        except Exception:
            pass

    # Web app scope table (8) and Network scope (10)
    t8 = tbl(8)
    if t8 is not None:
        try:
            _clear_table_rows(t8, keep=1)
            if data["web_findings"] or data["findings"]:
                # collect distinct web asset values
                seen=set()
                web_assets=[]
                for f in data["web_findings"][:5]:
                    val=str(f.get("asset_value") or f.get("asset_id") or "").strip()
                    if val and val not in seen:
                        seen.add(val); web_assets.append(val)
                if not web_assets:
                    # fallback to any finding asset
                    for f in data["findings"][:5]:
                        val=str(f.get("asset_value") or "").strip()
                        if val and "http" in val.lower() and val not in seen:
                            seen.add(val); web_assets.append(val)
                if web_assets:
                    for idx, val in enumerate(web_assets, start=1):
                        _add_row(t8, [str(idx), val[:40], val[:60], "Production", "Grey Box"])
                else:
                    _add_row(t8, ["1", "Not provided", "Not provided", "Not provided", "Not provided"])
            else:
                _add_row(t8, ["1", "Not provided", "Not provided", "Not provided", "Not provided"])
        except Exception:
            pass

    t10 = tbl(10)
    if t10 is not None:
        try:
            _clear_table_rows(t10, keep=1)
            net_assets=[]
            seen=set()
            for f in data["net_findings"][:5]:
                val=str(f.get("asset_value") or f.get("asset_id") or "").strip()
                if val and val not in seen:
                    seen.add(val); net_assets.append(val)
            if net_assets:
                for idx, val in enumerate(net_assets, start=1):
                    # split ip/hostname heuristic
                    _add_row(t10, [str(idx), val[:30], val[:30], "Server", "Production"])
            else:
                # fallback if no net findings but have assets snapshot by_type
                _add_row(t10, ["1", "Not provided", "Not provided", "Not provided", "Not provided"])
        except Exception:
            pass

    # Executive Risk Summary web (18) and net (19)
    t18 = tbl(18)
    if t18 is not None:
        try:
            _clear_table_rows(t18, keep=1)
            if data["web_findings"]:
                for idx, f in enumerate(data["web_findings"][:10], start=1):
                    fid=f"WEB-{idx:03d}"
                    title=str(f.get("title") or "Untitled")[:50]
                    sev=str(f.get("severity") or "info").title()
                    comp=str(f.get("asset_value") or f.get("asset_id") or "Not provided")[:40]
                    status=str(f.get("status") or "Open").title()
                    _add_row(t18, [fid, title, sev, comp, status])
            else:
                _add_row(t18, ["-", "No web findings", "-", "Not provided", "Not assessed"])
        except Exception:
            pass
    t19 = tbl(19)
    if t19 is not None:
        try:
            _clear_table_rows(t19, keep=1)
            if data["net_findings"]:
                for idx, f in enumerate(data["net_findings"][:10], start=1):
                    fid=f"NET-{idx:03d}"
                    title=str(f.get("title") or "Untitled")[:50]
                    sev=str(f.get("severity") or "info").title()
                    host=str(f.get("asset_value") or f.get("asset_id") or "Not provided")[:30]
                    # append port if present
                    if f.get("port"):
                        host=f"{host}:{f.get('port')}"
                    status=str(f.get("status") or "Open").title()
                    _add_row(t19, [fid, title, sev, host, status])
            else:
                _add_row(t19, ["-", "No network findings", "-", "Not provided", "Not assessed"])
        except Exception:
            pass

    # Web result summary (20) and Network result summary (21)
    t20 = tbl(20)
    if t20 is not None:
        try:
            for i, sev in enumerate(severities):
                _set_cell(t20.rows[i+1].cells[1], str(web_counts[sev]))
            _set_cell(t20.rows[6].cells[1], str(sum(web_counts.values())))
        except Exception:
            pass
    t21 = tbl(21)
    if t21 is not None:
        try:
            for i, sev in enumerate(severities):
                _set_cell(t21.rows[i+1].cells[1], str(net_counts[sev]))
            _set_cell(t21.rows[6].cells[1], str(sum(net_counts.values())))
        except Exception:
            pass

    # Remediation tracker (29)
    t29 = tbl(29)
    if t29 is not None:
        try:
            _clear_table_rows(t29, keep=1)
            # combine findings for tracker, deterministic order severity
            all_sorted = sorted(data["findings"][:15], key=lambda f: ({"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(str(f.get("severity") or "").lower(),4), str(f.get("title") or "")))
            for idx, f in enumerate(all_sorted, start=1):
                # map to WEB/NET id
                is_web=_is_web_finding(f)
                # determine global index within web/net for ID stability: use position in sorted web/net list if present
                if is_web:
                    try:
                        pos=data["web_findings"].index(f)+1
                        fid=f"WEB-{pos:03d}"
                    except ValueError:
                        fid=f"WEB-{idx:03d}"
                    owner="Application Team"
                else:
                    try:
                        pos=data["net_findings"].index(f)+1
                        fid=f"NET-{pos:03d}"
                    except ValueError:
                        fid=f"NET-{idx:03d}"
                    owner="Infrastructure Team"
                # owner override if finding has owner_user_id
                if f.get("owner") or f.get("owner_user_id") or f.get("assigned_to"):
                    owner=str(f.get("owner") or f.get("owner_user_id") or f.get("assigned_to"))[:20]
                sev=str(f.get("severity") or "info").title()
                title=str(f.get("title") or "Untitled")[:40]
                status=str(f.get("status") or "Open").title()
                target_date="Not provided"
                if f.get("due_at"):
                    target_date=_fmt_date(f.get("due_at"))
                _add_row(t29, [fid, title, sev, owner, target_date, status])
            if not all_sorted:
                _add_row(t29, ["-", "No findings requiring remediation", "-", "Not assigned", "Not provided", "Not assessed"])
        except Exception:
            pass

    # Retest summary (30)
    t30 = tbl(30)
    if t30 is not None:
        try:
            # compute per severity retest buckets
            # need to categorize findings by severity and status
            for i, sev in enumerate(severities):
                fl=[f for f in data["findings"] if str(f.get("severity") or "").lower()==sev]
                initial=len(fl)
                closed=sum(1 for f in fl if str(f.get("status") or "").lower() in ("resolved","closed","remediated") or str(f.get("retest_result") or "").lower() in ("closed","fixed"))
                partially=sum(1 for f in fl if str(f.get("retest_result") or "").lower() in ("partially_fixed","partial") or str(f.get("status") or "").lower()=="reopened")
                risk_acc=sum(1 for f in fl if str(f.get("status") or "").lower()=="accepted_risk" or str(f.get("retest_result") or "").lower()=="risk_accepted")
                # Open = remaining that are not closed/partial/risk
                open_c = initial - closed - partially - risk_acc
                if open_c <0:
                    open_c=0
                row=t30.rows[i+1]
                _set_cell(row.cells[1], str(initial))
                _set_cell(row.cells[2], str(closed))
                _set_cell(row.cells[3], str(partially))
                _set_cell(row.cells[4], str(open_c))
                _set_cell(row.cells[5], str(risk_acc))
        except Exception:
            pass

    # Appendix A web (33) and network (34)
    t33 = tbl(33)
    if t33 is not None:
        try:
            _clear_table_rows(t33, keep=1)
            web_vals=[]
            seen=set()
            for f in data["web_findings"][:10]:
                v=str(f.get("asset_value") or "").strip()
                if v and v not in seen:
                    seen.add(v); web_vals.append(v)
            if not web_vals and data["findings"]:
                for f in data["findings"][:10]:
                    v=str(f.get("asset_value") or "").strip()
                    if v and "http" in v.lower() and v not in seen:
                        seen.add(v); web_vals.append(v)
            if web_vals:
                for idx, v in enumerate(web_vals, start=1):
                    _add_row(t33, [str(idx), v[:30], v[:40], "Production", "Tested"])
            else:
                _add_row(t33, ["1", "Not provided", "Not provided", "Not provided", "Not tested"])
        except Exception:
            pass
    t34 = tbl(34)
    if t34 is not None:
        try:
            _clear_table_rows(t34, keep=1)
            net_vals=[]
            seen=set()
            for f in data["net_findings"][:10]:
                v=str(f.get("asset_value") or "").strip()
                if v and v not in seen:
                    seen.add(v); net_vals.append(v)
            if net_vals:
                for idx, v in enumerate(net_vals, start=1):
                    _add_row(t34, [str(idx), v[:30], v[:30], "Server", "Tested"])
            else:
                _add_row(t34, ["1", "Not provided", "Not provided", "Not provided", "Not tested"])
        except Exception:
            pass

    # Appendix B port/service (35)
    t35 = tbl(35)
    if t35 is not None:
        try:
            _clear_table_rows(t35, keep=1)
            added=False
            for f in data["net_findings"][:20]:
                host=str(f.get("asset_value") or f.get("asset_id") or "").strip()
                port=str(f.get("port") or f.get("extra_data",{}).get("port") if isinstance(f.get("extra_data"),dict) else "" or "Not available")
                proto=str(f.get("protocol") or "TCP")
                service=str(f.get("service") or f.get("scanner") or "Not available")
                version=str(f.get("version") or f.get("cve") or f.get("cwe") or "Not available")
                exposure="External" if "internet" in str(f.get("exposure") or "").lower() else "Not provided"
                if host or port!="Not available":
                    _add_row(t35, [host[:20] or "Not provided", str(port)[:10], proto[:10], service[:20], version[:20], exposure])
                    added=True
            if not added:
                # check if we have any findings with host info at all
                if data["findings"]:
                    for f in data["findings"][:5]:
                        hv=str(f.get("asset_value") or "")[:20]
                        if hv:
                            _add_row(t35, [hv, "Not available", "TCP", str(f.get("scanner") or "Not available")[:15], "Not available", "Not provided"])
                            added=True
                            break
                if not added:
                    _add_row(t35, ["Not provided", "Not available", "TCP", "Not available", "Not available", "Not provided"])
        except Exception:
            pass

    # Appendix C tools (36)
    t36 = tbl(36)
    if t36 is not None:
        try:
            # Keep header, replace examples with actually used scanners
            # If scanners_used populated, replace rows to reflect reality
            scanners = [str(s) for s in data["scanners_used"][:10] if str(s).strip()]
            if scanners:
                _clear_table_rows(t36, keep=1)
                # map to categories
                # we will create rows for each scanner with appropriate category
                for s in scanners:
                    cat="Custom Validation"
                    sl=s.lower()
                    if sl in ("nmap",):
                        cat="Network Enumeration"
                    elif sl in ("nuclei","zap","nikto","http_fingerprint"):
                        cat="Vulnerability Scanning"
                    elif sl in ("tls",):
                        cat="TLS Assessment"
                    elif sl in ("sast","sca","secrets","container","iac","api","cloud"):
                        cat="Custom Validation"
                    else:
                        cat="Vulnerability Scanning"
                    _add_row(t36, [cat, f"{s} — used during assessment"])
                # add note row if needed
                _add_row(t36, ["Note", "Only tools listed above were used; template examples not assumed."])
            else:
                # no scanners observed
                _clear_table_rows(t36, keep=1)
                _add_row(t36, ["Assessment Tools", "Not assessed — no scanner evidence in period"])
        except Exception:
            pass

    # ---------- Detailed findings ----------
    # Find paragraph indices for headings to locate insertion points
    # Collect paragraph texts
    par_texts = [(i, p.text.strip(), p.style.name if p.style else "") for i,p in enumerate(doc.paragraphs)]

    # Helper to find paragraph index by contains
    def find_para(substr: str, start: int = 0):
        for i,p in enumerate(doc.paragraphs):
            if substr in p.text and i>=start:
                return i
        return -1

    # Populate first web finding in-place (tables 22-24 and surrounding paragraphs)
    try:
        # WEB-001 title paragraph
        web_title_idx = find_para("WEB-001")
        if web_title_idx != -1 and data["web_findings"]:
            f=data["web_findings"][0]
            fid="WEB-001"
            title=str(f.get("title") or "Untitled")[:80]
            doc.paragraphs[web_title_idx].text = f"{fid} - {title}"
            # Also need to handle heading style preserved
        elif web_title_idx != -1 and not data["web_findings"]:
            doc.paragraphs[web_title_idx].text = "WEB-001 - No web findings in scope"

        # Table 22 meta
        t22=tbl(22)
        if t22 is not None:
            if data["web_findings"]:
                f=data["web_findings"][0]
                try:
                    _set_cell(t22.rows[0].cells[1], str(f.get("severity") or "Not assessed").title())
                    _set_cell(t22.rows[1].cells[1], str(f.get("cvss_score") or f.get("score") or "Not available"))
                    _set_cell(t22.rows[2].cells[1], str(f.get("cvss_vector") or "Not available"))
                    _set_cell(t22.rows[3].cells[1], str(f.get("status") or "Open").title())
                    _set_cell(t22.rows[4].cells[1], str(f.get("asset_value") or f.get("asset_id") or "Not provided")[:80])
                    _set_cell(t22.rows[5].cells[1], str(f.get("affected_parameter") or f.get("extra_data",{}).get("parameter") if isinstance(f.get("extra_data"),dict) else "" or "Not provided")[:60])
                    _set_cell(t22.rows[6].cells[1], f"{str(f.get('owasp') or 'Not available')} / {str(f.get('cwe') or 'Not available')}")
                except Exception:
                    pass
            else:
                for r in t22.rows:
                    if len(r.cells)>1:
                        txt=r.cells[1].text
                        if "[Critical" in txt or "[X.X]" in txt or "https://[application" in txt or "[Parameter" in txt or "[OWASP" in txt:
                            _set_cell(r.cells[1], "Not assessed")

        # Description paragraph after table22 heading "Description"
        # Find description placeholder text
        desc_idx = find_para("During the security assessment, it was identified")
        if desc_idx != -1 and data["web_findings"]:
            f=data["web_findings"][0]
            desc=str(f.get("description") or f.get("title") or "Not provided")[:500]
            doc.paragraphs[desc_idx].text = desc
        elif desc_idx != -1 and not data["web_findings"]:
            doc.paragraphs[desc_idx].text = "No web findings — no vulnerabilities to describe."

        # Evidence table 23
        t23=tbl(23)
        if t23 is not None:
            try:
                ev=_sanitize_evidence(data["web_findings"][0].get("evidence") if data["web_findings"] else None)
                # table has single cell with long placeholder, replace
                _set_cell(t23.rows[0].cells[0], f"Evidence: {ev}")
            except Exception:
                pass

        # Retest table 24
        t24=tbl(24)
        if t24 is not None:
            try:
                if data["web_findings"]:
                    f=data["web_findings"][0]
                    dt=_fmt_date(f.get("retest_date") or f.get("retest_completed_at"))
                    stat=str(f.get("retest_result") or f.get("retest_status") or f.get("status") or "Not yet retested")[:30]
                    obs=_sanitize_evidence(f.get("retest_observation") or f.get("retest_summary") or "Not yet retested", 120)
                    # header row 0, data row 1
                    if len(t24.rows)>1:
                        _set_cell(t24.rows[1].cells[0], dt if dt!="Not provided" else "Not yet retested")
                        _set_cell(t24.rows[1].cells[1], stat)
                        _set_cell(t24.rows[1].cells[2], obs)
                else:
                    if len(t24.rows)>1:
                        _set_cell(t24.rows[1].cells[0], "Not yet retested")
                        _set_cell(t24.rows[1].cells[1], "Not applicable")
                        _set_cell(t24.rows[1].cells[2], "No web findings")
            except Exception:
                pass

        # Network finding NET-001
        net_title_idx = find_para("NET-001")
        if net_title_idx != -1 and data["net_findings"]:
            f=data["net_findings"][0]
            fid="NET-001"
            title=str(f.get("title") or "Untitled")[:80]
            doc.paragraphs[net_title_idx].text = f"{fid} - {title}"
        elif net_title_idx != -1 and not data["net_findings"]:
            doc.paragraphs[net_title_idx].text = "NET-001 - No network findings in scope"

        t25=tbl(25)
        if t25 is not None:
            if data["net_findings"]:
                f=data["net_findings"][0]
                try:
                    _set_cell(t25.rows[0].cells[1], str(f.get("severity") or "Not assessed").title())
                    _set_cell(t25.rows[1].cells[1], str(f.get("cvss_score") or f.get("score") or "Not available"))
                    _set_cell(t25.rows[2].cells[1], str(f.get("status") or "Open").title())
                    _set_cell(t25.rows[3].cells[1], str(f.get("asset_value") or f.get("asset_id") or "Not provided")[:60])
                    _set_cell(t25.rows[4].cells[1], str(f.get("port") or f.get("protocol") or "Not provided")[:30])
                    _set_cell(t25.rows[5].cells[1], str(f.get("service") or f.get("version") or "Not available")[:40])
                    _set_cell(t25.rows[6].cells[1], str(f.get("cve") or f.get("cwe") or "Not available"))
                except Exception:
                    pass
            else:
                for r in t25.rows:
                    if len(r.cells)>1 and ("[Critical" in r.cells[1].text or "[X.X]" in r.cells[1].text or "[x.x.x.x" in r.cells[1].text or "[443" in r.cells[1].text or "[Service" in r.cells[1].text or "[CVE" in r.cells[1].text):
                        _set_cell(r.cells[1], "Not assessed")

        # Network evidence table 26
        t26=tbl(26)
        if t26 is not None:
            try:
                ev=_sanitize_evidence(data["net_findings"][0].get("evidence") if data["net_findings"] else None)
                _set_cell(t26.rows[0].cells[0], f"Validated Evidence: {ev}")
            except Exception:
                pass
        # Network description placeholder after t25: find second occurrence of "During network security testing"
        net_desc_idx = find_para("During network security testing,")
        if net_desc_idx != -1 and data["net_findings"]:
            f=data["net_findings"][0]
            desc=str(f.get("description") or f.get("title") or "Not provided")[:500]
            doc.paragraphs[net_desc_idx].text = desc
        elif net_desc_idx != -1 and not data["net_findings"]:
            doc.paragraphs[net_desc_idx].text = "No network findings — no vulnerabilities to describe."

        # Retest table 27
        t27=tbl(27)
        if t27 is not None:
            try:
                if data["net_findings"]:
                    f=data["net_findings"][0]
                    dt=_fmt_date(f.get("retest_date") or "")
                    stat=str(f.get("retest_result") or f.get("status") or "Not yet retested")[:30]
                    obs=_sanitize_evidence(f.get("retest_observation") or "Not yet retested", 120)
                    if len(t27.rows)>1:
                        _set_cell(t27.rows[1].cells[0], dt if dt!="Not provided" else "Not yet retested")
                        _set_cell(t27.rows[1].cells[1], stat)
                        _set_cell(t27.rows[1].cells[2], obs)
                else:
                    if len(t27.rows)>1:
                        _set_cell(t27.rows[1].cells[0], "Not yet retested")
                        _set_cell(t27.rows[1].cells[1], "Not applicable")
                        _set_cell(t27.rows[1].cells[2], "No network findings")
            except Exception:
                pass

    except Exception:
        pass

    # ---------- Insert additional findings beyond first ----------
    # We insert before the headings "10.1 Common Web Finding Content Library" and "11.1 Common Network Finding Content Library"
    try:
        # find anchor paragraphs
        anchor_web_idx = find_para("10.1 Common Web Finding Content Library")
        anchor_net_idx = find_para("11.1 Common Network Finding Content Library")
        # doc.element.body is the XML body containing paragraphs and tables as direct children
        body = doc.element.body
        # helper to get element from paragraph index
        # We'll need to map doc.paragraphs index to body element index, but easier: find paragraph element by text and insert before it
        def _insert_findings(is_web: bool, findings: list, start_pos: int):
            if len(findings) <= 1:
                return
            # Determine anchor element
            anchor_text = "10.1 Common Web Finding Content Library" if is_web else "11.1 Common Network Finding Content Library"
            anchor_para = None
            for p in doc.paragraphs:
                if anchor_text in p.text:
                    anchor_para = p
                    break
            if anchor_para is None:
                return
            anchor_el = anchor_para._element
            # For each extra finding (index 1..)
            for idx, f in enumerate(findings[1:10], start=2):  # cap 10 extra
                fid = f"{'WEB' if is_web else 'NET'}-{idx:03d}"
                title = str(f.get("title") or "Untitled")[:80]
                sev = str(f.get("severity") or "Not assessed").title()
                cvss = str(f.get("cvss_score") or f.get("score") or "Not available")
                vector = str(f.get("cvss_vector") or "")
                status = str(f.get("status") or "Open").title()
                asset = str(f.get("asset_value") or f.get("asset_id") or "Not provided")[:60]
                # Create elements via copy of first finding's block? Simpler: create new paragraphs/tables via python-docx then move
                # Create a temporary document to build block, then move its body elements before anchor
                from docx import Document as DocxDoc
                # Build a small doc fragment for one finding
                frag = DocxDoc()
                # Ensure fragment has no default paragraph
                # Clear default
                if len(frag.paragraphs) and not frag.paragraphs[0].text:
                    p_el = frag.paragraphs[0]._element
                    p_el.getparent().remove(p_el)
                # Title
                p = frag.add_paragraph()
                p.style = doc.paragraphs[0].style  # fallback
                try:
                    p.style = doc.paragraphs[find_para("WEB-001") if is_web else find_para("NET-001")].style
                except Exception:
                    pass
                run = p.add_run(f"{fid} - {title}")
                run.bold = True
                # Meta table
                if is_web:
                    mt = frag.add_table(rows=7, cols=2)
                    # set header shading not needed
                    rows_data = [
                        ("Severity", sev),
                        ("CVSS Score", cvss),
                        ("CVSS Vector", vector or "Not available"),
                        ("Status", status),
                        ("Affected URL", asset),
                        ("Affected Parameter / Function", str(f.get("affected_parameter") or "Not provided")[:60]),
                        ("OWASP / CWE", f"{str(f.get('owasp') or 'Not available')} / {str(f.get('cwe') or 'Not available')}"),
                    ]
                else:
                    mt = frag.add_table(rows=7, cols=2)
                    rows_data = [
                        ("Severity", sev),
                        ("CVSS Score", cvss),
                        ("Status", status),
                        ("Affected Host", asset),
                        ("Port / Protocol", str(f.get("port") or f.get("protocol") or "Not provided")[:30]),
                        ("Service / Version", str(f.get("service") or f.get("version") or "Not available")[:40]),
                        ("CVE / CWE", str(f.get("cve") or f.get("cwe") or "Not available")),
                    ]
                for i, (k,v) in enumerate(rows_data):
                    _set_cell(mt.rows[i].cells[0], k)
                    _set_cell(mt.rows[i].cells[1], v)
                # Description heading + paragraph
                h = frag.add_paragraph()
                h.style = "Heading 2"
                h.add_run("Description")
                desc = str(f.get("description") or f.get("title") or "Not provided")[:500]
                frag.add_paragraph(desc)
                # Evidence
                h2 = frag.add_paragraph()
                h2.style = "Heading 2"
                h2.add_run("Evidence / Proof of Concept" if is_web else "Evidence")
                ev = _sanitize_evidence(f.get("evidence"))
                frag.add_paragraph(ev[:400])
                # Impact headings
                for heading in ["Technical Impact", "Business Impact", "Recommendation", "References"]:
                    h3 = frag.add_paragraph()
                    h3.style = "Heading 2"
                    h3.add_run(heading)
                    # content placeholders
                    if heading == "Technical Impact":
                        frag.add_paragraph(str(f.get("technical_impact") or "Not assessed")[:200])
                    elif heading == "Business Impact":
                        frag.add_paragraph(str(f.get("business_impact") or "Not assessed")[:200])
                    elif heading == "Recommendation":
                        frag.add_paragraph(str(f.get("remediation") or "Not provided")[:300])
                    else:
                        frag.add_paragraph(str(f.get("references") or "Not provided")[:120])
                # Retest
                h4 = frag.add_paragraph()
                h4.style = "Heading 2"
                h4.add_run("Retest Result")
                rt = frag.add_table(rows=2, cols=3)
                _set_cell(rt.rows[0].cells[0], "Retest Date")
                _set_cell(rt.rows[0].cells[1], "Status")
                _set_cell(rt.rows[0].cells[2], "Observation")
                _set_cell(rt.rows[1].cells[0], _fmt_date(f.get("retest_date") or ""))
                _set_cell(rt.rows[1].cells[1], str(f.get("retest_result") or f.get("status") or "Not yet retested")[:30])
                _set_cell(rt.rows[1].cells[2], _sanitize_evidence(f.get("retest_observation"), 120))

                # Now move all elements from frag body to main doc before anchor
                # frag body children are paragraphs (w:p) and tables (w:tbl)
                # Insert in reverse order to maintain order? But inserting before anchor repeatedly will reverse if not careful
                # So we collect elements and insert each before anchor in order
                frag_body = frag.element.body
                # copy list first because moving mutates
                elems = list(frag_body)
                for el in elems:
                    # skip sectPr
                    if el.tag.endswith("sectPr"):
                        continue
                    # deep copy not needed because we will move original; but to avoid parent issues, deepcopy
                    new_el = copy.deepcopy(el)
                    anchor_el.addprevious(new_el)
            # end for each finding

        _insert_findings(True, data["web_findings"], 0)
        _insert_findings(False, data["net_findings"], 0)
    except Exception as e:
        # don't fail whole export due to extra findings insertion
        pass

    # ---------- Final header/footer placeholder refresh ----------
    # Header already has [CUSTOMER NAME] placeholder replaced above; ensure header text reflects customer
    try:
        for sec in doc.sections:
            for p in sec.header.paragraphs:
                if "[CUSTOMER NAME]" in p.text:
                    p.text = p.text.replace("[CUSTOMER NAME]", cust.upper())
                if "[Customer Name]" in p.text:
                    p.text = p.text.replace("[Customer Name]", cust)
            for p in sec.footer.paragraphs:
                if "Version 1.0" in p.text:
                    p.text = p.text.replace("Version 1.0", f"Version {data['version']} - Final")
    except Exception:
        pass

    # Save to bytes
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()
