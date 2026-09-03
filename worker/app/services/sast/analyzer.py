"""
S3 SAST Foundation Analyzer — Python only, deterministic, offline.
AST-based where practical, conservative.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Any

MAX_FILES = 500
MAX_FILE_SIZE = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".cache", ".pytest_cache", ".mypy_cache", ".tox"}

SECRET_KEYWORDS = {"password", "passwd", "secret", "api_key", "apikey", "token", "access_key", "secret_key", "private_key", "auth_token"}

# Severity and score mapping per spec: all high for S3/S3.1
RULE_META = {
    "SAST001": {"title": "Hardcoded secret", "description": "Hardcoded credential detected", "severity": "high", "score": 75, "remediation": "Remove hardcoded secret and use environment variables or secret management."},
    "SAST002": {"title": "Dangerous dynamic code execution", "description": "Use of eval/exec with dynamic input", "severity": "high", "score": 75, "remediation": "Avoid eval/exec; use safe alternatives."},
    "SAST003": {"title": "Subprocess shell execution", "description": "subprocess with shell=True", "severity": "high", "score": 75, "remediation": "Avoid shell=True; use argument list without shell."},
    "SAST004": {"title": "Unsafe SQL construction", "description": "SQL query built via string concatenation/interpolation", "severity": "high", "score": 75, "remediation": "Use parameterized queries / prepared statements."},
    "SAST005": {"title": "Unsafe deserialization", "description": "Unsafe pickle deserialization", "severity": "high", "score": 75, "remediation": "Avoid pickle for untrusted data; use json."},
    "JS001": {"title": "Dangerous eval", "description": "Dangerous eval with dynamic input", "severity": "high", "score": 75, "remediation": "Avoid eval; use safe alternatives."},
    "JS002": {"title": "Function constructor", "description": "Dynamic Function constructor", "severity": "high", "score": 75, "remediation": "Avoid Function constructor with dynamic input."},
    "JS003": {"title": "Hardcoded secret", "description": "Hardcoded credential detected", "severity": "high", "score": 75, "remediation": "Remove hardcoded secret and use environment variables."},
    "JS004": {"title": "Dangerous child process execution", "description": "child_process exec with dynamic input", "severity": "high", "score": 75, "remediation": "Avoid child_process.exec with dynamic input."},
    "JS005": {"title": "Unsafe SQL construction", "description": "SQL query built via string concatenation/interpolation", "severity": "high", "score": 75, "remediation": "Use parameterized queries."},
    "JS006": {"title": "Potential Server-Side Request Forgery", "description": "HTTP request uses user-controlled data", "severity": "high", "score": 75, "remediation": "Validate and sanitize user-controlled URLs."},
    "JS007": {"title": "Potential Cross-Site Scripting", "description": "Dangerous DOM sink with dynamic input", "severity": "high", "score": 75, "remediation": "Encode output and avoid innerHTML with untrusted data."},
    "JS008": {"title": "Hardcoded AWS Access Key", "description": "Hardcoded AWS Access Key ID detected", "severity": "critical", "score": 90, "remediation": "Remove hardcoded AWS key and use IAM roles or secret management."},
    "JAVA001": {"title": "Java Runtime Command Execution", "description": "Runtime command execution", "severity": "high", "score": 75, "remediation": "Validate input and avoid Runtime.exec with untrusted data."},
    "JAVA002": {"title": "Unsafe Java Deserialization", "description": "Unsafe Java deserialization via ObjectInputStream", "severity": "high", "score": 75, "remediation": "Avoid Java deserialization of untrusted data."},
    "JAVA003": {"title": "Potential Java SQL Injection", "description": "SQL query built via string concatenation", "severity": "high", "score": 75, "remediation": "Use prepared statements."},
    "JAVA004": {"title": "Hardcoded Java Secret", "description": "Hardcoded credential detected", "severity": "high", "score": 75, "remediation": "Remove hardcoded secret."},
    "JAVA005": {"title": "Weak Java Cryptography", "description": "Weak cryptographic algorithm", "severity": "medium", "score": 50, "remediation": "Use strong cryptography (e.g., AES/GCM, SHA-256)."},
    "GO001": {"title": "Go Command Execution", "description": "Go command execution via os/exec", "severity": "high", "score": 75, "remediation": "Validate input and avoid exec.Command with untrusted data."},
    "GO002": {"title": "Potential Go SQL Injection", "description": "SQL query built via string concatenation", "severity": "high", "score": 75, "remediation": "Use parameterized queries."},
    "GO003": {"title": "Hardcoded Go Secret", "description": "Hardcoded credential detected", "severity": "high", "score": 75, "remediation": "Remove hardcoded secret."},
    "GO004": {"title": "Weak Go Cryptography", "description": "Weak cryptographic algorithm", "severity": "medium", "score": 50, "remediation": "Use strong crypto."},
    "GO005": {"title": "Insecure Go TLS Configuration", "description": "Insecure TLS InsecureSkipVerify", "severity": "high", "score": 75, "remediation": "Do not set InsecureSkipVerify true."},
    "PY006": {"title": "Potential Server-Side Request Forgery", "description": "HTTP request with user-controlled URL", "severity": "high", "score": 75, "remediation": "Validate and sanitize user-controlled URLs."},
    "PY007": {"title": "Potential Cross-Site Scripting", "description": "Unsafe HTML rendering via render_template_string", "severity": "high", "score": 75, "remediation": "Avoid render_template_string with untrusted data."},
    "PY008": {"title": "Hardcoded AWS Access Key", "description": "Hardcoded AWS Access Key ID detected", "severity": "critical", "score": 90, "remediation": "Remove hardcoded AWS key and use IAM roles."},
    "PY009": {"title": "Unsafe HTML Markup", "description": "Potentially unsafe use of markupsafe.Markup with user-controlled input", "severity": "high", "score": 75, "remediation": "Avoid Markup with untrusted data; escape correctly."},
    "PY010": {"title": "Command Injection", "description": "Command execution with user-controlled input", "severity": "high", "score": 75, "remediation": "Validate input and avoid shell execution with untrusted data."},
    "JAVA006": {"title": "Potential Java SSRF", "description": "HTTP request with user-controlled URL", "severity": "high", "score": 75, "remediation": "Validate user-controlled URLs."},
    "JAVA007": {"title": "Potential Java XSS", "description": "Unsafe Java HTML output", "severity": "high", "score": 75, "remediation": "Encode output."},
    "JAVA008": {"title": "Hardcoded AWS Access Key", "description": "Hardcoded AWS Access Key ID detected", "severity": "critical", "score": 90, "remediation": "Remove hardcoded AWS key."},
    "JAVA009": {"title": "Java Command Execution", "description": "Request-controlled command execution", "severity": "high", "score": 75, "remediation": "Validate input and avoid Runtime.exec with untrusted data."},
    "GO006": {"title": "Potential Go SSRF", "description": "HTTP request with user-controlled URL", "severity": "high", "score": 75, "remediation": "Validate user-controlled URLs."},
    "GO007": {"title": "Potential Go XSS", "description": "Unsafe HTML conversion", "severity": "high", "score": 75, "remediation": "Avoid template.HTML with untrusted data."},
    "GO008": {"title": "Hardcoded AWS Access Key", "description": "Hardcoded AWS Access Key ID detected", "severity": "critical", "score": 90, "remediation": "Remove hardcoded AWS key."},
    "GO009": {"title": "Go Command Injection", "description": "Request-controlled command execution via exec.Command", "severity": "high", "score": 75, "remediation": "Validate input and avoid exec.Command with untrusted data."},
    "JS009": {"title": "Potential Cross-Site Scripting via document.write", "description": "document.write with user-controlled input", "severity": "high", "score": 75, "remediation": "Avoid document.write with untrusted data."},
}

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
}

class SASTAnalyzer:
    def analyze(self, target: str | Path) -> dict[str, Any]:
        target_path = Path(target)
        files: list[Path] = []
        total_bytes = 0
        files_skipped = 0
        errors: list[dict] = []

        if target_path.is_file() and target_path.suffix.lower() in SUPPORTED_EXTENSIONS:
            files = [target_path]
        elif target_path.is_dir():
            for root, dirs, filenames in os.walk(target_path, topdown=True):
                # deterministic: sort dirs and files (do not filter ignored dirs here; count skipped files explicitly)
                dirs[:] = sorted(dirs)
                filenames = sorted(filenames)
                for fname in filenames:
                    ext = Path(fname).suffix.lower()
                    if ext not in SUPPORTED_EXTENSIONS:
                        continue
                    fpath = Path(root) / fname
                    # skip if any part is ignored
                    if any(part in IGNORED_DIRS for part in fpath.parts):
                        files_skipped += 1
                        continue
                    if any(part.startswith(".") for part in fpath.parts):
                        files_skipped += 1
                        continue
                    # skip symlinks outside tree
                    try:
                        if fpath.is_symlink():
                            # resolve and check if outside target
                            resolved = fpath.resolve()
                            try:
                                resolved.relative_to(target_path.resolve())
                            except ValueError:
                                files_skipped += 1
                                continue
                    except Exception:
                        pass
                    try:
                        size = fpath.stat().st_size
                    except Exception:
                        files_skipped += 1
                        continue
                    if size > MAX_FILE_SIZE:
                        files_skipped += 1
                        continue
                    if total_bytes + size > MAX_TOTAL_BYTES:
                        files_skipped += 1
                        continue
                    if len(files) >= MAX_FILES:
                        files_skipped += 1
                        continue
                    total_bytes += size
                    files.append(fpath)
        else:
            # target is not a valid file/dir -> treat as error
            return {
                "scanner": "sast",
                "findings": [],
                "errors": [{"file": str(target), "error_type": "invalid_target", "message": "Target must be a Python file or directory"}],
                "metadata": {"language": "python", "files_scanned": 0, "files_skipped": 0, "rules": sorted(RULE_META.keys())}
            }

        # Ensure deterministic file order
        files = sorted(files, key=lambda p: str(p))

        findings: list[dict] = []
        files_scanned = 0

        for fpath in files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="strict")
            except Exception as e:
                errors.append({"file": str(fpath), "error_type": "read_error", "message": str(e)})
                continue
            files_scanned += 1
            ext = fpath.suffix.lower()
            language = SUPPORTED_EXTENSIONS.get(ext, "python")
            lines = content.splitlines()
            rel_path = str(fpath.relative_to(target_path).as_posix() if target_path.is_dir() else fpath.name)

            # Language dispatch
            if language == "python":
                try:
                    tree = ast.parse(content, filename=str(fpath))
                except SyntaxError as e:
                    errors.append({"file": str(fpath), "error_type": "syntax_error", "message": str(e), "language": language})
                    continue
                except Exception as e:
                    errors.append({"file": str(fpath), "error_type": "parse_error", "message": str(e), "language": language})
                    continue
                file_findings = self._analyze_ast(tree, content, rel_path, lines)
            elif language in ("javascript", "typescript"):
                file_findings = self._analyze_js(content, rel_path, lines, language)
            elif language == "java":
                file_findings = self._analyze_java(content, rel_path, lines, language)
            elif language == "go":
                file_findings = self._analyze_go(content, rel_path, lines, language)
            else:
                file_findings = []
            findings.extend(file_findings)

        # Deterministic ordering
        findings.sort(key=lambda f: (f["file"], f["line"], f["rule_id"]))

        # Determine languages present for metadata
        langs = set()
        for f in files:
            langs.add(SUPPORTED_EXTENSIONS.get(f.suffix.lower(), "python"))
        if not langs:
            langs = {"python"}

        return {
            "scanner": "sast",
            "findings": findings,
            "errors": errors,
            "metadata": {
                "language": "python" if langs == {"python"} else ",".join(sorted(langs)),
                "languages": sorted(langs),
                "files_scanned": files_scanned,
                "files_skipped": files_skipped,
                "rules": sorted(RULE_META.keys()),
            }
        }

    def _analyze_ast(self, tree: ast.AST, content: str, rel_path: str, lines: list[str]) -> list[dict]:
        findings = []
        # Use visitor
        for node in ast.walk(tree):
            # SAST002: eval/exec
            if isinstance(node, ast.Call):
                func = node.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                if func_name in ("eval", "exec"):
                    line = getattr(node, 'lineno', 1)
                    col = getattr(node, 'col_offset', 0)
                    evidence = self._bounded_evidence(lines, line)
                    findings.append(self._make_finding("SAST002", rel_path, line, col, evidence, node))
                # SAST005: pickle.loads
                if isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name) and func.value.id == "pickle" and func.attr in ("loads", "load"):
                        line = getattr(node, 'lineno', 1)
                        col = getattr(node, 'col_offset', 0)
                        evidence = self._bounded_evidence(lines, line)
                        findings.append(self._make_finding("SAST005", rel_path, line, col, evidence, node))
                    # SAST003: subprocess shell
                    if isinstance(func.value, ast.Name) and func.value.id == "subprocess" and func.attr in ("run", "call", "Popen", "check_call", "check_output"):
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                line = getattr(node, 'lineno', 1)
                                col = getattr(node, 'col_offset', 0)
                                evidence = self._bounded_evidence(lines, line)
                                findings.append(self._make_finding("SAST003", rel_path, line, col, evidence, node))
                                break
            # SAST004: SQL construction — outside Call to handle JoinedStr/BinOp directly
            if isinstance(node, ast.JoinedStr):
                raw = ast.get_source_segment(content, node) or ""
                if "select" in raw.lower() and "from" in raw.lower():
                    line = getattr(node, 'lineno', 1)
                    col = getattr(node, 'col_offset', 0)
                    evidence = self._bounded_evidence(lines, line)
                    findings.append(self._make_finding("SAST004", rel_path, line, col, evidence, node))
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = node.left
                right = node.right
                left_str = ""
                if isinstance(left, ast.Constant) and isinstance(left.value, str):
                    left_str = left.value.lower()
                elif isinstance(left, ast.JoinedStr):
                    left_str = (ast.get_source_segment(content, left) or "").lower()
                if "select" in left_str and "from" in left_str:
                    if not (isinstance(right, ast.Constant) and isinstance(right.value, str)):
                        line = getattr(node, 'lineno', 1)
                        col = getattr(node, 'col_offset', 0)
                        evidence = self._bounded_evidence(lines, line)
                        findings.append(self._make_finding("SAST004", rel_path, line, col, evidence, node))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                func_val = node.func.value
                if isinstance(func_val, ast.Constant) and isinstance(func_val.value, str) and "select" in func_val.value.lower():
                    line = getattr(node, 'lineno', 1)
                    col = getattr(node, 'col_offset', 0)
                    evidence = self._bounded_evidence(lines, line)
                    findings.append(self._make_finding("SAST004", rel_path, line, col, evidence, node))

            # SAST001: hardcoded secret
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        for kw in SECRET_KEYWORDS:
                            if kw in name_lower:
                                # Check value is constant string
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    val = node.value.value
                                    if len(val) >= 4 and val.strip() != "":
                                        line = getattr(node, 'lineno', 1)
                                        col = getattr(node, 'col_offset', 0)
                                        evidence = self._bounded_evidence(lines, line)
                                        findings.append(self._make_finding("SAST001", rel_path, line, col, evidence, node))
                                break
            # AnnAssign for typed assignments like password: str = "secret"
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name_lower = node.target.id.lower()
                for kw in SECRET_KEYWORDS:
                    if kw in name_lower:
                        if node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            if len(val) >= 4 and val.strip() != "":
                                line = getattr(node, 'lineno', 1)
                                col = getattr(node, 'col_offset', 0)
                                evidence = self._bounded_evidence(lines, line)
                                findings.append(self._make_finding("SAST001", rel_path, line, col, evidence, node))
                        break
            # PY006: SSRF — requests.get/post/request, urllib.request.urlopen with request.* user-controlled
            if isinstance(node, ast.Call):
                is_requests = False
                is_urllib = False
                func = node.func
                if isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name) and func.value.id == "requests" and func.attr in ("get", "post", "request"):
                        is_requests = True
                    elif isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name) and func.value.value.id == "urllib" and func.value.attr == "request" and func.attr == "urlopen":
                        is_urllib = True
                    elif isinstance(func.value, ast.Name) and func.attr == "urlopen":
                        is_urllib = True
                if is_requests or is_urllib:
                    for arg in node.args:
                        src = ast.get_source_segment(content, arg) or ""
                        if re.search(r'request\.(?:args|form|json|query_params|path_params)\.get\s*\(', src):
                            line = getattr(node, 'lineno', 1)
                            col = getattr(node, 'col_offset', 0)
                            evidence = self._bounded_evidence(lines, line)
                            findings.append(self._make_finding("PY006", rel_path, line, col, evidence, node))
                            break
                        if re.search(r'request\.(args|form|json)\s*\[', src):
                            line = getattr(node, 'lineno', 1)
                            col = getattr(node, 'col_offset', 0)
                            evidence = self._bounded_evidence(lines, line)
                            findings.append(self._make_finding("PY006", rel_path, line, col, evidence, node))
                            break
            # PY007: XSS — render_template_string
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "render_template_string":
                    line = getattr(node, 'lineno', 1)
                    col = getattr(node, 'col_offset', 0)
                    evidence = self._bounded_evidence(lines, line)
                    findings.append(self._make_finding("PY007", rel_path, line, col, evidence, node))
                elif isinstance(func, ast.Attribute) and func.attr == "render_template_string":
                    line = getattr(node, 'lineno', 1)
                    col = getattr(node, 'col_offset', 0)
                    evidence = self._bounded_evidence(lines, line)
                    findings.append(self._make_finding("PY007", rel_path, line, col, evidence, node))
            # PY009: Markup with request-controlled input
            if isinstance(node, ast.Call):
                func = node.func
                is_markup = False
                if isinstance(func, ast.Name) and func.id == "Markup":
                    is_markup = True
                elif isinstance(func, ast.Attribute) and func.attr == "Markup":
                    is_markup = True
                if is_markup:
                    for arg in node.args:
                        src = ast.get_source_segment(content, arg) or ""
                        if re.search(r'request\.(?:args|form|json|query_params|path_params)', src):
                            line = getattr(node, 'lineno', 1)
                            col = getattr(node, 'col_offset', 0)
                            evidence = self._bounded_evidence(lines, line)
                            findings.append(self._make_finding("PY009", rel_path, line, col, evidence, node))
                            break
            # PY010: Command Injection — os.system(request...), subprocess.* with shell=True and request
            if isinstance(node, ast.Call):
                func = node.func
                is_os_system = isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "os" and func.attr == "system"
                is_subprocess = isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "subprocess" and func.attr in ("call", "run", "Popen", "check_call", "check_output")
                if is_os_system:
                    for arg in node.args:
                        src = ast.get_source_segment(content, arg) or ""
                        if re.search(r'request\.(?:args|form|json|query_params|path_params)', src):
                            line = getattr(node, 'lineno', 1)
                            col = getattr(node, 'col_offset', 0)
                            evidence = self._bounded_evidence(lines, line)
                            findings.append(self._make_finding("PY010", rel_path, line, col, evidence, node))
                            break
                if is_subprocess:
                    has_shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                    if has_shell_true:
                        for arg in node.args:
                            src = ast.get_source_segment(content, arg) or ""
                            if re.search(r'request\.(?:args|form|json|query_params|path_params)', src):
                                line = getattr(node, 'lineno', 1)
                                col = getattr(node, 'col_offset', 0)
                                evidence = self._bounded_evidence(lines, line)
                                findings.append(self._make_finding("PY010", rel_path, line, col, evidence, node))
                                break
        # PY008: AWS Access Key — AKIA[0-9A-Z]{16} (after AST walk, line-level for Python)
        for idx, raw_line in enumerate(lines):
            if re.search(r'AKIA[0-9A-Z]{16}', raw_line):
                stripped = raw_line.strip()
                if stripped.startswith("#"):
                    continue
                line_no = idx + 1
                if not any(f["line"] == line_no and f["rule_id"] == "PY008" for f in findings):
                    # Use last node for evidence fallback
                    evidence = self._bounded_evidence(lines, line_no)
                    # Create a dummy node for _make_finding
                    dummy = ast.Constant(value=raw_line)
                    dummy.lineno = line_no
                    dummy.col_offset = raw_line.find("AKIA")
                    findings.append(self._make_finding("PY008", rel_path, line_no, raw_line.find("AKIA"), evidence, dummy))
        return findings

    def _make_finding(self, rule_id: str, file: str, line: int, col: int, evidence: str, node: ast.AST) -> dict:
        meta = RULE_META[rule_id]
        # Determine language from rule_id
        lang = "javascript" if rule_id.startswith("JS") else "python"
        return {
            "rule_id": rule_id,
            "title": meta["title"],
            "description": meta["description"],
            "severity": meta["severity"],
            "score": meta["score"],
            "file": file,
            "line": line,
            "column": col,
            "evidence": evidence[:500],
            "remediation": meta["remediation"],
            "metadata": {
                "rule_id": rule_id,
                "file": file,
                "line": line,
                "column": col,
                "language": lang,
            }
        }

    def _make_js_finding(self, rule_id: str, file: str, line: int, col: int, evidence: str) -> dict:
        meta = RULE_META[rule_id]
        lang = "typescript" if file.endswith((".ts", ".tsx")) else "javascript"
        return {
            "rule_id": rule_id,
            "title": meta["title"],
            "description": meta["description"],
            "severity": meta["severity"],
            "score": meta["score"],
            "file": file,
            "line": line,
            "column": col,
            "evidence": evidence[:500],
            "remediation": meta["remediation"],
            "metadata": {
                "rule_id": rule_id,
                "file": file,
                "line": line,
                "column": col,
                "language": lang,
            }
        }

    def _analyze_js(self, content: str, rel_path: str, lines: list[str], language: str) -> list[dict]:
        findings = []
        # Prepare line-level comment/string handling
        in_block_comment = False
        for idx, raw_line in enumerate(lines):
            line_no = idx + 1
            line = raw_line

            # Handle block comments /* ... */
            if "/*" in line:
                in_block_comment = True
            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                continue
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            # Remove // comment part for analysis (but keep evidence original)
            code_part = line.split("//")[0]
            # For strings, we will use regex that avoids matches inside quotes via placeholder
            # Create a version where string literals are replaced with placeholders to avoid false positives
            # Simple: replace "..." and '...' and `...` (but keep template interpolation)
            placeholder = re.sub(r'"[^"]*"', '""', code_part)
            placeholder = re.sub(r"'[^']*'", "''", placeholder)
            # For template literals, keep ${} but replace quoted parts?
            # Keep placeholder for matching, but original evidence uses raw_line

            # JS001: eval(
            if re.search(r'\beval\s*\(', placeholder):
                # Ensure not inside string placeholder already, and not a comment
                # Check that eval is not part of a larger word and not inside string literal original
                # Our placeholder already removed quoted strings, so if still matches, it's code
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS001", rel_path, line_no, line.find("eval"), evidence))

            # JS002: new Function or Function(
            if re.search(r'\bnew\s+Function\s*\(', placeholder) or re.search(r'(?<!\bnew\s)\bFunction\s*\(', placeholder):
                # The second regex ensures Function( not preceded by new (to avoid double count)
                # Actually first covers new Function, second covers Function without new
                # Use simpler: check for Function(
                if re.search(r'\bFunction\s*\(', placeholder):
                    # Distinguish new vs plain, but both are JS002
                    evidence = self._bounded_evidence(lines, line_no)
                    # Avoid duplicate if both match same line (new Function will match both)
                    if not any(f["line"] == line_no and f["rule_id"] == "JS002" for f in findings):
                        findings.append(self._make_js_finding("JS002", rel_path, line_no, line.find("Function"), evidence))

            # JS003: hardcoded secret — (const|let|var) <name> = "value"
            m = re.search(r'\b(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*["\']([^"\']{4,})["\']', code_part)
            if m:
                var_name = m.group(1).lower()
                for kw in SECRET_KEYWORDS:
                    if kw in var_name:
                        evidence = self._bounded_evidence(lines, line_no)
                        findings.append(self._make_js_finding("JS003", rel_path, line_no, line.find(var_name), evidence))
                        break

            # JS004: child_process.exec / execSync
            if re.search(r'child_process\s*\.\s*exec(?:Sync)?\s*\(', placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS004", rel_path, line_no, line.find("child_process"), evidence))

            # JS005: SQL string construction
            # Check for SELECT ... FROM with + or template ${}
            lower_raw = raw_line.lower()
            if "select" in lower_raw and "from" in lower_raw:
                # Check for + concatenation or template interpolation
                if "+" in code_part and re.search(r'"[^"]*select[^"]*"', lower_raw):
                    # Ensure it's not just a constant string alone without dynamic part
                    # If line contains + and SELECT, it's dynamic
                    evidence = self._bounded_evidence(lines, line_no)
                    findings.append(self._make_js_finding("JS005", rel_path, line_no, lower_raw.find("select"), evidence))
                elif "${" in line:
                    # Template literal with interpolation containing SELECT
                    if re.search(r'`[^`]*select[^`]*\$\{', lower_raw):
                        evidence = self._bounded_evidence(lines, line_no)
                        findings.append(self._make_js_finding("JS005", rel_path, line_no, lower_raw.find("select"), evidence))

            # JS006: SSRF — fetch/axios/http(s) with req.query|body|params
            ssrf_sources = r'(?:req|request)\s*\.\s*(?:query|body|params)\s*\.'
            if re.search(r'\bfetch\s*\(\s*' + ssrf_sources, placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS006", rel_path, line_no, line.find("fetch"), evidence))
            elif re.search(r'\baxios\s*\.\s*get\s*\(\s*' + ssrf_sources, placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS006", rel_path, line_no, line.find("axios"), evidence))
            elif re.search(r'\baxios\s*\.\s*post\s*\(\s*' + ssrf_sources, placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS006", rel_path, line_no, line.find("axios"), evidence))
            elif re.search(r'\baxios\s*\(\s*' + ssrf_sources, placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS006", rel_path, line_no, line.find("axios"), evidence))
            elif re.search(r'\bhttps?\s*\.\s*get\s*\(\s*' + ssrf_sources, placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS006", rel_path, line_no, line.find("http"), evidence))
            elif re.search(r'\bhttps?\s*\.\s*request\s*\(\s*' + ssrf_sources, placeholder):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS006", rel_path, line_no, line.find("http"), evidence))

            # JS007: XSS — innerHTML/outerHTML/insertAdjacentHTML/dangerouslySetInnerHTML
            # innerHTML = dynamic (not static string)
            if re.search(r'\.innerHTML\s*=', placeholder):
                # Check if RHS is static string literal (placeholder has "" )
                if not re.search(r'\.innerHTML\s*=\s*""', placeholder) and not re.search(r"\.innerHTML\s*=\s*''", placeholder):
                    # Ensure RHS contains dynamic content (not just quoted string)
                    # If original code_part has innerHTML = "<p>..." then placeholder would be = "" -> skip, else dynamic -> flag
                    if not re.search(r'\.innerHTML\s*=\s*["\']<', code_part):
                        evidence = self._bounded_evidence(lines, line_no)
                        findings.append(self._make_js_finding("JS007", rel_path, line_no, line.find("innerHTML"), evidence))
            if re.search(r'\.outerHTML\s*=', placeholder):
                if not re.search(r'\.outerHTML\s*=\s*""', placeholder):
                    evidence = self._bounded_evidence(lines, line_no)
                    findings.append(self._make_js_finding("JS007", rel_path, line_no, line.find("outerHTML"), evidence))
            if re.search(r'\.insertAdjacentHTML\s*\(', placeholder):
                # Check second arg is dynamic (not just static string)
                # If placeholder contains insertAdjacentHTML("beforeend", "") -> static, skip
                if not re.search(r'insertAdjacentHTML\s*\(\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']*["\']\s*\)', placeholder):
                    evidence = self._bounded_evidence(lines, line_no)
                    findings.append(self._make_js_finding("JS007", rel_path, line_no, line.find("insertAdjacentHTML"), evidence))
            if "dangerouslySetInnerHTML" in code_part and "__html" in code_part:
                # Check for dynamic __html: userInput vs static "<p>..."
                # If __html: "static" then placeholder would have "" -> skip
                if re.search(r'__html\s*:\s*[^"\']', code_part) and not re.search(r'__html\s*:\s*["\']<', code_part):
                    evidence = self._bounded_evidence(lines, line_no)
                    findings.append(self._make_js_finding("JS007", rel_path, line_no, line.find("dangerouslySetInnerHTML"), evidence))

            # JS008: AWS Access Key AKIA[0-9A-Z]{16}
            if re.search(r'AKIA[0-9A-Z]{16}', raw_line):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_js_finding("JS008", rel_path, line_no, raw_line.find("AKIA"), evidence))

            # JS009: document.write / writeln with request-controlled input
            if re.search(r'document\s*\.\s*write(?:ln)?\s*\(', placeholder):
                if re.search(r'req\s*\.\s*(?:query|body|params)\s*\.|request\s*\.\s*(?:query|body|params)\s*\.|location\s*\.\s*(?:search|hash)|URLSearchParams', code_part):
                    evidence = self._bounded_evidence(lines, line_no)
                    # Avoid static string: placeholder would be "" if static, but we already check for dynamic sources
                    findings.append(self._make_js_finding("JS009", rel_path, line_no, line.find("document.write") if "document.write" in line else line.find("document.writeln"), evidence))

        return findings

    def _analyze_java(self, content: str, rel_path: str, lines: list[str], language: str) -> list[dict]:
        findings = []
        in_block_comment = False
        for idx, raw_line in enumerate(lines):
            line_no = idx + 1
            line = raw_line
            if "/*" in line:
                in_block_comment = True
            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                continue
            if line.strip().startswith("//"):
                continue
            code_part = line.split("//")[0]
            placeholder = re.sub(r'"[^"]*"', '""', code_part)
            placeholder = re.sub(r"'[^']*'", "''", placeholder)
            # JAVA001: Runtime.getRuntime().exec or ProcessBuilder
            if re.search(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', placeholder) or re.search(r'\bnew\s+ProcessBuilder\s*\(', placeholder):
                findings.append(self._make_java_finding("JAVA001", rel_path, line_no, line.find("Runtime") if "Runtime" in line else line.find("ProcessBuilder"), self._bounded_evidence(lines, line_no)))
            # JAVA002: ObjectInputStream / readObject
            if re.search(r'\bObjectInputStream\b', placeholder) or re.search(r'\breadObject\s*\(', placeholder):
                # Check not just import string
                if re.search(r'ObjectInputStream', placeholder):
                    findings.append(self._make_java_finding("JAVA002", rel_path, line_no, line.find("ObjectInputStream") if "ObjectInputStream" in line else line.find("readObject"), self._bounded_evidence(lines, line_no)))
                elif re.search(r'\breadObject\s*\(', placeholder):
                    findings.append(self._make_java_finding("JAVA002", rel_path, line_no, line.find("readObject"), self._bounded_evidence(lines, line_no)))
            # JAVA003: SQL injection via SELECT/INSERT/UPDATE/DELETE + concatenation
            lower_raw = raw_line.lower()
            if any(kw in lower_raw for kw in ("select", "insert", "update", "delete")) and ("+" in code_part or "${" in line):
                # Check for SQL keyword with string concat
                if re.search(r'"[^"]*(select|insert|update|delete)[^"]*"', lower_raw) and "+" in code_part:
                    findings.append(self._make_java_finding("JAVA003", rel_path, line_no, lower_raw.find("select") if "select" in lower_raw else 0, self._bounded_evidence(lines, line_no)))
                elif "${" in line and any(kw in lower_raw for kw in ("select", "insert")):
                    findings.append(self._make_java_finding("JAVA003", rel_path, line_no, lower_raw.find("select") if "select" in lower_raw else 0, self._bounded_evidence(lines, line_no)))
            # JAVA004: Hardcoded secret — String assignment with secret keyword
            m = re.search(r'\b(?:String\s+)?([A-Za-z0-9_]+)\s*=\s*"([^"]{4,})"', code_part)
            if m:
                var_name = m.group(1).lower()
                for kw in SECRET_KEYWORDS:
                    if kw in var_name:
                        findings.append(self._make_java_finding("JAVA004", rel_path, line_no, line.find(var_name), self._bounded_evidence(lines, line_no)))
                        break
            # JAVA005: Weak crypto MD5/SHA1/DES/3DES/RC4
            if re.search(r'MD5|SHA-?1|DES|3DES|RC4', code_part, re.IGNORECASE):
                if re.search(r'getInstance\s*\(\s*"[^"]*(?:MD5|SHA-?1|DES|3DES|RC4)[^"]*"\s*\)', code_part, re.IGNORECASE):
                    findings.append(self._make_java_finding("JAVA005", rel_path, line_no, line.find("MD5") if "MD5" in line else 0, self._bounded_evidence(lines, line_no)))
            # JAVA006: SSRF — URL/HttpClient with request.getParameter etc.
            if re.search(r'new\s+URL\s*\(', placeholder) or re.search(r'HttpClient|URLConnection|HttpURLConnection', placeholder):
                if re.search(r'request\s*\.\s*getParameter|getQueryString|getHeader', code_part):
                    findings.append(self._make_java_finding("JAVA006", rel_path, line_no, line.find("URL") if "URL" in line else 0, self._bounded_evidence(lines, line_no)))
                elif re.search(r'req\s*\.\s*getParameter', code_part):
                    findings.append(self._make_java_finding("JAVA006", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            elif re.search(r'request\s*\.\s*getParameter', code_part) and re.search(r'new\s+URL|openConnection|HttpClient', placeholder):
                findings.append(self._make_java_finding("JAVA006", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            # JAVA007: XSS — response.getWriter().write with request input
            if re.search(r'getWriter\s*\(\s*\)\s*\.\s*write\s*\(', placeholder) or re.search(r'print\s*\(\s*.*request\.getParameter', code_part):
                if re.search(r'request\s*\.\s*getParameter', code_part):
                    findings.append(self._make_java_finding("JAVA007", rel_path, line_no, line.find("write") if "write" in line else 0, self._bounded_evidence(lines, line_no)))
            elif re.search(r'\.write\s*\(.*request\.getParameter', code_part):
                findings.append(self._make_java_finding("JAVA007", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            # JAVA008: AWS Access Key
            if re.search(r'AKIA[0-9A-Z]{16}', raw_line):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_java_finding("JAVA008", rel_path, line_no, raw_line.find("AKIA"), evidence))
            # JAVA009: Command Execution with request-controlled input
            if re.search(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', placeholder) or re.search(r'\bnew\s+ProcessBuilder\s*\(', placeholder):
                if re.search(r'request\s*\.\s*getParameter|getHeader|getQueryString', code_part):
                    # Avoid static command
                    if not re.search(r'exec\s*\(\s*"[^"]*"\s*\)', code_part):
                        findings.append(self._make_java_finding("JAVA009", rel_path, line_no, line.find("Runtime") if "Runtime" in line else line.find("ProcessBuilder"), self._bounded_evidence(lines, line_no)))
        return findings

    def _make_java_finding(self, rule_id: str, file: str, line: int, col: int, evidence: str) -> dict:
        meta = RULE_META[rule_id]
        return {"rule_id": rule_id, "title": meta["title"], "description": meta["description"], "severity": meta["severity"], "score": meta["score"], "file": file, "line": line, "column": col, "evidence": evidence[:500], "remediation": meta["remediation"], "metadata": {"rule_id": rule_id, "file": file, "line": line, "column": col, "language": "java"}}

    def _analyze_go(self, content: str, rel_path: str, lines: list[str], language: str) -> list[dict]:
        findings = []
        in_block_comment = False
        for idx, raw_line in enumerate(lines):
            line_no = idx + 1
            line = raw_line
            if "/*" in line:
                in_block_comment = True
            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                continue
            if line.strip().startswith("//"):
                continue
            code_part = line.split("//")[0]
            placeholder = re.sub(r'"[^"]*"', '""', code_part)
            placeholder = re.sub(r"'[^']*'", "''", placeholder)
            # GO001: exec.Command
            if re.search(r'\bexec\s*\.\s*Command\s*\(', placeholder) or re.search(r'\bos/exec\b', line):
                # Check for os/exec import or exec.Command
                if "exec.Command" in line:
                    findings.append(self._make_go_finding("GO001", rel_path, line_no, line.find("exec.Command"), self._bounded_evidence(lines, line_no)))
            # GO002: SQL injection similar to Java
            lower_raw = raw_line.lower()
            if any(kw in lower_raw for kw in ("select", "insert", "update", "delete")) and ("+" in code_part or "fmt.Sprintf" in code_part):
                if re.search(r'"[^"]*select[^"]*"', lower_raw) and "+" in code_part:
                    findings.append(self._make_go_finding("GO002", rel_path, line_no, lower_raw.find("select"), self._bounded_evidence(lines, line_no)))
                elif "fmt.Sprintf" in code_part and "select" in lower_raw:
                    findings.append(self._make_go_finding("GO002", rel_path, line_no, lower_raw.find("select"), self._bounded_evidence(lines, line_no)))
            # GO003: Hardcoded secret
            m = re.search(r'\b([A-Za-z0-9_]+)\s*:=?\s*"([^"]{4,})"', code_part)
            if m:
                var_name = m.group(1).lower()
                for kw in SECRET_KEYWORDS:
                    if kw in var_name:
                        findings.append(self._make_go_finding("GO003", rel_path, line_no, line.find(var_name), self._bounded_evidence(lines, line_no)))
                        break
            # GO004: Weak crypto
            if re.search(r'\bmd5\b', placeholder, re.IGNORECASE) or re.search(r'\bsha1\b', placeholder, re.IGNORECASE) or re.search(r'\bdes\b', placeholder, re.IGNORECASE) or re.search(r'\brc4\b', placeholder, re.IGNORECASE):
                if "crypto/md5" in line or "crypto/sha1" in line or "crypto/des" in line or "crypto/rc4" in line or "md5.New" in line or "sha1.New" in line:
                    findings.append(self._make_go_finding("GO004", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            # GO005: InsecureSkipVerify: true
            if re.search(r'InsecureSkipVerify\s*:\s*true', code_part):
                findings.append(self._make_go_finding("GO005", rel_path, line_no, line.find("InsecureSkipVerify"), self._bounded_evidence(lines, line_no)))
            # GO006: SSRF — http.Get/Post/NewRequest with r.URL.Query etc.
            if re.search(r'http\s*\.\s*Get\s*\(\s*r\.URL\.Query', placeholder) or re.search(r'http\s*\.\s*Post\s*\(\s*r\.', placeholder) or re.search(r'http\s*\.\s*NewRequest\s*\(.*r\.(URL|FormValue)', code_part):
                if re.search(r'r\.URL\.Query\(\)\.Get| r\.FormValue| r\.URL\.Path', code_part):
                    findings.append(self._make_go_finding("GO006", rel_path, line_no, line.find("http"), self._bounded_evidence(lines, line_no)))
                elif re.search(r'r\.URL\.Query| r\.FormValue', placeholder):
                    findings.append(self._make_go_finding("GO006", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            elif re.search(r'http\.NewRequest\s*\(.*r\.FormValue', code_part):
                findings.append(self._make_go_finding("GO006", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            # GO007: XSS — template.HTML with user input
            if re.search(r'template\s*\.\s*HTML\s*\(', placeholder):
                # Check for dynamic input like r.FormValue, r.URL.Query
                if re.search(r'r\.FormValue|r\.URL\.Query|r\.PostFormValue', code_part):
                    findings.append(self._make_go_finding("GO007", rel_path, line_no, line.find("template.HTML"), self._bounded_evidence(lines, line_no)))
                elif not re.search(r'template\.HTML\s*\(\s*""', placeholder):
                    # If not static "" then likely dynamic
                    if re.search(r'template\.HTML\s*\(.*\buser', code_part, re.IGNORECASE):
                        findings.append(self._make_go_finding("GO007", rel_path, line_no, 0, self._bounded_evidence(lines, line_no)))
            # GO008: AWS Access Key
            if re.search(r'AKIA[0-9A-Z]{16}', raw_line):
                evidence = self._bounded_evidence(lines, line_no)
                findings.append(self._make_go_finding("GO008", rel_path, line_no, raw_line.find("AKIA"), evidence))
            # GO009: Command Injection with request input
            if re.search(r'\bexec\s*\.\s*Command(?:Context)?\s*\(', placeholder):
                if re.search(r'r\.FormValue|r\.URL\.Query\(\)\.Get|r\.Header\.Get', code_part):
                    # Avoid static command without request
                    if not re.search(r'exec\.Command\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)', code_part):
                        findings.append(self._make_go_finding("GO009", rel_path, line_no, line.find("exec.Command"), self._bounded_evidence(lines, line_no)))
        return findings

    def _make_go_finding(self, rule_id: str, file: str, line: int, col: int, evidence: str) -> dict:
        meta = RULE_META[rule_id]
        return {"rule_id": rule_id, "title": meta["title"], "description": meta["description"], "severity": meta["severity"], "score": meta["score"], "file": file, "line": line, "column": col, "evidence": evidence[:500], "remediation": meta["remediation"], "metadata": {"rule_id": rule_id, "file": file, "line": line, "column": col, "language": "go"}}

    def _bounded_evidence(self, lines: list[str], line: int) -> str:
        idx = line - 1
        start = max(0, idx - 2)
        end = min(len(lines), idx + 3)
        snippet = "\n".join(lines[start:end])
        if len(snippet) > 500:
            snippet = snippet[:500]
        return snippet
