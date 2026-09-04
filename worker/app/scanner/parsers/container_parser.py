"""S7.6 Container Parser — Trivy SARIF, container_image assets, no plaintext leakage.

Parses Trivy SARIF 2.1.0 into normalized findings. Preserves image, package,
installed_version, fixed_version, layer, and vulnerability metadata without
fabrication. Ensures container_image asset association and project isolation
via the persistence layer (which is scanner-agnostic).
"""

import json

from app.scanner.parsers.base import BaseParser


class ContainerParser(BaseParser):
    scanner_name = "container"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "container", "assets": [], "findings": [], "metadata": {"reason": "empty output"}}

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid container output JSON: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("Container output must be a JSON object")

        # SARIF path — Trivy with --format sarif produces SARIF
        if "runs" in data or "version" in data:
            if "runs" not in data or not isinstance(data.get("runs"), list):
                if "version" in data and "runs" not in data:
                    raise ValueError("SARIF output missing runs array")
            return self._parse_sarif(data, raw_output)

        # Legacy/non-SARIF path — treat as already normalized container result
        return self._parse_legacy(data)

    def _parse_sarif(self, data: dict, raw_output: str) -> dict:
        from app.scanner.parsers.sarif_parser import SarifParser

        sarif = SarifParser()
        # Delegate to generic SARIF parser (handles empty runs, malformed gracefully)
        # SarifParser expects raw JSON string; we pass raw_output directly
        try:
            result = sarif.parse(raw_output)
        except Exception:
            # Fallback: try with redacted raw if needed (no secrets in container, but safe)
            result = sarif.parse(json.dumps(data))

        # Normalize to container scanner
        result["scanner"] = "container"

        # Post-process findings: Trivy SARIF encodes package/version in message/properties;
        # SarifParser already extracts title/description/severity/cve/cwe/file/line.
        # We enrich metadata with container-specific fields where present in raw SARIF,
        # without fabricating.
        runs = data.get("runs", [])
        # Build lookup for raw result metadata (for package info)
        raw_results = []
        for run in runs:
            if isinstance(run, dict) and isinstance(run.get("results"), list):
                raw_results.extend(run["results"])

        for idx, f in enumerate(result.get("findings", [])):
            if not isinstance(f, dict):
                continue
            f["scanner"] = "container"
            # Evidence type for container should be container_layer (mapped in evidence.py)
            if not f.get("evidence_type"):
                f["evidence_type"] = "container_layer"
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if not isinstance(meta, dict):
                meta = {}
            # Derive CVE from rule_id if it looks like CVE-*
            rule_id = f.get("rule_id") or meta.get("rule_id") or ""
            if isinstance(rule_id, str) and rule_id.upper().startswith("CVE-") and not f.get("cve"):
                f["cve"] = rule_id.strip()
                # Also set CWE if available via tags (already handled by SarifParser)
            # Preserve any Trivy-specific properties from raw SARIF result
            if idx < len(raw_results):
                raw_res = raw_results[idx]
                if isinstance(raw_res, dict):
                    props = raw_res.get("properties", {}) if isinstance(raw_res.get("properties"), dict) else {}
                    for key in ("packageName", "packageVersion", "installedVersion", "fixedVersion",
                                "severity", "cvssScore", "cvss", "layerDigest", "layerIndex",
                                "PURL", "image", "type", "class"):
                        if key in props and props[key] not in (None, ""):
                            # Use lowercase normalized keys
                            norm_key = {
                                "packageName": "package_name",
                                "packageVersion": "package_version",
                                "installedVersion": "installed_version",
                                "fixedVersion": "fixed_version",
                                "cvssScore": "cvss_score",
                                "layerDigest": "layer_digest",
                                "layerIndex": "layer_index",
                                "PURL": "purl",
                            }.get(key, key.lower())
                            if norm_key not in meta:
                                meta[norm_key] = str(props[key])[:500]
                    # Also handle CVE in properties directly
                    for cve_key in ("cve", "CVE", "vulnerabilityID"):
                        if cve_key in props and props[cve_key] and not f.get("cve"):
                            f["cve"] = str(props[cve_key]).strip()

            # Ensure mandatory provenance fields are not missing (scanner will also inject)
            if "execution_engine" not in meta:
                meta["execution_engine"] = "trivy"
                meta["execution_mode"] = "docker"
            f["metadata"] = meta
            # Ensure file/line/rule_id top-level for normalizer (already set by SarifParser)

        # Assets: ensure container_image asset exists
        assets = result.get("assets", [])
        # SarifParser creates source_file assets for file_path; for container, we want container_image
        # If no container_image asset yet, try to infer from runs
        has_container_image = any(
            isinstance(a, dict) and a.get("type") == "container_image"
            for a in assets
        )
        if not has_container_image:
            # Try to extract image from SARIF runs (Trivy may include tool properties)
            image_ref = None
            for run in runs:
                if not isinstance(run, dict):
                    continue
                # Trivy SARIF sometimes has no explicit image in SARIF; we leave for scanner to add
                # Here we just check if any finding metadata has image
                pass
            # If still none, don't fabricate — scanner will add it when it knows the ref
            # For parser-only tests, we can add a generic placeholder if needed? Don't.
            pass

        # Mark assets with provenance
        for a in assets:
            if isinstance(a.get("metadata"), dict):
                a["metadata"]["asset_type"] = a.get("type", "container_image")
            else:
                a["metadata"] = {"asset_type": a.get("type", "container_image")}

        result["assets"] = assets
        result.setdefault("metadata", {})["scanner"] = "container"
        return result

    def _parse_legacy(self, data: dict) -> dict:
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        for f in findings:
            if isinstance(f, dict):
                f["scanner"] = "container"
                if not f.get("evidence_type"):
                    f["evidence_type"] = "container_layer"
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                if not isinstance(meta, dict):
                    meta = {}
                if "execution_engine" not in meta:
                    meta["execution_engine"] = "trivy"
                f["metadata"] = meta
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        # Ensure container_image asset if findings exist but no asset
        if findings and not any(isinstance(a, dict) and a.get("type") == "container_image" for a in assets):
            # Don't fabricate image value; leave to scanner
            pass
        return {
            "scanner": "container",
            "assets": assets,
            "findings": findings,
            "metadata": data.get("metadata", {}),
        }
