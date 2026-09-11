"""E3 IAM policy analysis — deterministic, bounded, no network, no AI.

Responsibilities:
- decode policy documents (URL-encoded or JSON)
- normalize statements into bounded structured representation
- identify dangerous patterns for AWS-IAM-001..008
- produce bounded evidence for FindingEngine

Security:
- Never store secret material, only metadata.
- Bound all collections and string lengths.
- Malformed/oversized documents -> NOT_ASSESSED/ERROR, never fabricated PASS/FAIL.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any

# Bounded limits (configurable via env in future; fixed for E3).
MAX_POLICIES = 20
MAX_STATEMENTS_PER_POLICY = 50
MAX_ACTIONS_PER_STATEMENT = 200
MAX_RESOURCES_PER_STATEMENT = 200
MAX_PRINCIPALS_PER_STATEMENT = 50
MAX_STRING_LENGTH = 1024
MAX_POLICY_SIZE_BYTES = 64 * 1024  # 64KB


DANGEROUS_ACTIONS = frozenset({
    "iam:*",
    "iam:passrole",
    "iam:createrole",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:createpolicy",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putgrouppolicy",
    "iam:updateassumerolepolicy",
    "organizations:*",
    "sts:assumerole",
    # privileged mutation actions
    "kms:*",
    # Keep list focused per E3 §12 — avoid huge speculative list.
})

# Wildcard service patterns considered dangerous when combined with Allow *.
ADMIN_SERVICE_WILDCARDS = frozenset({
    "s3:*", "ec2:*", "lambda:*", "cloudformation:*",
})


def _truncate(s: str, limit: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s[:limit]


def _bounded_list(items: list[Any], limit: int) -> tuple[list[Any], bool]:
    """Return bounded list and truncation flag."""
    if len(items) > limit:
        return items[:limit], True
    return items, False


def decode_policy_document(raw: str | dict | None) -> tuple[dict | None, str | None]:
    """Decode a policy document that may be URL-encoded JSON.

    Returns (document_dict, error). On oversized -> error, on malformed -> error.
    Never raises.
    """
    if raw is None:
        return None, "empty document"
    try:
        if isinstance(raw, dict):
            doc = raw
        else:
            text = str(raw).strip()
            if not text:
                return None, "empty document"
            if len(text.encode("utf-8")) > MAX_POLICY_SIZE_BYTES:
                return None, "oversized document"
            # URL-decode if it looks encoded (%7B etc).
            # AWS GetPolicyVersion returns URL-encoded JSON; also handle plain JSON.
            # Try url-decode once if % present.
            if "%" in text:
                try:
                    decoded = urllib.parse.unquote(text)
                    # Only use decoded if it looks like JSON
                    if decoded.strip().startswith("{"):
                        text = decoded
                except Exception:
                    pass
            doc = json.loads(text)
        if not isinstance(doc, dict):
            return None, "document is not an object"
        return doc, None
    except json.JSONDecodeError as exc:
        return None, f"malformed JSON: {str(exc)[:200]}"
    except Exception as exc:
        return None, f"decode error: {str(exc)[:200]}"


def _as_list(value: Any) -> list[str]:
    """Normalize Action/Resource/Principal to list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [_truncate(value)]
    if isinstance(value, list):
        out = []
        for item in value:
            if item is None:
                continue
            out.append(_truncate(str(item)))
        return out
    return [_truncate(str(value))]


def _principal_list(principal: Any) -> list[str]:
    """Normalize Principal field to list of principal strings."""
    if principal is None:
        return []
    if isinstance(principal, str):
        return [_truncate(principal)]
    if isinstance(principal, dict):
        out = []
        for key, val in principal.items():
            vals = _as_list(val)
            for v in vals:
                out.append(_truncate(f"{key}:{v}"))
            if not vals:
                out.append(_truncate(str(key)))
        return out
    if isinstance(principal, list):
        out = []
        for p in principal:
            out.extend(_principal_list(p))
        return out
    return [_truncate(str(principal))]


def normalize_policy_document(
    doc: dict,
    policy_name: str | None = None,
    policy_arn: str | None = None,
) -> tuple[list[dict], dict]:
    """Normalize policy document into bounded structured statements.

    Returns (statements, truncation_meta). Each statement:
    {effect, actions, resources, principals, sid, condition_keys}
    principals only present for trust policies; empty otherwise.
    """
    truncation: dict[str, Any] = {"truncated": False, "reasons": []}
    statements: list[dict] = []

    raw_stmts = doc.get("Statement")
    if raw_stmts is None:
        truncation["truncated"] = False
        truncation["reasons"].append("no Statement field")
        return [], truncation

    if isinstance(raw_stmts, dict):
        raw_stmts = [raw_stmts]
    if not isinstance(raw_stmts, list):
        return [], {"truncated": False, "reasons": ["Statement not a list/object"]}

    bounded_stmts, stmts_truncated = _bounded_list(raw_stmts, MAX_STATEMENTS_PER_POLICY)
    if stmts_truncated:
        truncation["truncated"] = True
        truncation["reasons"].append(f"statements truncated to {MAX_STATEMENTS_PER_POLICY}")

    for raw in bounded_stmts:
        if not isinstance(raw, dict):
            continue
        effect = str(raw.get("Effect") or "").strip()
        # Normalize to Allow/Deny
        effect_norm = "Allow" if effect.lower() == "allow" else "Deny" if effect.lower() == "deny" else _truncate(effect)

        # Actions: Action or NotAction
        actions = _as_list(raw.get("Action"))
        not_actions = _as_list(raw.get("NotAction"))
        # Use Action; if NotAction present, treat as actions with not_action flag
        is_not_action = bool(not_actions) and not actions
        if is_not_action:
            actions = not_actions

        resources = _as_list(raw.get("Resource"))
        not_resources = _as_list(raw.get("NotResource"))
        is_not_resource = bool(not_resources) and not resources
        if is_not_resource:
            resources = not_resources

        principals = _principal_list(raw.get("Principal"))
        # Also handle NotPrincipal
        if not principals and raw.get("NotPrincipal") is not None:
            principals = _principal_list(raw.get("NotPrincipal"))

        # Bound actions/resources/principals
        actions_b, a_trunc = _bounded_list(actions, MAX_ACTIONS_PER_STATEMENT)
        resources_b, r_trunc = _bounded_list(resources, MAX_RESOURCES_PER_STATEMENT)
        principals_b, p_trunc = _bounded_list(principals, MAX_PRINCIPALS_PER_STATEMENT)

        if a_trunc or r_trunc or p_trunc:
            truncation["truncated"] = True
            if a_trunc:
                truncation["reasons"].append("actions truncated")
            if r_trunc:
                truncation["reasons"].append("resources truncated")
            if p_trunc:
                truncation["reasons"].append("principals truncated")

        sid = raw.get("Sid")
        sid_norm = _truncate(str(sid)) if sid is not None else None
        # Condition keys (bounded, never values)
        condition = raw.get("Condition")
        condition_keys: list[str] = []
        if isinstance(condition, dict):
            for op, kv in list(condition.items())[:10]:
                if isinstance(kv, dict):
                    for k in list(kv.keys())[:10]:
                        condition_keys.append(_truncate(f"{op}:{k}"))
                else:
                    condition_keys.append(_truncate(str(op)))

        stmt: dict[str, Any] = {
            "effect": effect_norm,
            "actions": actions_b,
            "resources": resources_b,
            "principals": principals_b,
            "sid": sid_norm,
            "condition_keys": condition_keys[:10],
        }
        if is_not_action:
            stmt["not_action"] = True
        if is_not_resource:
            stmt["not_resource"] = True
        if policy_name:
            stmt["policy_name"] = _truncate(policy_name, 256)
        if policy_arn:
            stmt["policy_arn"] = _truncate(policy_arn, 1024)
        statements.append(stmt)

    return statements, truncation


def statement_identity(policy_arn_or_name: str, statement: dict, index: int) -> str:
    """Deterministic statement identity (hash). Uses SID if present, else canonical content."""
    sid = statement.get("sid")
    if sid:
        payload = f"{policy_arn_or_name}|sid:{sid}|idx:{index}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
    # Canonical content hash: sorted actions/resources/principals + effect
    actions = sorted(statement.get("actions") or [])
    resources = sorted(statement.get("resources") or [])
    principals = sorted(statement.get("principals") or [])
    effect = statement.get("effect") or ""
    payload = json.dumps(
        {"effect": effect, "actions": actions, "resources": resources, "principals": principals},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    h = hashlib.sha256(f"{policy_arn_or_name}|{payload}".encode()).hexdigest()[:16]
    return h


# ---------------------------------------------------------------------------
# Deterministic detectors — pure functions over normalized statements
# ---------------------------------------------------------------------------

def has_wildcard_action(statement: dict) -> bool:
    if statement.get("effect") != "Allow":
        return False
    for action in statement.get("actions") or []:
        if action.strip() == "*" or action.strip().endswith(":*") and ":" not in action.strip().replace(":*", ""):
            # "*" is wildcard; also service:* is handled in dangerous check
            if action.strip() == "*":
                return True
        if action.strip() == "*":
            return True
    return False


def has_wildcard_resource(statement: dict) -> bool:
    if statement.get("effect") != "Allow":
        return False
    for res in statement.get("resources") or []:
        if res.strip() == "*":
            return True
    return False


def has_dangerous_action(statement: dict) -> list[str]:
    """Return list of dangerous actions matched (bounded)."""
    if statement.get("effect") != "Allow":
        return []
    matched: list[str] = []
    for action in statement.get("actions") or []:
        norm = action.strip().lower()
        if norm in DANGEROUS_ACTIONS or norm == "iam:*":
            matched.append(action)
        elif norm in ADMIN_SERVICE_WILDCARDS:
            matched.append(action)
        elif norm == "iam:*" or norm.startswith("iam:"):
            # Any iam:* is already covered; but iam:PassRole etc checked via set
            if norm in DANGEROUS_ACTIONS:
                matched.append(action)
    # Deduplicate, bounded
    return sorted(set(matched))[:20]


def has_wildcard_principal(statement: dict) -> bool:
    for p in statement.get("principals") or []:
        # Principal "*" or AWS "*"
        if p.strip() == "*" or p.strip().endswith(":*") and p.strip() == "*":
            return True
        if p.strip() == "AWS:*" or p.strip().endswith("*") and p.strip() == "*":
            return True
        if p == "*":
            return True
        # Normalized form "AWS:*"
        if p == "AWS:*":
            return True
    return False


def has_external_account_principal(statement: dict, own_account_id: str | None) -> list[str]:
    """Detect principals that are external AWS account ARNs."""
    external: list[str] = []
    own = str(own_account_id or "").strip()
    for p in statement.get("principals") or []:
        # Principal format: AWS:arn:aws:iam::123456789012:root etc or AWS:123456789012
        # Our normalization produces "AWS:arn:..." or "AWS:123456789012" or "AWS:*"
        # Also "CanonicalUser", "Federated", "Service"
        if p.startswith("AWS:"):
            val = p[4:]
            # Extract 12-digit account id if present
            m = re.search(r"(\d{12})", val)
            if m:
                acct = m.group(1)
                if acct != own and acct != "000000000000":
                    external.append(acct)
            elif val.strip() == "*":
                # Wildcard already handled separately; not external account
                pass
        elif re.match(r"^\d{12}$", p.strip()):
            if p.strip() != own:
                external.append(p.strip())
    return sorted(set(external))[:10]


def is_service_principal(principal: str) -> bool:
    return principal.startswith("Service:")


def is_federated_principal(principal: str) -> bool:
    return principal.startswith("Federated:")


def trust_principal_type(principal: str) -> str:
    if principal == "*" or principal == "AWS:*":
        return "wildcard"
    if principal.startswith("Service:"):
        return "service"
    if principal.startswith("Federated:"):
        return "federated"
    if principal.startswith("AWS:"):
        return "aws_account"
    if re.match(r"^\d{12}$", principal):
        return "aws_account"
    return "unknown"
