"""E1 AWS connector — cross-account IAM role assumption (backend fast path).

Used by the connection-test endpoint for STS identity validation and region
listing. Full multi-service discovery lives in the worker
(``worker/app/aws_discovery.py``) so API requests never block on it.

Security rules (enforced here and in callers):
- Only identifiers are configured/stored (account ID, role ARN, external ID).
- Temporary credentials exist in memory only, never persisted or logged.
- Errors are sanitized: no keys, tokens, headers, payloads, or tracebacks.
- boto3 is imported lazily so mock mode and tests never require AWS SDKs.
"""

from __future__ import annotations

import os
import re
from typing import Any

AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")
AWS_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/([\w+=,.@-]+)$")
AWS_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")

PROVIDER_TIMEOUT = int(os.getenv("PROVIDER_TIMEOUT", "10"))

# Form-level bounds (identifiers only, never secrets).
EXTERNAL_ID_MAX = 256
ROLE_ARN_MAX = 512
REGIONS_MAX = 32


class AWSConnectorError(Exception):
    """Sanitized, bounded connector failure (safe for API responses)."""


def sanitize_aws_error(exc: Exception, default: str = "AWS operation failed") -> str:
    msg = str(exc or "")[:500]
    low = msg.lower()
    for tok in ("accesskey", "secretaccesskey", "sessiontoken", "authorization",
                "x-amz-", "credential", "privatekey", "BEGIN PRIVATE"):
        if tok in low:
            return default
    # Strip any embedded key-like material conservatively.
    msg = re.sub(r"(?i)(secret|token|key)\s*[:=]\s*\S+", r"\1=[REDACTED]", msg)
    return (msg.strip() or default)[:300]


def validate_account_id(account_id: str | None) -> str:
    value = str(account_id or "").strip()
    if not AWS_ACCOUNT_RE.match(value):
        raise AWSConnectorError("Invalid AWS account ID: expected 12 digits")
    return value


def validate_role_arn(role_arn: str | None, account_id: str | None = None) -> str:
    value = str(role_arn or "").strip()
    if len(value) > ROLE_ARN_MAX:
        raise AWSConnectorError("Invalid IAM role ARN")
    match = AWS_ROLE_ARN_RE.match(value)
    if not match:
        raise AWSConnectorError("Invalid IAM role ARN: expected arn:aws:iam::<account>:role/<name>")
    if account_id and match.group(1) != str(account_id).strip():
        raise AWSConnectorError("Role ARN account does not match connection account ID")
    return value


def validate_external_id(external_id: str | None) -> str | None:
    if external_id is None:
        return None
    value = str(external_id).strip()
    if not value:
        return None
    if len(value) > EXTERNAL_ID_MAX or not re.match(r"^[\w+=,.@:/-]+$", value):
        raise AWSConnectorError("Invalid external ID")
    return value


def validate_regions(regions: Any) -> list[str] | None:
    if regions is None:
        return None
    if not isinstance(regions, list):
        raise AWSConnectorError("regions must be a list")
    cleaned = []
    for region in regions[:REGIONS_MAX]:
        name = str(region or "").strip().lower()
        if not AWS_REGION_RE.match(name):
            raise AWSConnectorError(f"Invalid AWS region: {region}")
        if name not in cleaned:
            cleaned.append(name)
    return cleaned or None


def _boto3_client(service: str, region: str, **credentials: str):
    try:
        import boto3
        from botocore.config import Config
    except Exception as exc:
        raise AWSConnectorError("AWS SDK unavailable for live validation") from exc
    try:
        config = Config(
            connect_timeout=min(PROVIDER_TIMEOUT, 10),
            read_timeout=min(PROVIDER_TIMEOUT, 10),
            retries={"mode": "standard", "max_attempts": 2},
        )
        params: dict[str, Any] = {"service_name": service, "region_name": region, "config": config}
        if credentials:
            params.update({
                "aws_access_key_id": credentials.get("access_key"),
                "aws_secret_access_key": credentials.get("secret_key"),
                "aws_session_token": credentials.get("session_token"),
            })
        return boto3.client(**{k: v for k, v in params.items() if v is not None})
    except AWSConnectorError:
        raise
    except Exception as exc:
        raise AWSConnectorError(sanitize_aws_error(exc)) from exc


def assume_role(role_arn: str, external_id: str | None = None) -> dict[str, str]:
    """AssumeRole via ambient credentials. Returns temp creds (memory only)."""
    sts = _boto3_client("sts", "us-east-1")
    kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": "vapt-discovery",
        "DurationSeconds": 900,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    try:
        response = sts.assume_role(**kwargs)
    except Exception as exc:
        raise AWSConnectorError(_permission_or_sanitized(exc)) from exc
    creds = (response or {}).get("Credentials") or {}
    if not creds.get("AccessKeyId") or not creds.get("SecretAccessKey"):
        raise AWSConnectorError("AWS AssumeRole returned no credentials")
    out = {
        "access_key": str(creds["AccessKeyId"]),
        "secret_key": str(creds["SecretAccessKey"]),
    }
    if creds.get("SessionToken"):
        out["session_token"] = str(creds["SessionToken"])
    return out


def _permission_or_sanitized(exc: Exception) -> str:
    """Classify permission failures explicitly (never reported as absence)."""
    try:
        code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", "") or "")
    except Exception:
        code = ""
    if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure", "InvalidClientTokenId",
                "SignatureDoesNotMatch", "AccessDeniedException", "NotAuthorized"):
        return f"AWS permission denied ({code or 'auth'}): check role trust policy and IAM permissions"
    return sanitize_aws_error(exc)


def get_account_identity(role_arn: str, external_id: str | None, account_id: str) -> dict[str, str]:
    """Assume the role and return sanitized caller identity (verified account)."""
    creds = assume_role(role_arn, external_id)
    try:
        sts = _boto3_client("sts", "us-east-1", **creds)
        identity = sts.get_caller_identity() or {}
    except Exception as exc:
        raise AWSConnectorError(_permission_or_sanitized(exc)) from exc
    finally:
        creds.clear()
    found = str(identity.get("Account") or "")
    if found != str(account_id):
        raise AWSConnectorError("Assumed role account does not match connection account ID")
    arn = str(identity.get("Arn") or "")
    # Return principal type only, not full identifying material beyond the ARN.
    return {"account_id": found, "arn": arn[:512], "user_id": str(identity.get("UserId") or "")[:128]}


def discover_regions(role_arn: str, external_id: str | None) -> list[str]:
    """List enabled regions via EC2 DescribeRegions (no hardcoded list)."""
    creds = assume_role(role_arn, external_id)
    try:
        ec2 = _boto3_client("ec2", "us-east-1", **creds)
        response = ec2.describe_regions(AllRegions=False)
    except Exception as exc:
        raise AWSConnectorError(_permission_or_sanitized(exc)) from exc
    finally:
        creds.clear()
    regions = []
    for region in (response or {}).get("Regions", []):
        name = str(region.get("RegionName") or "").strip().lower()
        if name and AWS_REGION_RE.match(name) and name not in regions:
            regions.append(name)
    if not regions:
        raise AWSConnectorError("No enabled AWS regions returned")
    return regions[:REGIONS_MAX]
