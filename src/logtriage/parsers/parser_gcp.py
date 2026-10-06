# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Google Cloud Platform (GCP) Cloud Audit Log parser.

Input: JSON array or NDJSON of Cloud Logging entries containing AuditLog
protoPayloads. Exported via Cloud Logging API, Pub/Sub, or BigQuery.

Reference: https://cloud.google.com/logging/docs/audit

Key fields mapped:
  timestamp                                    → timestamp
  protoPayload.requestMetadata.callerIp        → ip_address
  protoPayload.requestMetadata.callerSuppliedUserAgent → user_agent
  protoPayload.methodName                      → path  (e.g. /gcp/iam/roles/create)
  protoPayload.authenticationInfo.principalEmail → user_principal_name
  protoPayload.status.code (gRPC)              → status_code (0→200, 7→403, 16→401, etc.)
  protoPayload.serviceName                     → resource_display_name
  protoPayload.authorizationInfo[].granted     → failure_reason if denied
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# gRPC status codes → HTTP equivalents
_GRPC_TO_HTTP: dict[int, int] = {
    0:  200,   # OK
    1:  499,   # CANCELLED
    2:  500,   # UNKNOWN
    3:  400,   # INVALID_ARGUMENT
    4:  504,   # DEADLINE_EXCEEDED
    5:  404,   # NOT_FOUND
    6:  409,   # ALREADY_EXISTS
    7:  403,   # PERMISSION_DENIED
    8:  429,   # RESOURCE_EXHAUSTED
    9:  400,   # FAILED_PRECONDITION
    10: 409,   # ABORTED
    11: 400,   # OUT_OF_RANGE
    12: 501,   # UNIMPLEMENTED
    13: 500,   # INTERNAL
    14: 503,   # UNAVAILABLE
    15: 500,   # DATA_LOSS
    16: 401,   # UNAUTHENTICATED
}


def _ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _method_to_path(method: str | None, service: str | None) -> str:
    if not method:
        return "/gcp/unknown"
    # methodName is like "google.iam.admin.v1.IAM.CreateRole"
    # or "storage.objects.get"
    parts = method.replace("google.", "").replace(".", "/").lower()
    return f"/gcp/{parts}"


def _http_method_from_gcp(method_name: str | None) -> str:
    if not method_name:
        return "POST"
    name_lower = method_name.lower()
    if any(x in name_lower for x in (".get", ".list", ".read", "objects.get")):
        return "GET"
    if any(x in name_lower for x in (".delete", ".remove")):
        return "DELETE"
    if any(x in name_lower for x in (".update", ".patch", ".set")):
        return "PUT"
    return "POST"


def _parse_entry(raw: dict[str, Any]) -> LogEvent | None:
    try:
        proto: dict[str, Any] = raw.get("protoPayload") or {}
        req_meta: dict[str, Any] = proto.get("requestMetadata") or {}
        auth_info: dict[str, Any] = proto.get("authenticationInfo") or {}
        status: dict[str, Any] = proto.get("status") or {}
        authz_list: list[dict[str, Any]] = proto.get("authorizationInfo") or []

        method_name: str | None = proto.get("methodName")
        service_name: str | None = proto.get("serviceName")

        ip = req_meta.get("callerIp")
        ua = req_meta.get("callerSuppliedUserAgent")
        upn = auth_info.get("principalEmail")

        grpc_code = status.get("code", 0)
        status_code = _GRPC_TO_HTTP.get(int(grpc_code), 500) if grpc_code is not None else 200

        failure_reason: str | None = None
        if grpc_code and int(grpc_code) != 0:
            failure_reason = status.get("message")

        # Check authorizationInfo for any denied permission
        if not failure_reason:
            denied = [a.get("permission") for a in authz_list if not a.get("granted", True)]
            if denied:
                failure_reason = f"Permission denied: {', '.join(d for d in denied if d)}"
                if status_code == 200:
                    status_code = 403

        path = _method_to_path(method_name, service_name)
        http_method = _http_method_from_gcp(method_name)
        resource = service_name or proto.get("resourceName") or "GCP Cloud Audit"

        return LogEvent(
            source_format=LogFormat.GCP_AUDIT,
            timestamp=_ts(raw.get("timestamp")),
            ip_address=ip,
            user_agent=ua,
            http_method=http_method,
            path=path,
            status_code=status_code,
            user_principal_name=upn,
            resource_display_name=resource,
            failure_reason=failure_reason,
        )
    except Exception as exc:
        logger.debug("Skipping malformed GCP audit entry: %s", exc)
        return None


def parse_gcp_audit(content: str) -> list[LogEvent]:
    """Parse GCP Cloud Audit Log JSON/NDJSON into LogEvents."""
    records: list[dict[str, Any]] = []
    stripped = content.strip()

    if stripped.startswith("{"):
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError:
                pass
    else:
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
            elif isinstance(data, dict):
                records = data.get("entries") or [data]
        except json.JSONDecodeError as exc:
            raise ValueError(f"GCP audit parser: invalid JSON — {exc}") from exc

    result = [e for e in (_parse_entry(r) for r in records) if e is not None]
    logger.info("GCP audit parser: %d/%d events parsed", len(result), len(records))
    return result


class GcpAuditParser(BaseParser):
    format_name = "gcp_audit"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if any(x in filename.lower() for x in ("gcp", "gcloud", "cloudaudit")):
            stripped = content.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                return True
        head = content.strip()[:3000]
        return (
            '"protoPayload"' in head and '"AuditLog"' in head
        ) or (
            '"protoPayload"' in head and '"authenticationInfo"' in head
            and '"requestMetadata"' in head
        ) or (
            '"logName"' in head and "cloudaudit.googleapis.com" in head
        )

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_gcp_audit(content)
