# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Azure AD / Entra ID Sign-In log parser.

Input: Azure Sign-In log JSON export — either a bare array of signIn objects
or the standard `{"value": [...]}` wrapper produced by the Graph API / Entra portal.

Reference fields: https://learn.microsoft.com/en-us/graph/api/resources/signin
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers import json_input
from logtriage.models import (
    ConditionalAccessDetail,
    DeviceDetail,
    LocationDetail,
    LogEvent,
    LogFormat,
)

logger = logging.getLogger(__name__)


def _parse_timestamp(raw: str | None) -> datetime:
    """Parse ISO-8601 timestamp from Azure logs; return UTC-aware datetime."""
    if not raw:
        return datetime.now(timezone.utc)
    try:
        # Azure uses "2024-01-15T10:23:45Z" or with ms "...45.123Z"
        raw_clean = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(raw_clean)
    except (ValueError, AttributeError):
        logger.debug("Could not parse Azure timestamp: %r", raw)
        return datetime.now(timezone.utc)


def _parse_device(raw: dict[str, Any] | None) -> DeviceDetail | None:
    if not raw:
        return None
    return DeviceDetail(
        display_name=raw.get("displayName"),
        operating_system=raw.get("operatingSystem"),
        browser=raw.get("browser"),
        is_compliant=raw.get("isCompliant"),
        is_managed=raw.get("isManaged"),
        trust_type=raw.get("trustType"),
    )


def _parse_location(raw: dict[str, Any] | None) -> LocationDetail | None:
    if not raw:
        return None
    coords: dict[str, float] | None = None
    if geo := raw.get("geoCoordinates"):
        try:
            coords = {"lat": float(geo.get("latitude", 0)), "lon": float(geo.get("longitude", 0))}
        except (TypeError, ValueError):
            pass
    return LocationDetail(
        city=raw.get("city"),
        state=raw.get("state"),
        country_or_region=raw.get("countryOrRegion"),
        geo_coordinates=coords,
    )


def _parse_conditional_access(raw: list[dict[str, Any]] | None) -> ConditionalAccessDetail | None:
    if not raw:
        return None
    # Azure returns an array; consolidate into one summary
    statuses = [p.get("result", "") for p in raw]
    # Determine overall status
    if any(s == "failure" for s in statuses):
        overall = "failure"
    elif any(s == "notApplied" for s in statuses):
        overall = "notApplied"
    else:
        overall = "success"
    not_satisfied = [
        p.get("displayName", "")
        for p in raw
        if p.get("result") in ("failure", "notEnabled")
    ]
    return ConditionalAccessDetail(status=overall, policies_not_satisfied=not_satisfied)


def _parse_signin(record: dict[str, Any]) -> LogEvent | None:
    """Convert a single Azure signIn object to a LogEvent."""
    try:
        status_obj: dict[str, Any] = record.get("status") or {}
        error_code_raw = status_obj.get("errorCode")
        error_code = int(error_code_raw) if error_code_raw is not None else None

        return LogEvent(
            source_format=LogFormat.AZURE_SIGNIN,
            raw_line=None,  # JSON records; raw preserved in file on disk
            timestamp=_parse_timestamp(record.get("createdDateTime")),
            ip_address=record.get("ipAddress"),
            user_agent=record.get("userAgent"),
            user_principal_name=record.get("userPrincipalName"),
            user_id=record.get("userId"),
            app_display_name=record.get("appDisplayName"),
            resource_display_name=record.get("resourceDisplayName"),
            client_app_used=record.get("clientAppUsed"),
            correlation_id=record.get("correlationId"),
            error_code=error_code,
            failure_reason=status_obj.get("failureReason"),
            mfa_detail=record.get("mfaDetail"),
            conditional_access=_parse_conditional_access(
                record.get("appliedConditionalAccessPolicies")
            ),
            device=_parse_device(record.get("deviceDetail")),
            location=_parse_location(record.get("location")),
            risk_level_aggregated=record.get("riskLevelAggregated"),
            risk_level_during_signin=record.get("riskLevelDuringSignIn"),
            is_interactive=record.get("isInteractive"),
        )
    except Exception as exc:
        logger.warning("Skipping malformed Azure record: %s — %r", exc, record.get("id", "?"))
        return None


# Log Analytics SigninLogs columns whose camelCase Graph name is not just the
# first letter lowered; dynamic columns arrive as JSON strings in CSV/JSON exports.
_LA_RENAMES = {
    "IPAddress": "ipAddress",
    "LocationDetails": "location",
    "ConditionalAccessPolicies": "appliedConditionalAccessPolicies",
}
_LA_DYNAMIC = frozenset({"deviceDetail", "location", "status", "mfaDetail", "appliedConditionalAccessPolicies"})


def _json_value(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in ("{", "["):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Graph / portal sign-ins pass through; two other exports are mapped onto them.

    - Diagnostic-settings archives (storage account, Event Hub): {"time", "category":
      "SignInLogs" | "NonInteractiveUserSignInLogs" | …, "resultType", "properties": {…}}
    - Log Analytics `SigninLogs` rows: PascalCase columns (UserPrincipalName, IPAddress,
      ResultType, TimeGenerated, …), dynamic columns sometimes as JSON strings.
    """
    props = record.get("properties")
    if isinstance(props, dict) and "signin" in str(record.get("category", "")).lower():
        flat = dict(props)
        flat.setdefault("createdDateTime", record.get("time"))
        flat.setdefault("ipAddress", record.get("callerIpAddress"))
        if "status" not in flat and record.get("resultType") is not None:
            flat["status"] = {"errorCode": record.get("resultType"), "failureReason": record.get("resultDescription")}
        return flat
    if "UserPrincipalName" in record and "userPrincipalName" not in record:
        flat = {}
        for key, value in record.items():
            name = _LA_RENAMES.get(key) or (key[:1].lower() + key[1:])
            flat[name] = _json_value(value) if name in _LA_DYNAMIC else value
        flat.setdefault("createdDateTime", record.get("TimeGenerated"))
        if not isinstance(flat.get("status"), dict) and record.get("ResultType") is not None:
            flat["status"] = {"errorCode": record.get("ResultType"), "failureReason": record.get("ResultDescription")}
        return flat
    return record


def _is_signin(record: dict[str, Any]) -> bool:
    """Same rule as the free analyzer's Entra module: a user plus a sign-in signal."""
    if record.get("operationName") and record.get("caller"):
        return False  # Azure Activity log
    return "userPrincipalName" in record and any(
        k in record for k in ("ipAddress", "createdDateTime", "status", "clientAppUsed")
    )


# Graph API: {"value": [...], "@odata.nextLink": ...}; diagnostic archives: {"records": [...]}
_ENVELOPES = ("value", "records")


def _records(raw_text: str) -> list[dict[str, Any]]:
    return [_normalize_record(r) for r in json_input.records(raw_text, _ENVELOPES)]


def parse_azure_signin(raw_text: str) -> list[LogEvent]:
    """
    Parse an Entra ID (Azure AD) sign-in export: a Graph API response or portal
    download (array or {"value": [...]}), NDJSON, a diagnostic-settings archive or
    Log Analytics SigninLogs rows.
    """
    records = _records(raw_text)
    events: list[LogEvent] = []
    for record in records:
        if event := _parse_signin(record):
            events.append(event)

    logger.info("Azure parser: %d/%d records parsed", len(events), len(records))
    return events


class AzureParser:
    """Plugin-registry entry for Azure AD / Entra ID Sign-In logs."""

    format_name = "azure_signin"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = [_normalize_record(r) for r in json_input.sample(content, _ENVELOPES)]
        return bool(head) and sum(_is_signin(r) for r in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_azure_signin(content)
