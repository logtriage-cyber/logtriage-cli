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


_AZURE_DISCRIMINATOR_FIELDS = {
    "userPrincipalName",
    "conditionalAccessStatus",
    "appliedConditionalAccessPolicies",
    "clientAppUsed",
    "deviceDetail",
}


def parse_azure_signin(raw_text: str) -> list[LogEvent]:
    """
    Parse an Azure Sign-In JSON export.

    Accepts:
      - Array of signIn objects: [{"id": "...", ...}, ...]
      - Graph API wrapper: {"value": [...], "@odata.nextLink": "..."}
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Azure Sign-In parser: invalid JSON — {exc}") from exc

    # Unwrap Graph API envelope
    records: list[dict[str, Any]]
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict) and "value" in data:
        records = data["value"]
    else:
        raise ValueError(
            "Azure Sign-In parser: expected a JSON array or {\"value\": [...]} object"
        )

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
        stripped = content.strip()
        if not stripped.startswith(("{", "[")):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                # CloudTrail uses "Records"; Azure uses "value"
                if "value" in data and "Records" not in data:
                    items = data["value"]
                    if not items:
                        return True
                    return isinstance(items[0], dict) and bool(
                        _AZURE_DISCRIMINATOR_FIELDS & set(items[0].keys())
                    )
                return False
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return bool(_AZURE_DISCRIMINATOR_FIELDS & set(data[0].keys()))
        except (json.JSONDecodeError, IndexError):
            pass
        # NDJSON — check first non-empty line
        for line in stripped.splitlines():
            if line.strip():
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        return bool(_AZURE_DISCRIMINATOR_FIELDS & set(obj.keys()))
                except json.JSONDecodeError:
                    pass
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_azure_signin(content)
