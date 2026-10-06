# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS CloudTrail log parser.

Input: CloudTrail JSON export — {"Records": [...]} where each record contains
eventSource, eventName, sourceIPAddress, userAgent, userIdentity, etc.

Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Map CloudTrail errorCode strings to approximate HTTP status equivalents
_ERROR_STATUS_MAP: dict[str, int] = {
    "AccessDenied": 403,
    "AccessDeniedException": 403,
    "AuthorizationError": 401,
    "UnauthorizedAccess": 401,
    "InvalidClientTokenId": 401,
    "ExpiredTokenException": 401,
    "TokenRefreshRequired": 401,
    "NoSuchBucket": 404,
    "NoSuchKey": 404,
    "NoSuchEntity": 404,
    "NotFoundException": 404,
    "ResourceNotFoundException": 404,
    "ThrottlingException": 429,
    "RequestLimitExceeded": 429,
    "ServiceUnavailableException": 503,
}


def _parse_timestamp(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _resolve_identity(identity: dict[str, Any]) -> str | None:
    """Return the most specific available identity string."""
    return (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("principalId")
        or identity.get("accountId")
    )


def _parse_record(record: dict[str, Any]) -> LogEvent | None:
    try:
        identity: dict[str, Any] = record.get("userIdentity") or {}
        error_code: str | None = record.get("errorCode")
        status_code = _ERROR_STATUS_MAP.get(error_code, 200) if error_code else 200

        return LogEvent(
            source_format=LogFormat.CLOUDTRAIL,
            timestamp=_parse_timestamp(record.get("eventTime")),
            ip_address=record.get("sourceIPAddress"),
            user_agent=record.get("userAgent"),
            user_principal_name=_resolve_identity(identity),
            # eventName ("AssumeRole", "PutBucketPolicy") → path slot
            path=record.get("eventName"),
            # eventSource ("iam.amazonaws.com") → resource_display_name slot
            resource_display_name=record.get("eventSource"),
            status_code=status_code,
            # errorMessage or errorCode string → failure_reason slot
            failure_reason=record.get("errorMessage") or error_code,
        )
    except Exception as exc:
        logger.warning(
            "Skipping malformed CloudTrail record %s: %s",
            record.get("eventID", "?"),
            exc,
        )
        return None


def parse_cloudtrail(raw_text: str) -> list[LogEvent]:
    """Parse a CloudTrail JSON export. Returns list of LogEvent."""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"CloudTrail parser: invalid JSON — {exc}") from exc

    if not isinstance(data, dict) or "Records" not in data:
        raise ValueError("CloudTrail parser: expected {\"Records\": [...]} object")

    records: list[dict[str, Any]] = data["Records"]
    events: list[LogEvent] = []
    for record in records:
        if event := _parse_record(record):
            events.append(event)

    logger.info("CloudTrail parser: %d/%d records parsed", len(events), len(records))
    return events


class CloudTrailParser(BaseParser):
    """Plugin-registry entry for AWS CloudTrail logs."""

    format_name = "cloudtrail"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        stripped = content.strip()
        if not stripped.startswith("{"):
            return False
        try:
            data = json.loads(stripped)
            if not isinstance(data, dict):
                return False
            records = data.get("Records")
            if not isinstance(records, list) or not records:
                return False
            first = records[0] if isinstance(records[0], dict) else {}
            return "eventSource" in first and "eventName" in first
        except (json.JSONDecodeError, IndexError):
            return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_cloudtrail(content)
