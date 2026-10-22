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

from logtriage.parsers import json_input
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


def _is_cloudtrail_record(record: dict[str, Any]) -> bool:
    return isinstance(record.get("eventSource"), str) and isinstance(record.get("eventName"), str)


def _records(raw_text: str) -> list[dict[str, Any]]:
    """CloudTrail events from a log file ({"Records": [...]}), `aws cloudtrail
    lookup-events` output ({"Events": [{"CloudTrailEvent": "<JSON>"}]}), or events
    one per line (CloudTrail Lake / CloudWatch Logs / EventBridge exports)."""
    out: list[dict[str, Any]] = []
    for record in json_input.records(raw_text, ("Records", "Events")):
        inner = record.get("CloudTrailEvent")
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except ValueError:
                inner = None
        if isinstance(inner, dict):
            record = inner
        elif record.get("source") == "aws.cloudtrail" or (
            isinstance(record.get("detail"), dict) and _is_cloudtrail_record(record["detail"])
        ):
            record = record.get("detail") or record  # EventBridge "AWS API Call via CloudTrail"
        out.append(record)
    return out


def parse_cloudtrail(raw_text: str) -> list[LogEvent]:
    records = _records(raw_text)
    events: list[LogEvent] = []
    for record in records:
        if event := _parse_record(record):
            events.append(event)

    logger.info("CloudTrail parser: %d/%d records parsed", len(events), len(records))
    return events


class CloudTrailParser(BaseParser):

    format_name = "cloudtrail"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = _records(content)[:5]
        return bool(head) and sum(_is_cloudtrail_record(r) for r in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_cloudtrail(content)
