# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS Config change event parser.

Accepts:
  - {"configurationItems": [...]} — history / snapshot files, get-resource-config-history
  - SNS notifications ({"Type": "Notification", "Message": "<JSON>"}), raw or as delivered
  - EventBridge events ({"source": "aws.config", "detail": {"configurationItem": {...}}})
  - {"configurationItem": {...}} and bare items, as a document, an array or NDJSON

Key fields: resourceType, resourceId, configurationItemStatus, awsAccountId,
configurationItemCaptureTime, changeType, configuration.

Status mapping:
  ResourceDeleted / ResourceNotRecorded → 403 (high-risk deletion)
  ResourceDiscovered                     → 200
  OK                                     → 200

Reference:
  https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html
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

_DELETE_STATUSES = frozenset({"ResourceDeleted", "ResourceDeletedNotRecorded"})
_RISKY_RESOURCE_TYPES = frozenset({
    "AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User",
    "AWS::S3::Bucket", "AWS::EC2::SecurityGroup", "AWS::KMS::Key",
    "AWS::Lambda::Function", "AWS::CloudTrail::Trail",
})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _item_to_log(item: dict[str, Any]) -> LogEvent | None:
    try:
        status = item.get("configurationItemStatus", "")
        resource_type = item.get("resourceType", "")
        resource_id = item.get("resourceId", "")
        account_id = item.get("awsAccountId")
        region = item.get("awsRegion", "")

        status_code = 403 if status in _DELETE_STATUSES else 200
        if resource_type in _RISKY_RESOURCE_TYPES and status not in ("OK", "ResourceDiscovered"):
            status_code = 401

        return LogEvent(
            source_format=LogFormat.AWS_CONFIG,
            timestamp=_parse_ts(item.get("configurationItemCaptureTime")),
            ip_address=None,
            path=f"/{resource_type}/{resource_id}",
            status_code=status_code,
            user_principal_name=account_id,
            resource_display_name=f"{resource_type} ({region})" if region else resource_type,
            failure_reason=status if status in _DELETE_STATUSES else None,
            raw_line=json.dumps(item),
        )
    except Exception as exc:
        logger.debug("Config: skipping item: %s", exc)
        return None


def _is_config_item(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "resourceType" in obj
        and ("awsAccountId" in obj or "accountId" in obj)
        and ("configurationItemStatus" in obj or "configurationStateId" in obj)
    )


def _unwrap(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The configuration items a delivered record carries.

    SNS notifications hold the change as a JSON string in "Message" (shown as an
    object in AWS's own examples, which also show "configurationItem" as a list);
    EventBridge events hold it in "detail"; history and snapshot files, and the
    CLI, list items under "configurationItems".
    """
    message = record.get("Message")
    if isinstance(message, str) and message.lstrip().startswith("{"):
        try:
            message = json.loads(message)
        except ValueError:
            message = None
    if isinstance(message, dict):
        record = message
    elif record.get("source") == "aws.config" and isinstance(record.get("detail"), dict):
        record = record["detail"]
    for key in ("configurationItems", "configurationItem"):
        inner = record.get(key)
        if isinstance(inner, list):
            return [i for i in inner if isinstance(i, dict)]
        if isinstance(inner, dict):
            return [inner]
    return [record] if _is_config_item(record) else []


def _items(content: str) -> list[dict[str, Any]]:
    return [item for record in json_input.records(content) for item in _unwrap(record)]


class AwsConfigParser(BaseParser):
    format_name = "aws_config"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = _items(content)[:5]
        return bool(head) and sum(_is_config_item(i) for i in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events = [ev for item in _items(content) if (ev := _item_to_log(item))]
        logger.info("Config parser: %d items", len(events))
        return events
