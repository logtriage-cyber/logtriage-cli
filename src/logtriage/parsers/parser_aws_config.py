# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS Config change event parser.

Accepts:
  - {"configurationItems": [...]} — bulk history export
  - {"configurationItem": {...}}  — SNS / EventBridge single change
  - NDJSON — one configurationItem per line

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


class AwsConfigParser(BaseParser):
    format_name = "aws_config"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "config" in filename.lower() and "aws" in filename.lower():
            return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                # Bulk export
                items = data.get("configurationItems")
                if isinstance(items, list) and items:
                    return _is_config_item(items[0])
                # SNS single
                item = data.get("configurationItem")
                if isinstance(item, dict):
                    return _is_config_item(item)
                return _is_config_item(data)
        except json.JSONDecodeError:
            pass
        # NDJSON
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_config_item(json.loads(line))
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        stripped = content.strip()

        def _from_list(items: list[Any]) -> None:
            for item in items:
                if ev := _item_to_log(item):
                    events.append(ev)

        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                items = data.get("configurationItems")
                if isinstance(items, list):
                    _from_list(items)
                    logger.info("Config parser: %d items", len(events))
                    return events
                item = data.get("configurationItem")
                if isinstance(item, dict):
                    if ev := _item_to_log(item):
                        events.append(ev)
                    return events
                if _is_config_item(data):
                    if ev := _item_to_log(data):
                        events.append(ev)
                    return events
        except json.JSONDecodeError:
            pass

        for line in stripped.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if ev := _item_to_log(obj):
                    events.append(ev)
            except json.JSONDecodeError:
                continue

        logger.info("Config parser: %d items (NDJSON)", len(events))
        return events
