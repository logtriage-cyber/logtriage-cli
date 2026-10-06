# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
SentinelOne threat/alert JSON parser.

SentinelOne exports via the Management API return either a top-level
{"data": [...]} envelope or a bare JSON array. Each alert object contains
`threatInfo`, `agentDetectionInfo`, and `indicators`.

Discriminator: `threatInfo` + `agentDetectionInfo` fields (both are
SentinelOne-specific nested objects).

Reference:
  https://usea1-partners.sentinelone.net/api-doc/
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        # ISO 8601 with Z suffix
        raw = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)


def _confidence_status(confidence: str | None, mitigation: str | None) -> int:
    conf = (confidence or "").lower()
    mit = (mitigation or "").lower()
    if conf == "malicious" or mit in ("killed", "quarantine", "remediated"):
        return 403
    if conf == "suspicious":
        return 401
    return 200


def _alert_to_log(obj: dict) -> LogEvent | None:
    threat = obj.get("threatInfo") or {}
    agent = obj.get("agentDetectionInfo") or {}
    white_detection = obj.get("whiteningOptions") or {}  # noqa: F841

    ts_raw = (
        threat.get("createdAt")
        or obj.get("createdAt")
        or threat.get("identifiedAt")
    )
    ts = _parse_ts(ts_raw)

    ip = (
        agent.get("agentIpV4")
        or agent.get("agentIpV6")
        or obj.get("sourceIp")
    )

    hostname = agent.get("agentComputerName") or agent.get("agentHostname")
    user = (
        threat.get("initiatedByUsername")
        or obj.get("username")
        or agent.get("agentDomain")
    )

    threat_name = threat.get("threatName") or threat.get("classification", "")
    sha256 = threat.get("sha256") or threat.get("fileSha256")
    if sha256 and len(sha256) != 64:
        sha256 = None

    path = (
        threat.get("filePath")
        or threat.get("threatFilePath")
        or threat_name
        or "SentinelOne/Alert"
    )

    confidence = threat.get("confidenceLevel")
    mitigation = threat.get("mitigationStatus")

    return LogEvent(
        source_format=LogFormat.SENTINELONE,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=user or None,
        path=path or None,
        http_method="ALERT",
        status_code=_confidence_status(confidence, mitigation),
        resource_display_name=hostname or "SentinelOne",
        file_hash=sha256,
    )


def parse_sentinelone(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []

    def _process(obj: dict) -> None:
        try:
            e = _alert_to_log(obj)
            if e:
                events.append(e)
        except Exception as exc:
            logger.debug("SentinelOne: skipping object: %s", exc)

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                inner = obj.get("data") or obj.get("threats") or obj.get("alerts")
                if isinstance(inner, list):
                    for item in inner:
                        if isinstance(item, dict):
                            _process(item)
                elif obj.get("threatInfo") or obj.get("agentDetectionInfo"):
                    _process(obj)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        _process(item)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("SentinelOne: JSON error: %s", exc)

    logger.info("SentinelOne parser: %d events", len(events))
    return events


def _is_sentinelone(obj: dict) -> bool:
    return ("threatInfo" in obj and "agentDetectionInfo" in obj) or (
        "indicators" in obj and "mitigationStatus" in obj and "threatInfo" in obj
    )


class SentinelOneParser(BaseParser):
    format_name = "sentinelone"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("sentinelone", "s1_", "s1-")):
            pass
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    inner = obj.get("data") or obj.get("threats") or obj.get("alerts")
                    if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                        obj = inner[0]
                    if _is_sentinelone(obj):
                        return True
                elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                    if _is_sentinelone(obj[0]):
                        return True
            except (json.JSONDecodeError, Exception):
                pass
            return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_sentinelone(content)
