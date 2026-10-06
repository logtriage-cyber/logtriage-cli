# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Azure NSG Flow Logs parser (v1 and v2).

Reference:
  https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview

Record structure:
  records[].properties.flows[].rule          → NSG rule name
  records[].properties.flows[].flows[].flowTuples[]
    v1 tuple: timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,decision
    v2 tuple: timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,decision,
              flowState,packetsS2D,bytesS2D,packetsD2S,bytesD2S

Direction: I=inbound, O=outbound
Decision:  A=allow,   D=deny
Protocol:  T=TCP,     U=UDP
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)


def _proto_name(code: str) -> str:
    return {"T": "TCP", "U": "UDP"}.get(code.upper(), code)


def _parse_tuple(
    tuple_str: str,
    rule: str,
    resource_id: str | None,
) -> LogEvent | None:
    parts = tuple_str.split(",")
    if len(parts) < 8:
        return None

    ts_raw, src_ip, dst_ip, src_port, dst_port, proto_code, direction, decision = parts[:8]

    try:
        ts = datetime.fromtimestamp(int(ts_raw), tz=timezone.utc)
    except (ValueError, OSError):
        ts = datetime.now(timezone.utc)

    proto = _proto_name(proto_code)
    allowed = decision.upper() == "A"
    status_code = 200 if allowed else 403
    dir_label = "inbound" if direction.upper() == "I" else "outbound"

    try:
        bytes_s2d = int(parts[10]) if len(parts) > 10 and parts[10] else None
    except ValueError:
        bytes_s2d = None

    failure_reason = None if allowed else f"NSG rule '{rule}' denied {dir_label} {proto}"

    return LogEvent(
        source_format=LogFormat.AZURE_NSG,
        timestamp=ts,
        ip_address=src_ip,
        path=f"{dst_ip}:{dst_port}/{proto}",
        status_code=status_code,
        failure_reason=failure_reason,
        response_size_bytes=bytes_s2d,
        resource_display_name=rule,
        raw_line=tuple_str,
    )


class AzureNsgParser(BaseParser):
    format_name = "azure_nsg"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        stripped = content.strip()
        if not stripped.startswith("{"):
            return False
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return False
        records = data.get("records")
        if not isinstance(records, list) or not records:
            return False
        first = records[0]
        return (
            first.get("category") == "NetworkSecurityGroupFlowEvent"
            or (
                isinstance(first.get("properties"), dict)
                and "flows" in first["properties"]
            )
        )

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("azure_nsg: JSON parse error in %s: %s", filename, exc)
            return events

        resource_id: str | None = None

        for record in data.get("records", []):
            resource_id = record.get("resourceId")
            props = record.get("properties", {})

            for rule_group in props.get("flows", []):
                rule = rule_group.get("rule", "unknown-rule")
                for mac_group in rule_group.get("flows", []):
                    for tup in mac_group.get("flowTuples", []):
                        ev = _parse_tuple(tup, rule, resource_id)
                        if ev:
                            events.append(ev)

        logger.info("azure_nsg: parsed %d events from %s", len(events), filename)
        return events
