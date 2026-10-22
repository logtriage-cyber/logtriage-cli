# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Azure NSG flow logs (v1, v2) and VNet flow logs parser.

Reference:
  https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview
  https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview

NSG flow logs (category NetworkSecurityGroupFlowEvent):
  records[].properties.flows[].rule          → NSG rule name
  records[].properties.flows[].flows[].flowTuples[]
    v1 tuple: timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,decision
    v2 tuple: timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,decision,
              flowState,packetsS2D,bytesS2D,packetsD2S,bytesD2S
  Direction: I=inbound, O=outbound · Decision: A=allow, D=deny · Protocol: T=TCP, U=UDP

VNet flow logs (category FlowLogFlowEvent; NSG flow logs' replacement — Azure
stopped new NSG flow logs in 2025):
  records[].flowRecords.flows[].flowGroups[].rule / .flowTuples[]
    tuple: timestamp(ms),srcIP,dstIP,srcPort,dstPort,protocol(IANA number),direction,
           flowState,encryption,packetsS2D,bytesS2D,packetsD2S,bytesD2S
  Flow state: B=begin, C=continuing, E=end, D=denied
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers import json_input
from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_IANA_PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}


def _proto_name(code: str) -> str:
    return {"T": "TCP", "U": "UDP"}.get(code.upper(), _IANA_PROTOCOLS.get(code, code))


def _timestamp(raw: str) -> datetime:
    try:
        value = int(raw)
    except ValueError:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(value / 1000 if value > 10**11 else value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return datetime.now(timezone.utc)


def _int(parts: list[str], index: int) -> int | None:
    try:
        return int(parts[index]) if len(parts) > index and parts[index] else None
    except ValueError:
        return None


def _parse_tuple(
    tuple_str: str,
    rule: str,
    resource_id: str | None,
    vnet: bool = False,
) -> LogEvent | None:
    parts = str(tuple_str).split(",")
    if len(parts) < 8:
        return None

    ts_raw, src_ip, dst_ip, src_port, dst_port, proto_code, direction, decision = parts[:8]

    proto = _proto_name(proto_code)
    # NSG: the 8th field is the decision (A/D); VNet: the flow state, D = denied
    allowed = decision.upper() != "D" if vnet else decision.upper() == "A"
    status_code = 200 if allowed else 403
    dir_label = "inbound" if direction.upper() == "I" else "outbound"
    bytes_s2d = _int(parts, 10)

    failure_reason = None if allowed else f"{'Rule' if vnet else 'NSG rule'} '{rule}' denied {dir_label} {proto}"

    return LogEvent(
        source_format=LogFormat.AZURE_NSG,
        timestamp=_timestamp(ts_raw),
        ip_address=src_ip,
        path=f"{dst_ip}:{dst_port}/{proto}",
        status_code=status_code,
        failure_reason=failure_reason,
        response_size_bytes=bytes_s2d,
        resource_display_name=rule,
        raw_line=str(tuple_str),
    )


def _is_flow_record(record: dict[str, Any]) -> bool:
    category = str(record.get("category", ""))
    props = record.get("properties")
    flow_records = record.get("flowRecords")
    return (
        category in ("NetworkSecurityGroupFlowEvent", "FlowLogFlowEvent")
        or (isinstance(props, dict) and "flows" in props)
        or (isinstance(flow_records, dict) and "flows" in flow_records)
    )


def _record_events(record: dict[str, Any]) -> list[LogEvent]:
    events: list[LogEvent] = []
    resource_id = record.get("resourceId") or record.get("targetResourceID")

    props = record.get("properties") or {}
    for rule_group in props.get("flows", []) if isinstance(props, dict) else []:
        rule = rule_group.get("rule", "unknown-rule")
        for mac_group in rule_group.get("flows", []):
            for tup in mac_group.get("flowTuples", []):
                if ev := _parse_tuple(tup, rule, resource_id):
                    events.append(ev)

    flow_records = record.get("flowRecords") or {}
    for flow in flow_records.get("flows", []) if isinstance(flow_records, dict) else []:
        for group in flow.get("flowGroups", []):
            rule = group.get("rule", "unknown-rule")
            for tup in group.get("flowTuples", []):
                if ev := _parse_tuple(tup, rule, resource_id, vnet=True):
                    events.append(ev)
    return events


class AzureNsgParser(BaseParser):
    format_name = "azure_nsg"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content, ("records",), n=1)
        return bool(head) and _is_flow_record(head[0])

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        for record in json_input.records(content, ("records",)):
            events.extend(_record_events(record))
        logger.info("azure_nsg: parsed %d events from %s", len(events), filename)
        return events
