# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS VPC Flow Logs parser — v2 through v5.

Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html

Standard v2 header:
  version account-id interface-id srcaddr dstaddr srcport dstport protocol
  packets bytes start end action log-status

v5 appends additional fields; the parser reads the header dynamically.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# v2 mandatory columns — used for detection and as fallback column list
_V2_COLUMNS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status",
]

# IANA protocol numbers → names
_PROTO_NAMES: dict[str, str] = {
    "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP",
}


def _proto_name(num: str) -> str:
    return _PROTO_NAMES.get(num, num)


def _parse_line(row: dict[str, str]) -> LogEvent | None:
    action = row.get("action", "").upper()
    if action == "-":          # NODATA / SKIPDATA records carry no useful fields
        return None

    srcaddr = row.get("srcaddr") or row.get("pkt-srcaddr")
    dstaddr = row.get("dstaddr") or row.get("pkt-dstaddr")
    srcport = row.get("srcport")
    dstport = row.get("dstport")
    protocol_raw = row.get("protocol", "")
    proto = _proto_name(protocol_raw)

    start_ts = row.get("start", "")
    try:
        ts = datetime.fromtimestamp(int(start_ts), tz=timezone.utc)
    except (ValueError, OSError):
        ts = datetime.now(timezone.utc)

    status_code = 200 if action == "ACCEPT" else 403
    failure_reason = None if action == "ACCEPT" else f"VPC flow REJECT — {proto} {srcaddr}:{srcport} → {dstaddr}:{dstport}"

    # Bytes transferred
    try:
        nbytes = int(row.get("bytes", 0))
    except ValueError:
        nbytes = None

    return LogEvent(
        source_format=LogFormat.VPC_FLOW,
        timestamp=ts,
        ip_address=srcaddr,
        path=f"{dstaddr}:{dstport}/{proto}" if dstaddr else None,
        status_code=status_code,
        failure_reason=failure_reason,
        response_size_bytes=nbytes,
        resource_display_name=row.get("interface-id"),
        raw_line=str(row),
    )


class VpcFlowParser(BaseParser):
    format_name = "vpc_flow"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            # Header line is unambiguous
            if "srcaddr" in line and "dstaddr" in line and ("action" in line or "log-status" in line):
                return True
            # Non-header data line: check for ACCEPT/REJECT + numeric fields
            if ("ACCEPT" in line or "REJECT" in line) and "eni-" in line:
                return True
            break
        return False

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        columns: list[str] = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            # First non-empty line is the header when it contains column names
            if not columns:
                if "srcaddr" in line and "dstaddr" in line:
                    columns = line.split()
                    continue
                # No explicit header — use v2 defaults
                columns = _V2_COLUMNS

            parts = line.split()
            if len(parts) < len(columns):
                # Pad with "-" for optional trailing columns
                parts += ["-"] * (len(columns) - len(parts))
            row = dict(zip(columns, parts))

            ev = _parse_line(row)
            if ev:
                events.append(ev)

        logger.info("vpc_flow: parsed %d events from %s", len(events), filename)
        return events
