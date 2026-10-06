# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Palo Alto Networks PAN-OS native CSV syslog parser.

PAN-OS writes comma-separated log records. The second field is always the log type:
  TRAFFIC, THREAT, AUTH, HIPMATCH, URL, DATA, TUNNEL, USERID, DECRYPTION, etc.

Field positions are fixed per log type (PAN-OS Log Reference):
  Common fields 0-5: domain, receive_time, serial, type, subtype, time_generated
  TRAFFIC fields:
    6=src  7=dst  8=natsrc  9=natdst  10=rulename  11=srcuser  12=dstuser
    13=srczn  14=dstzn  15=inbound_if  16=outbound_if  17=logfwdprofile  18=(pad)
    19=sessionid  20=repeatcnt  21=sport  22=dport  23=natsport  24=natdport
    25=flags  26=proto  27=action  28=bytes  29=bytes_sent  30=bytes_rcvd  …
  THREAT fields:
    6=src  7=dst  ...  11=srcuser  12=dstuser  ...  27=action  28=threat/content-name
    29=category  30=severity  31=direction  …
  AUTH fields:
    6=srcip  7=user  8=normalize-user  9=object  10=authpolicy  11=repeatcnt  12=authid
    13=vendor  14=logprofile  15=desc  16=clienttype  17=event  18=factorno
    19=seqno  20=actionflags  21=vsys  22=vsys_name  …
"""
from __future__ import annotations

import csv
import io
import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_TS_FMT = "%Y/%m/%d %H:%M:%S"


def _parse_ts(raw: str) -> datetime:
    try:
        return datetime.strptime(raw.strip(), _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _g(row: list[str], idx: int) -> str | None:
    try:
        v = row[idx].strip()
        return v if v else None
    except IndexError:
        return None


def _action_status(action: str | None) -> int:
    a = (action or "").lower()
    if a in ("deny", "drop", "block", "reset-both", "reset-client", "reset-server"):
        return 403
    if a in ("drop-icmp",):
        return 400
    return 200


def _threat_status(severity: str | None, action: str | None) -> int:
    s = (severity or "").lower()
    a = (action or "").lower()
    if a in ("block", "block-url", "block-ip", "drop", "reset-both"):
        return 403
    if s in ("critical", "high"):
        return 401
    if s in ("medium",):
        return 400
    return 200


def _row_to_log(row: list[str]) -> LogEvent | None:
    if len(row) < 5:
        return None

    log_type = _g(row, 3) or ""
    ts = _parse_ts(_g(row, 1) or "")

    if log_type.upper() == "TRAFFIC":
        src = _g(row, 6)
        user = _g(row, 11)
        proto = _g(row, 26)
        action = _g(row, 27)
        dport = _g(row, 22)
        dst = _g(row, 7)
        path = f"{dst}:{dport}" if dst and dport else dst
        return LogEvent(
            source_format=LogFormat.PANOS,
            timestamp=ts,
            ip_address=src,
            user_principal_name=user,
            http_method=(proto or "").upper() or None,
            path=path,
            status_code=_action_status(action),
            resource_display_name="PAN-OS/TRAFFIC",
        )

    if log_type.upper() == "THREAT":
        src = _g(row, 6)
        user = _g(row, 11)
        action = _g(row, 27)
        threat_name = _g(row, 28)
        severity = _g(row, 30)
        return LogEvent(
            source_format=LogFormat.PANOS,
            timestamp=ts,
            ip_address=src,
            user_principal_name=user,
            path=threat_name or "THREAT",
            http_method="THREAT",
            status_code=_threat_status(severity, action),
            resource_display_name="PAN-OS/THREAT",
        )

    if log_type.upper() == "AUTH":
        src = _g(row, 6)
        user = _g(row, 7)
        event = _g(row, 17)
        return LogEvent(
            source_format=LogFormat.PANOS,
            timestamp=ts,
            ip_address=src,
            user_principal_name=user,
            path=event or "AUTH",
            http_method="AUTH",
            status_code=403 if (event or "").lower() in ("auth-fail", "failure") else 200,
            resource_display_name="PAN-OS/AUTH",
        )

    # Generic fallback for other log types
    src = _g(row, 6)
    return LogEvent(
        source_format=LogFormat.PANOS,
        timestamp=ts,
        ip_address=src,
        path=log_type,
        http_method=log_type.upper() or None,
        status_code=200,
        resource_display_name="PAN-OS",
    )


def parse_panos(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            reader = csv.reader(io.StringIO(line))
            for row in reader:
                e = _row_to_log(row)
                if e:
                    events.append(e)
        except Exception as exc:
            logger.debug("PAN-OS: skipping line: %s", exc)
    logger.info("PAN-OS parser: %d events", len(events))
    return events


# PAN-OS log type values used as discriminator
_PANOS_TYPES = frozenset({"TRAFFIC", "THREAT", "AUTH", "URL", "DATA", "HIPMATCH", "TUNNEL", "USERID", "DECRYPTION", "GLOBALPROTECT"})

_PANOS_SERIAL_RE = re.compile(r"^\d{10,},")  # serial number in field 2


def _is_panos_line(line: str) -> bool:
    parts = line.split(",", 5)
    if len(parts) < 4:
        return False
    log_type = parts[3].strip().upper()
    return log_type in _PANOS_TYPES


class PanosParser(BaseParser):
    format_name = "panos"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("panos", "pan-os", "panorama", "palo")):
            pass
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if _is_panos_line(line):
                return True
            count += 1
            if count >= 10:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_panos(content)
