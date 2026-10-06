# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Palo Alto Networks PAN-OS syslog parser (comma-separated log records).

PAN-OS forwards each log entry as one comma-separated record, optionally behind a
BSD/IETF syslog header (which has no commas, so it lands in the unused field 0).
Field positions are fixed per log type, as documented by Palo Alto Networks in
"Syslog Field Descriptions" (the pan-os/10-2 and pan-os/11-1 URLs redirect here):

  https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields
  https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields
  https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/authentication-log-fields

0-based positions read here:
  All types:   0 FUTURE_USE  1 Receive Time  2 Serial Number  3 Type
               4 Threat/Content Type (subtype)  5 FUTURE_USE  6 Generated Time
  TRAFFIC and THREAT (identical through Action):
               7 Source Address  8 Destination Address  9 NAT Source IP  10 NAT Destination IP
               11 Rule Name  12 Source User  13 Destination User  14 Application
               15 Virtual System  16 Source Zone  17 Destination Zone  18 Inbound Interface
               19 Outbound Interface  20 Log Action  21 FUTURE_USE  22 Session ID
               23 Repeat Count  24 Source Port  25 Destination Port  26 NAT Source Port
               27 NAT Destination Port  28 Flags  29 Protocol  30 Action
  THREAT:      31 URL/Filename  32 Threat ID ("name(id)"; only "(9999)" on URL logs)
               33 Category  34 Severity  35 Direction ... 69 Threat Category
  AUTHENTICATION (documented Type "AUTHENTICATION"; real devices also write "AUTH"):
               7 Virtual System  8 Source IP  9 User  10 Normalize User  11 Object
               12 Authentication Policy  13 Repeat Count  14 Authentication ID  15 Vendor
               16 Log Action  17 Server Profile  18 Description  19 Client Type
               20 Event Type  21 Factor Number ...

New releases append fields to the end of a record, so these leading positions are
stable across versions; a short (older or truncated) record yields None for what is
missing. Addresses are validated with ipaddress, so a record in an unexpected layout
never puts a timestamp or a host name into ip_address. Times carry no UTC offset
(firewall local time) and are read as UTC, as in the other parsers.

status_code: TRAFFIC deny/drop/reset -> 403, drop ICMP -> 400; THREAT blocking
actions -> 403, otherwise by severity (critical/high -> 401, medium -> 400);
AUTHENTICATION failure -> 403, success -> 200. The documentation does not enumerate
the Event Type values, so the outcome is matched by keyword ("fail", "deny",
"reject" / "success"); anything else (e.g. "Authentication Timeout") gets no status.
"""
from __future__ import annotations

import csv
import ipaddress
import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Positions shared by every log type
_RECEIVE_TIME, _TYPE, _SUBTYPE, _GENERATED_TIME = 1, 3, 4, 6
# TRAFFIC and THREAT
_SRC, _DST, _SRC_USER, _APP, _DPORT, _PROTO, _ACTION = 7, 8, 12, 14, 25, 29, 30
# THREAT
_URL, _THREAT_ID, _CATEGORY, _SEVERITY, _THREAT_CATEGORY = 31, 32, 33, 34, 69
# AUTHENTICATION
_AUTH_SRC, _AUTH_USER, _AUTH_NORMALIZED_USER, _AUTH_DESCRIPTION, _AUTH_EVENT = 8, 9, 10, 18, 20

# Type values from the "Syslog Field Descriptions" pages (URL, data-filtering and
# WildFire logs are THREAT subtypes), plus spellings real devices also emit: AUTH and
# HIPMATCH. URL, DATA and TUNNEL were accepted before and still are. Tunnel
# inspection's START/END are too generic to use as a format discriminator.
_AUTH_TYPES = frozenset({"AUTHENTICATION", "AUTH"})
_PANOS_TYPES = frozenset({
    "TRAFFIC", "THREAT", *_AUTH_TYPES, "SYSTEM", "CONFIG", "HIP-MATCH", "HIPMATCH",
    "GLOBALPROTECT", "USERID", "IPTAG", "DECRYPTION", "CORRELATION", "SCTP", "GTP",
    "URL", "DATA", "TUNNEL",
})

_TS_FMT = "%Y/%m/%d %H:%M:%S"
_TS_RE = re.compile(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
_PROTO_RE = re.compile(r"[A-Za-z0-9-]{1,32}")
_PORT_RE = re.compile(r"[0-9]{1,5}")
_THREAT_ID_RE = re.compile(r"\(\d+\)$")  # trailing "(8002)" of "SCAN: Host Sweep(8002)"
_UNSET_CATEGORIES = frozenset({"any", "unknown", "n/a"})
_MAX_LABEL = 256  # width of the user_principal_name / resource_display_name columns


def _g(row: list[str], idx: int) -> str | None:
    try:
        v = row[idx].strip()
        return v if v else None
    except IndexError:
        return None


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw, _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _ip(raw: str | None) -> str | None:
    """A real IP address, or None for anything else (empty, 0.0.0.0, a time, a host name)."""
    if not raw:
        return None
    try:
        addr = ipaddress.ip_address(raw.split("%", 1)[0])  # drop an IPv6 zone ("%eth0")
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_loopback:
        return None
    return str(addr)


def _endpoint(ip: str | None, port: str | None) -> str | None:
    if not ip:
        return None
    if not (port and _PORT_RE.fullmatch(port) and int(port) > 0):
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _cap(value: str | None) -> str | None:
    return value[:_MAX_LABEL] if value else None


def _norm(value: str | None) -> str:
    """Lower-case and hyphenate: TRAFFIC records spell actions 'reset both', 'drop ICMP'."""
    return "-".join((value or "").lower().split())


_DENY_ACTIONS = frozenset({"deny", "drop", "block", "reset-both", "reset-client", "reset-server"})


def _action_status(action: str | None) -> int:
    a = _norm(action)
    if a in _DENY_ACTIONS:
        return 403
    if a == "drop-icmp":
        return 400
    return 200


# THREAT actions that stop the traffic: the documented values, plus "drop-packet",
# which real records also use.
_THREAT_BLOCK_ACTIONS = frozenset({
    "deny", "drop", "drop-all-packets", "drop-packet", "reset-client", "reset-server",
    "reset-both", "block", "block-url", "block-ip", "random-drop", "sinkhole",
    "block-continue", "block-override", "override-lockout",
})


def _threat_status(severity: str | None, action: str | None) -> int:
    if _norm(action) in _THREAT_BLOCK_ACTIONS:
        return 403
    s = _norm(severity)
    if s in ("critical", "high"):
        return 401
    if s == "medium":
        return 400
    return 200


def _auth_status(event: str | None) -> int | None:
    e = (event or "").lower()
    if any(word in e for word in ("fail", "deny", "denied", "reject")):
        return 403
    if "success" in e or "succeed" in e:
        return 200
    return None


def _traffic(row: list[str], ts: datetime) -> LogEvent:
    proto = _g(row, _PROTO)
    return LogEvent(
        source_format=LogFormat.PANOS,
        timestamp=ts,
        ip_address=_ip(_g(row, _SRC)),
        user_principal_name=_cap(_g(row, _SRC_USER)),
        app_display_name=_g(row, _APP),
        http_method=proto.upper() if proto and _PROTO_RE.fullmatch(proto) else None,
        path=_endpoint(_ip(_g(row, _DST)), _g(row, _DPORT)),
        status_code=_action_status(_g(row, _ACTION)),
        resource_display_name="PAN-OS/TRAFFIC",
    )


def _threat(row: list[str], ts: datetime) -> LogEvent:
    subtype = _g(row, _SUBTYPE)
    threat = _g(row, _THREAT_ID)
    if not threat or not _THREAT_ID_RE.sub("", threat).strip():
        # URL-filtering records carry only "(9999)" here; the URL is in URL/Filename.
        threat = _g(row, _URL) or threat
    # Category is the URL category or WildFire verdict ("any" otherwise); Threat
    # Category classifies the signature (e.g. sql-injection).
    category = next(
        (v for v in (_g(row, _CATEGORY), _g(row, _THREAT_CATEGORY))
         if v and v.lower() not in _UNSET_CATEGORIES),
        None,
    )
    return LogEvent(
        source_format=LogFormat.PANOS,
        timestamp=ts,
        ip_address=_ip(_g(row, _SRC)),
        user_principal_name=_cap(_g(row, _SRC_USER)),
        app_display_name=_g(row, _APP),
        http_method="THREAT",
        path=threat or "THREAT",
        status_code=_threat_status(_g(row, _SEVERITY), _g(row, _ACTION)),
        resource_display_name=_cap("/".join(p for p in ("PAN-OS/THREAT", subtype, category) if p)),
    )


def _auth(row: list[str], ts: datetime) -> LogEvent:
    event = _g(row, _AUTH_EVENT)
    status = _auth_status(event)
    return LogEvent(
        source_format=LogFormat.PANOS,
        timestamp=ts,
        ip_address=_ip(_g(row, _AUTH_SRC)),
        user_principal_name=_cap(_g(row, _AUTH_USER) or _g(row, _AUTH_NORMALIZED_USER)),
        http_method="AUTH",
        path=event or "AUTH",
        status_code=status,
        failure_reason=(_g(row, _AUTH_DESCRIPTION) or event) if status == 403 else None,
        resource_display_name="PAN-OS/AUTH",
    )


def _row_to_log(row: list[str]) -> LogEvent | None:
    log_type = (_g(row, _TYPE) or "").upper()
    if log_type not in _PANOS_TYPES:
        return None  # a header row (e.g. a web-UI CSV export) or not a PAN-OS record

    ts = (
        _parse_ts(_g(row, _GENERATED_TIME))
        or _parse_ts(_g(row, _RECEIVE_TIME))
        or datetime.now(timezone.utc)
    )
    if log_type == "TRAFFIC":
        return _traffic(row, ts)
    if log_type == "THREAT":
        return _threat(row, ts)
    if log_type in _AUTH_TYPES:
        return _auth(row, ts)

    # Other log types: a minimal event. Position 7 is the source address in the
    # DECRYPTION, SCTP and CORRELATION layouts and something else (a user, a vsys,
    # a host) in others, which the address check turns into None.
    return LogEvent(
        source_format=LogFormat.PANOS,
        timestamp=ts,
        ip_address=_ip(_g(row, _SRC)),
        path=log_type,
        http_method=log_type,
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
            event = _row_to_log(next(csv.reader([line])))
        except Exception as exc:
            logger.debug("PAN-OS: skipping line: %s", exc)
            continue
        if event:
            events.append(event)
    logger.info("PAN-OS parser: %d events", len(events))
    return events


def _is_panos_line(line: str) -> bool:
    """A PAN-OS log type at position 3 and a PAN-OS time at Receive or Generated Time."""
    parts = line.split(",", 7)
    if len(parts) < 7 or parts[_TYPE].strip().upper() not in _PANOS_TYPES:
        return False
    return any(_TS_RE.fullmatch(parts[i].strip()) for i in (_RECEIVE_TIME, _GENERATED_TIME))


class PanosParser(BaseParser):
    format_name = "panos"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        checked = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if _is_panos_line(line):
                return True
            checked += 1
            if checked >= 10:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_panos(content)
