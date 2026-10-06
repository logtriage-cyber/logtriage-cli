# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
IBM QRadar LEEF (Log Event Extended Format) parser.

Supports LEEF 1.0 and LEEF 2.0.
Header format: LEEF:version|Vendor|Product|Version|EventID[|delimiter]
Attributes are tab-delimited (LEEF 1.0) or delimited by the optional 6th field (LEEF 2.0).

Reference: https://www.ibm.com/docs/en/dsm?topic=leef-tokens-explained
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?\w{3}\s+\d+ \d{2}:\d{2}:\d{2}(?:\s+\S+)?\s+", re.ASCII
)

# LEEF 2.0 delimiter field e.g. "x09" (hex tab) or a literal char
def _decode_delimiter(raw: str) -> str:
    raw = raw.strip()
    if re.match(r"^x[0-9a-fA-F]{2}$", raw):
        return bytes.fromhex(raw[1:]).decode("latin-1")
    if raw.startswith("0x") or raw.startswith("0X"):
        return bytes.fromhex(raw[2:]).decode("latin-1")
    return raw or "\t"


def _parse_leef_ts(val: str | None) -> datetime:
    if not val:
        return datetime.now(timezone.utc)
    for fmt in (
        "%b %d %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(val, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _status_from_leef(attrs: dict[str, str]) -> int:
    sev = attrs.get("sev", "").lower()
    cat = attrs.get("cat", "").lower()
    action = attrs.get("action", "").lower()
    if action in ("block", "deny", "drop", "reject"):
        return 403
    if "fail" in cat or "fail" in action:
        return 401
    if sev in ("high", "critical") or sev.isdigit() and int(sev) >= 7:
        return 400
    return 200


def _parse_line(line: str) -> LogEvent | None:
    # Strip syslog prefix if present
    line = _SYSLOG_PREFIX_RE.sub("", line, count=1).strip()
    if not line.upper().startswith("LEEF:"):
        return None

    parts = line.split("|", 5)
    if len(parts) < 5:
        return None

    vendor = parts[1]
    product = parts[2]
    # version = parts[3]
    event_id = parts[4]

    # Determine attribute delimiter
    attr_delim = "\t"
    attr_blob = parts[5] if len(parts) == 6 else ""

    if attr_blob and not attr_blob.startswith("\t") and "|" not in attr_blob:
        # LEEF 2.0: 6th pipe segment may be "x09\tkey=val…"
        maybe_delim, _, rest = attr_blob.partition("\t")
        if re.match(r"^(?:x[0-9a-fA-F]{2}|0x[0-9a-fA-F]{2}|.)$", maybe_delim):
            attr_delim = _decode_delimiter(maybe_delim)
            attr_blob = rest

    attrs: dict[str, str] = {}
    for token in attr_blob.split(attr_delim):
        token = token.strip()
        if "=" in token:
            k, _, v = token.partition("=")
            attrs[k.strip()] = v.strip()

    ts = _parse_leef_ts(attrs.get("devTime") or attrs.get("rt") or attrs.get("startTime"))
    ip = attrs.get("src") or attrs.get("srcip") or attrs.get("sourceAddress")
    user = attrs.get("usrName") or attrs.get("dstUsrName") or attrs.get("srcUsrName")
    ua = attrs.get("requestClientApplication") or attrs.get("userAgent")
    path = attrs.get("request") or attrs.get("url") or event_id
    method = (attrs.get("requestMethod") or attrs.get("proto") or "").upper() or None

    return LogEvent(
        source_format=LogFormat.LEEF,
        timestamp=ts,
        ip_address=ip,
        user_principal_name=user,
        user_agent=ua,
        http_method=method,
        path=path,
        status_code=_status_from_leef(attrs),
        resource_display_name=f"{vendor}/{product}",
    )


def parse_leef(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        if not line.strip():
            continue
        try:
            e = _parse_line(line)
            if e:
                events.append(e)
        except Exception as exc:
            logger.debug("LEEF: skipping line: %s", exc)
    logger.info("LEEF parser: %d events", len(events))
    return events


class LeefParser(BaseParser):
    format_name = "leef"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Strip syslog prefix before checking
            stripped = _SYSLOG_PREFIX_RE.sub("", stripped, count=1)
            return stripped.upper().startswith("LEEF:")
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_leef(content)
