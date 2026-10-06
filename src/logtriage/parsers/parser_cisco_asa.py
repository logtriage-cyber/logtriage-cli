# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Cisco ASA / FTD syslog parser.

Message format:
  [optional syslog prefix] %ASA-severity-mnemonic: message body

Severity levels 1-3 → critical/error → 403
Severity 4         → warning        → 401
Severity 5         → notification   → 400
Severity 6-7       → info/debug     → 200

Common mnemonics handled:
  106001/106006/106015/106023 — ACL/access-list deny
  302013/302014/302015/302016 — connection build/teardown
  713228/722051/725001-725007 — VPN
  338001-338004               — botnet filter
  430003                      — AMP/malware
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Matches the %ASA-severity-mnemonic: portion
_MSG_ID_RE = re.compile(r"%(?:ASA|FTD|PIX)-(\d)-(\w+):\s*(.*)", re.DOTALL)

# Syslog timestamp prefix patterns
_SYSLOG_TS_RE = re.compile(
    r"^(?:<\d+>)?"                              # optional PRI
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?)"  # timestamp
    r"\s+\S+\s+"                                # hostname
)

# IP extraction helpers
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SRC_PATTERNS = [
    re.compile(r"(?:src|source)\s+(?:\w+:)?(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?", re.I),
    re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?(?:\s+to\s+)?", re.I),
    re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})/\d+\s+to\s+\d"),  # IP/port to IP/port
]

_DENY_MNEMONICS = frozenset({
    "106001", "106006", "106007", "106010", "106014", "106015", "106016",
    "106017", "106020", "106021", "106022", "106023", "106100",
    "338001", "338002", "338003", "338004",  # botnet
    "430003",                                 # AMP malware
})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    for fmt in (
        "%b %d %H:%M:%S %Y",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            return dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _extract_src_ip(msg_body: str) -> str | None:
    for pat in _SRC_PATTERNS:
        m = pat.search(msg_body)
        if m:
            return m.group(1)
    # fallback: first IP in message
    m = _IP_RE.search(msg_body)
    return m.group(1) if m else None


def _parse_line(line: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    ts = datetime.now(timezone.utc)
    ts_m = _SYSLOG_TS_RE.match(line)
    if ts_m:
        ts = _parse_ts(ts_m.group(1))
        line = line[ts_m.end():]

    m = _MSG_ID_RE.search(line)
    if not m:
        return None

    severity_str, mnemonic, body = m.group(1), m.group(2), m.group(3)
    severity = int(severity_str)

    if severity <= 3 or mnemonic in _DENY_MNEMONICS:
        status = 403
    elif severity == 4:
        status = 401
    elif severity == 5:
        status = 400
    else:
        status = 200

    src_ip = _extract_src_ip(body)
    # Extract user from "uauth" or "user" keywords
    user_m = re.search(r"(?:uauth|user)\s+<([^>]+)>", body, re.I)
    user = user_m.group(1) if user_m else None

    return LogEvent(
        source_format=LogFormat.CISCO_ASA,
        timestamp=ts,
        ip_address=src_ip,
        user_principal_name=user,
        path=f"%ASA-{severity}-{mnemonic}",
        status_code=status,
        resource_display_name="Cisco ASA",
        raw_line=line[:500],
    )


def parse_cisco_asa(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        try:
            e = _parse_line(line)
            if e:
                events.append(e)
        except Exception as exc:
            logger.debug("CiscoASA: skipping line: %s", exc)
    logger.info("CiscoASA parser: %d events", len(events))
    return events


class CiscoAsaParser(BaseParser):
    format_name = "cisco_asa"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("asa", "ftd", "pix", "cisco")):
            pass
        count = 0
        for line in content.splitlines():
            if not line.strip():
                continue
            if _MSG_ID_RE.search(line):
                return True
            count += 1
            if count >= 30:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_cisco_asa(content)
