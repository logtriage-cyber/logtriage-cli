# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Fortinet FortiGate log parser.

FortiGate logs are space-separated key=value pairs, optionally preceded by
a syslog header. Discriminator: devid=FG (or devname= present).

Common fields: date=, time=, devid=, logid=, type=, subtype=, level=,
               srcip=, dstip=, srcport=, dstport=, action=, user=, msg=,
               app=, service=, policyname=, url=, reqtype=, method=

References:
  https://docs.fortinet.com/document/fortigate/7.4.0/log-message-reference
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
)

# Matches key=value or key="value with spaces"
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

_DENY_ACTIONS = frozenset({
    "deny", "block", "blocked", "drop", "dropped",
    "server-rst", "client-rst", "timeout",
})
_ALLOW_ACTIONS = frozenset({"accept", "allow", "pass", "passthrough"})


def _parse_ts(date_str: str, time_str: str) -> datetime:
    raw = f"{date_str} {time_str}".strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _action_status(action: str | None, level: str | None) -> int:
    a = (action or "").lower()
    lv = (level or "").lower()
    if a in _DENY_ACTIONS:
        return 403
    if lv in ("critical", "alert", "emergency"):
        return 403
    if lv == "error":
        return 401
    if lv == "warning":
        return 400
    return 200


def _parse_kv(line: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        kv[key] = val or ""
    return kv


def _parse_line(line: str) -> LogEvent | None:
    line = _SYSLOG_PREFIX_RE.sub("", line, count=1).strip()
    if not line:
        return None

    kv = _parse_kv(line)
    if not kv:
        return None

    # Must look like FortiGate
    if not (kv.get("devid", "").startswith("FG") or
            kv.get("devid", "").startswith("FW") or
            "devname" in kv or "logid" in kv):
        return None

    date_s = kv.get("date", "")
    time_s = kv.get("time", "")
    ts = _parse_ts(date_s, time_s)

    src_ip = kv.get("srcip") or kv.get("src_ip") or kv.get("remip")
    user = kv.get("user") or kv.get("unauthuser") or kv.get("username")
    ua = kv.get("agent")
    action = kv.get("action")
    level = kv.get("level")
    url = kv.get("url") or kv.get("hostname") or kv.get("service") or kv.get("msg", "")[:120]
    method = (kv.get("method") or kv.get("reqtype") or "").upper() or None
    app = kv.get("app") or kv.get("appcat")

    return LogEvent(
        source_format=LogFormat.FORTIGATE,
        timestamp=ts,
        ip_address=src_ip or None,
        user_principal_name=user or None,
        user_agent=ua or None,
        http_method=method,
        path=url or None,
        status_code=_action_status(action, level),
        resource_display_name=f"FortiGate/{app}" if app else "FortiGate",
    )


def parse_fortigate(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        if not line.strip():
            continue
        try:
            e = _parse_line(line)
            if e:
                events.append(e)
        except Exception as exc:
            logger.debug("FortiGate: skipping line: %s", exc)
    logger.info("FortiGate parser: %d events", len(events))
    return events


class FortiGateParser(BaseParser):
    format_name = "fortigate"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("fortigate", "fortinet", "fortifw")):
            pass
        count = 0
        for line in content.splitlines():
            stripped = _SYSLOG_PREFIX_RE.sub("", line.strip(), count=1)
            if not stripped:
                continue
            kv = _parse_kv(stripped)
            if kv.get("devid", "").startswith(("FG", "FW")) or (
                "devname" in kv and "logid" in kv and ("srcip" in kv or "action" in kv)
            ):
                return True
            count += 1
            if count >= 10:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_fortigate(content)
