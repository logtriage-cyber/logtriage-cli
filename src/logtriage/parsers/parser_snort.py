# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Snort IDS alert_fast / alert_full log parser.

alert_fast format (one line per alert):
  01/15-14:32:01.234567  [**] [1:2001219:20] ET SCAN SSH Scan [**] \
  [Classification: Attempted Info Leak] [Priority: 2] {TCP} 185.220.101.42:54321 -> 10.0.0.50:22

alert_full adds a packet dump block after each alert header — we skip the dump lines
and parse only the alert header lines that match the [**] pattern.

Reference: https://www.snort.org/documents
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Priority 1=high→403, 2=medium→401, 3=low→400
_PRIORITY_STATUS: dict[int, int] = {1: 403, 2: 401, 3: 400}

# alert_fast line pattern
# Groups: timestamp, gid:sid:rev, signature, classification (opt), priority (opt), proto, src_ip, dst_ip
_ALERT_RE = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)"   # timestamp
    r"\s+\[\*\*\]\s+"
    r"\[(\d+:\d+:\d+)\]\s+"                          # [gid:sid:rev]
    r"(.+?)\s+\[\*\*\]"                              # signature text
    r"(?:.*?\[Classification:\s*([^\]]+)\])?"        # optional Classification
    r"(?:.*?\[Priority:\s*(\d+)\])?"                 # optional Priority
    r"(?:.*?\{(\w+)\})?"                             # optional {PROTO}
    r"(?:.*?(\d+\.\d+\.\d+\.\d+)(?::\d+)?"          # src IP
    r".*?->\s*(\d+\.\d+\.\d+\.\d+))?",              # dst IP
    re.DOTALL,
)


def _parse_ts(raw: str) -> datetime:
    """Parse MM/DD-HH:MM:SS[.ffffff] — no year, assume current UTC year."""
    year = datetime.now(timezone.utc).year
    try:
        if "." in raw:
            return datetime.strptime(f"{year}/{raw}", "%Y/%m/%d-%H:%M:%S.%f").replace(
                tzinfo=timezone.utc
            )
        return datetime.strptime(f"{year}/{raw}", "%Y/%m/%d-%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return datetime.now(timezone.utc)


def parse_snort(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if "[**]" not in line:
            continue
        m = _ALERT_RE.search(line)
        if not m:
            continue
        ts_raw, _sid, signature, classification, priority_str, proto, src_ip, _dst_ip = m.groups()
        priority = int(priority_str) if priority_str else 3
        try:
            events.append(
                LogEvent(
                    source_format=LogFormat.SNORT,
                    timestamp=_parse_ts(ts_raw),
                    ip_address=src_ip,
                    path=signature.strip(),
                    resource_display_name=classification.strip() if classification else None,
                    http_method=proto,
                    status_code=_PRIORITY_STATUS.get(priority, 400),
                    raw_line=line,
                )
            )
        except Exception as exc:
            logger.debug("Snort: skipping line: %s", exc)

    logger.info("Snort parser: %d alerts parsed", len(events))
    return events


class SnortParser(BaseParser):
    """Plugin-registry entry for Snort alert_fast / alert_full logs."""

    format_name = "snort"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "snort" in filename.lower():
            return True
        # Look for the distinctive [**] [gid:sid:rev] pattern in the first 20 lines
        count = 0
        for line in content.splitlines():
            if "[**]" in line and re.search(r"\[\d+:\d+:\d+\]", line):
                return True
            count += 1
            if count > 20:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_snort(content)
