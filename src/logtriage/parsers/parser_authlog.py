# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Linux auth.log / secure parser.

Handles both modern (ISO-8601) and legacy (syslog BSD) timestamps without
the <PRI> prefix that distinguishes syslog from auth.log.

Key event types:
  - SSH failed password / invalid user
  - SSH accepted password / publickey
  - SSH connection closed / disconnect
  - sudo usage (command execution)
  - PAM authentication failures
  - su / login events
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Timestamp patterns
_ISO_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)"
    r"\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)

_BSD_TS_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)

_BSD_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# ── message-level patterns ────────────────────────────────────────────────────

_SSH_FAIL_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)",
    re.IGNORECASE,
)
_SSH_ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\S+)",
    re.IGNORECASE,
)
_SSH_INVALID_RE = re.compile(
    r"Invalid user (\S+) from (\S+)",
    re.IGNORECASE,
)
_SUDO_RE = re.compile(
    r"(\S+)\s*:\s+TTY=\S+\s*;\s+PWD=(\S+)\s*;\s+USER=(\S+)\s*;\s+COMMAND=(.*)",
)
_PAM_FAIL_RE = re.compile(
    # [^\n]*? instead of .*? — bounded to one line, avoids cross-line backtracking
    r"pam_unix\(\S+\):\s+authentication failure[^\n]*?(?:user=(\S+))?",
    re.IGNORECASE,
)
# Simplified: no leading .*\s+ — re.search finds the pattern anywhere in the message.
# Guard: only applied when proc_lower contains "su" (see _classify_message).
_SU_RE = re.compile(
    r"(?:from\s+(\S+)\s+to|for\s+user)\s+(\S+)",
    re.IGNORECASE,
)
_MSG_MAX = 2000  # cap message length before running patterns to bound worst-case backtracking


def _parse_iso_ts(ts: str) -> datetime:
    ts = ts.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _parse_bsd_ts(ts: str) -> datetime:
    parts = ts.split()
    if len(parts) < 3:
        return datetime.now(timezone.utc)
    try:
        month = _BSD_MONTHS.get(parts[0].lower(), 1)
        day = int(parts[1])
        h, m, s = (int(x) for x in parts[2].split(":"))
        year = datetime.now(timezone.utc).year
        return datetime(year, month, day, h, m, s, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return datetime.now(timezone.utc)


def _classify_message(
    process: str, message: str
) -> tuple[str | None, str | None, int, str | None]:
    """
    Return (ip_address, user, status_code, path).

    status_code: 200=success/info, 401=auth fail, 403=deny, 400=invalid
    """
    # Cap message length to bound worst-case regex backtracking on adversarial input
    message = message[:_MSG_MAX]
    proc_lower = process.lower()

    # SSH: failed password or invalid user
    m = _SSH_FAIL_RE.search(message) or _SSH_INVALID_RE.search(message)
    if m:
        user, ip = m.group(1), m.group(2)
        return ip, user, 401, f"sshd: {message[:80]}"

    # SSH: accepted
    m = _SSH_ACCEPT_RE.search(message)
    if m:
        user, ip = m.group(1), m.group(2)
        return ip, user, 200, f"sshd: {message[:80]}"

    # sudo
    m = _SUDO_RE.search(message)
    if m:
        initiating_user = m.group(1)
        target_user = m.group(3)
        command = m.group(4)
        return None, initiating_user, 200, f"sudo: {target_user} COMMAND={command[:60]}"

    # PAM failure
    m = _PAM_FAIL_RE.search(message)
    if m:
        user = m.group(1)
        return None, user, 401, f"pam: {message[:80]}"

    # su — only run this pattern when process name confirms it's su/login to avoid
    # the re.search scanning unrelated long messages for the from/for pattern
    if any(kw in proc_lower for kw in ("su", "login")):
        m = _SU_RE.search(message)
        if m:
            return None, m.group(2) or m.group(1), 200, f"su: {message[:80]}"

    # Generic fallback for sshd / login / auth-related processes
    if any(kw in proc_lower for kw in ("sshd", "login", "auth", "pam", "sudo", "su")):
        status = 401 if any(w in message.lower() for w in ("fail", "invalid", "error", "denied")) else 200
        return None, None, status, f"{process}: {message[:80]}"

    return None, None, 200, f"{process}: {message[:80]}"


def _parse_line(line: str) -> LogEvent | None:
    m = _ISO_TS_RE.match(line)
    if m:
        ts_raw, hostname, process, _pid, message = m.groups()
        ts = _parse_iso_ts(ts_raw)
    else:
        m = _BSD_TS_RE.match(line)
        if not m:
            return None
        ts_raw, hostname, process, _pid, message = m.groups()
        ts = _parse_bsd_ts(ts_raw)

    ip, user, status, path = _classify_message(process, message)

    return LogEvent(
        source_format=LogFormat.AUTH_LOG,
        timestamp=ts,
        ip_address=ip,
        user_principal_name=user,
        path=path,
        status_code=status,
        failure_reason=message if status in (401, 403) else None,
        resource_display_name=hostname,
        raw_line=line,
    )


class AuthLogParser(BaseParser):
    format_name = "auth_log"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        # filename hint
        fname = filename.lower()
        if any(fname.endswith(suf) for suf in ("auth.log", "secure", "auth.log.1")):
            return True

        # Content: must look like BSD syslog WITHOUT <NNN> priority prefix
        # (SyslogParser takes lines that start with <NNN>)
        hits = 0
        for line in content.splitlines()[:20]:
            line = line.strip()
            if not line:
                continue
            if re.match(r"<\d+>", line):
                return False  # syslog — leave it for SyslogParser
            if _BSD_TS_RE.match(line) or _ISO_TS_RE.match(line):
                hits += 1
            if hits >= 2:
                return True

        return False

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            ev = _parse_line(line)
            if ev:
                events.append(ev)
        logger.info("auth_log: parsed %d events from %s", len(events), filename)
        return events
