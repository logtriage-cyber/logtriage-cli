# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Windows Event Log parser.

Accepts two input formats:
  1. XML export — produced by `wevtutil qe Security /f:xml > events.xml`,
     Event Viewer "Save As XML", or SIEM XML exports.  Content starts with
     `<Events>` or individual `<Event xmlns='...'>` elements.

  2. Binary .evtx — requires the optional `python-evtx` package (pip install
     python-evtx).  When the analysis task detects a .evtx filename it calls
     `parse_evtx_binary(file_path)` directly, bypassing the text pipeline.

Security-relevant Event IDs supported:
  4624  Successful logon
  4625  Failed logon
  4648  Logon with explicit credentials
  4672  Special privileges assigned to new logon
  4688  Process created
  4698  Scheduled task created
  4702  Scheduled task updated
  4720  User account created
  4722  User account enabled
  4724  Password reset attempt
  4728  Member added to global security group
  4732  Member added to local group
  4756  Member added to universal group
  4768  Kerberos TGT requested
  4769  Kerberos service ticket requested
  4771  Kerberos pre-authentication failed
  4776  NTLM credential validation
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

try:
    import defusedxml.ElementTree as ET  # type: ignore[import-untyped]
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]  # fallback if defusedxml not installed

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

_HASH_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_HASH_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")

logger = logging.getLogger(__name__)

# Windows Security Event Log XML namespace
_NS_URL = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"e": _NS_URL}

# Magic bytes for a binary .evtx file (first 8 bytes: ElfFile\x00)
_EVTX_MAGIC = b"ElfFile\x00"

# Optional python-evtx import
try:
    import Evtx.Evtx as _evtx_lib  # type: ignore[import-untyped]
    _EVTX_AVAILABLE = True
except ImportError:
    _EVTX_AVAILABLE = False

# ---------------------------------------------------------------------------
# EventID → (path, http_method) mapping
# ---------------------------------------------------------------------------

_EVENTID_META: dict[int, dict[str, str]] = {
    4624: {"path": "/windows/logon",              "method": "POST"},
    4625: {"path": "/windows/logon",              "method": "POST"},
    4648: {"path": "/windows/logon/explicit",     "method": "POST"},
    4672: {"path": "/windows/admin/privileges",   "method": "POST"},
    4688: {"path": "/windows/process",            "method": "POST"},
    4698: {"path": "/windows/scheduler/task",     "method": "POST"},
    4702: {"path": "/windows/scheduler/task",     "method": "PUT"},
    4720: {"path": "/windows/admin/users",        "method": "POST"},
    4722: {"path": "/windows/admin/users",        "method": "PUT"},
    4724: {"path": "/windows/admin/users/reset",  "method": "POST"},
    4728: {"path": "/windows/admin/groups/global","method": "POST"},
    4732: {"path": "/windows/admin/groups/local", "method": "POST"},
    4756: {"path": "/windows/admin/groups/universal", "method": "POST"},
    4768: {"path": "/windows/auth/kerberos/tgt",  "method": "POST"},
    4769: {"path": "/windows/auth/kerberos/service", "method": "POST"},
    4771: {"path": "/windows/auth/kerberos",      "method": "POST"},
    4776: {"path": "/windows/auth/ntlm",          "method": "POST"},
}

# EventIDs that always represent a failure
_FAILURE_EVENTIDS = {4625, 4771}
# EventIDs where failure is indicated by a non-zero Status field (0x0 = success)
_STATUS_FIELD_EVENTIDS = {4768, 4769, 4776}
# EventIDs that map to 200 on success
_SUCCESS_EVENTIDS = {4624, 4648, 4672, 4688, 4698, 4702, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4776}


# ---------------------------------------------------------------------------
# XML parsing helpers
# ---------------------------------------------------------------------------


def _find(element: ET.Element, tag: str) -> ET.Element | None:
    """Find a child element, trying namespaced and non-namespaced variants.

    Must use explicit None check — ET.Element is falsy when it has no children,
    so `or` would skip a valid leaf element like <EventID>4624</EventID>.
    """
    result = element.find(f"e:{tag}", _NS)
    if result is not None:
        return result
    return element.find(tag)


def _findall(element: ET.Element, tag: str) -> list[ET.Element]:
    result = element.findall(f"e:{tag}", _NS)
    return result if result else element.findall(tag)


def _text(element: ET.Element, tag: str) -> str | None:
    el = _find(element, tag)
    return el.text.strip() if el is not None and el.text else None


def _parse_timestamp(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        clean = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except (ValueError, AttributeError):
        logger.debug("Could not parse EVTX timestamp: %r", raw)
        return datetime.now(timezone.utc)


def _clean_ip(raw: str | None) -> str | None:
    """Return None for local/placeholder IP strings."""
    if not raw or raw in ("-", "LOCAL", "127.0.0.1", "::1", "0.0.0.0"):
        return None
    return raw


def _parse_event_element(event_el: ET.Element) -> LogEvent | None:
    """Parse a single <Event> XML element into a LogEvent."""
    try:
        system = _find(event_el, "System")
        if system is None:
            return None

        # EventID — may have a Qualifiers attribute; just take text
        eid_el = _find(system, "EventID")
        if eid_el is None or not eid_el.text:
            return None
        try:
            event_id = int(eid_el.text.strip())
        except ValueError:
            return None

        if event_id not in _EVENTID_META:
            return None

        time_el = _find(system, "TimeCreated")
        ts_raw = time_el.get("SystemTime") if time_el is not None else None
        timestamp = _parse_timestamp(ts_raw)

        computer = _text(system, "Computer")

        # EventData — collect all <Data Name="..."> elements
        event_data_el = _find(event_el, "EventData")
        data: dict[str, str] = {}
        if event_data_el is not None:
            for d in _findall(event_data_el, "Data"):
                name = d.get("Name")
                if name and d.text:
                    data[name] = d.text.strip()

        # Extract key fields
        target_user = data.get("TargetUserName") or data.get("SubjectUserName")
        target_domain = data.get("TargetDomainName") or data.get("SubjectDomainName")
        ip_raw = data.get("IpAddress") or data.get("CallerIPAddress") or data.get("Workstation")
        ip_address = _clean_ip(ip_raw)

        # Build user principal name
        upn: str | None = None
        if target_user and target_user not in ("-", "ANONYMOUS LOGON", "SYSTEM"):
            if target_domain and target_domain not in ("-", "NT AUTHORITY", "WORKGROUP"):
                upn = f"{target_user}@{target_domain}"
            else:
                upn = target_user

        # Workstation name as a proxy for user_agent in Windows events
        workstation = data.get("WorkstationName") or data.get("CallerProcessName") or computer
        ua = workstation if workstation and workstation != "-" else None

        meta = _EVENTID_META[event_id]
        path = meta["path"]
        method = meta["method"]

        # Determine status code
        if event_id in _FAILURE_EVENTIDS:
            status_code = 401
            failure_reason = data.get("Status") or data.get("SubStatus") or data.get("FailureReason")
        elif event_id in _STATUS_FIELD_EVENTIDS:
            # 4768/4769/4776: Status field "0x0" = success; anything else = auth failure
            raw_status = data.get("Status") or data.get("FailureCode")
            if raw_status and raw_status not in ("0x0", "0x00", "0"):
                status_code = 401
                failure_reason = raw_status
            else:
                status_code = 200
                failure_reason = None
        else:
            status_code = 200
            failure_reason = None

        # Enrich path with process name for 4688; also extract file hash
        file_hash: str | None = None
        if event_id == 4688:
            proc = data.get("NewProcessName") or data.get("ProcessName")
            if proc:
                proc_name = proc.split("\\")[-1].lower()
                path = f"/windows/process/{proc_name}"
            # 4688 Hashes field: "MD5=abc...,SHA256=def...,IMPHASH=..." — prefer SHA256
            hashes_raw = data.get("Hashes") or ""
            if hashes_raw:
                hash_pairs = dict(
                    pair.split("=", 1)
                    for pair in hashes_raw.split(",")
                    if "=" in pair
                )
                # Prefer SHA256 > MD5 for longer, more unique hash
                for algo in ("SHA256", "SHA-256", "MD5"):
                    candidate = hash_pairs.get(algo, "").strip().lower()
                    if _HASH_SHA256_RE.match(candidate) or _HASH_MD5_RE.match(candidate):
                        file_hash = candidate
                        break

        # Enrich path with task name for scheduler events
        if event_id in (4698, 4702):
            task = data.get("TaskName")
            if task:
                task_name = task.lstrip("\\").lower()
                path = f"/windows/scheduler/task/{task_name}"

        return LogEvent(
            source_format=LogFormat.EVTX,
            timestamp=timestamp,
            ip_address=ip_address,
            user_agent=ua,
            http_method=method,
            path=path,
            status_code=status_code,
            user_principal_name=upn,
            resource_display_name=f"Windows EventID {event_id} on {computer}" if computer else f"Windows EventID {event_id}",
            failure_reason=failure_reason,
            file_hash=file_hash,
        )

    except Exception as exc:
        logger.debug("Skipping malformed EVTX event: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public parse functions
# ---------------------------------------------------------------------------


def parse_evtx_xml(content: str) -> list[LogEvent]:
    """Parse Windows Event Log XML export into a list of LogEvents."""
    events: list[LogEvent] = []

    # Wrap bare <Event> elements in a root tag if needed
    stripped = content.strip()
    if not stripped.startswith("<Events>") and stripped.startswith("<Event"):
        content = f"<Events>{content}</Events>"

    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"EVTX XML parser: invalid XML — {exc}") from exc

    # Root may be <Events> wrapping multiple <Event> children,
    # or the root itself may be a single <Event>.
    if root.tag in ("Events", f"{{{_NS_URL}}}Events"):
        event_elements = (
            _findall(root, "Event")
            or list(root)  # fallback: all direct children
        )
    else:
        event_elements = [root]

    for el in event_elements:
        ev = _parse_event_element(el)
        if ev:
            events.append(ev)

    logger.info("EVTX XML parser: %d/%d events parsed", len(events), len(event_elements))
    return events


def parse_evtx_binary(file_path: str) -> list[LogEvent]:
    """
    Parse a binary .evtx file using the python-evtx library.
    Raises ImportError if python-evtx is not installed.
    """
    if not _EVTX_AVAILABLE:
        raise ImportError(
            "python-evtx is not installed. "
            "Install it with: pip install python-evtx  "
            "Or export the .evtx to XML first: wevtutil qe Security /f:xml > events.xml"
        )
    events: list[LogEvent] = []
    with _evtx_lib.Evtx(file_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                el = ET.fromstring(xml_str)
                ev = _parse_event_element(el)
                if ev:
                    events.append(ev)
            except Exception as exc:
                logger.debug("Skipping unreadable EVTX record: %s", exc)
    logger.info("EVTX binary parser: %d events parsed from %s", len(events), file_path)
    return events


# ---------------------------------------------------------------------------
# Plugin registry class
# ---------------------------------------------------------------------------


class EvtxParser(BaseParser):
    """Plugin-registry entry for Windows Event Log (XML export format)."""

    format_name = "evtx"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        # XML export: look for Windows event log namespace or EventID elements
        stripped = content.strip()
        if not stripped.startswith("<"):
            return False
        head = stripped[:4096]
        return (
            "microsoft.com/win/2004/08/events" in head
            or ("<EventID>" in head and "<EventData>" in head)
            or ("<EventID>" in head and "<System>" in head)
        )

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_evtx_xml(content)
