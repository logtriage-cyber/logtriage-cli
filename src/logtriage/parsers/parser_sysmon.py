# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Microsoft Sysmon (System Monitor) XML event log parser.

Sysmon writes to the Windows Event Log under the provider
"Microsoft-Windows-Sysmon" using EventIDs 1-29. Logs are exported as
XML (same format as other Windows Event Logs) but contain Sysmon-specific
EventData field names.

This parser must be registered BEFORE the generic EVTX parser since it is
more specific — it detects the Sysmon provider name in the XML.

EventID → operation mapping (key events):
  1  ProcessCreate       — command execution, child process, cmdline + hash
  2  FileCreateTime      — timestamp tampering
  3  NetworkConnect      — outbound network + DestinationIp
  5  ProcessTerminate
  6  DriverLoad
  7  ImageLoad           — DLL load + hash
  8  CreateRemoteThread  — code injection indicator
  10 ProcessAccess       — lsass dumping (TargetImage contains lsass)
  11 FileCreate
  12 RegistryEvent       — registry key creation/modification
  13 RegistryEvent
  15 FileCreateStreamHash
  17 PipeEvent
  18 PipeEvent
  22 DNSEvent           — DNS query + QueryName
  23 FileDelete
  25 ProcessTampering

Reference:
  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
try:
    import defusedxml.ElementTree as ET  # type: ignore[import-untyped]
except ImportError:
    from xml.etree import ElementTree as ET  # type: ignore[no-redef]  # fallback if defusedxml not installed

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

_HIGH_RISK_IDS = frozenset({8, 10, 25})   # RemoteThread, ProcessAccess, ProcessTamper
_MEDIUM_RISK_IDS = frozenset({3, 22})      # NetworkConnect, DNSEvent

# EventIDs that map to 403 (suspicious blocking-worthy activity)
_BLOCK_STATUS_IDS = frozenset({8, 10, 25})

_EVENT_NAMES: dict[int, str] = {
    1: "ProcessCreate", 2: "FileCreateTime", 3: "NetworkConnect",
    4: "SysmonStateChange", 5: "ProcessTerminate", 6: "DriverLoad",
    7: "ImageLoad", 8: "CreateRemoteThread", 9: "RawAccessRead",
    10: "ProcessAccess", 11: "FileCreate", 12: "RegistryCreate",
    13: "RegistrySet", 14: "RegistryRename", 15: "FileCreateStreamHash",
    17: "PipeCreated", 18: "PipeConnected", 19: "WmiFilter",
    20: "WmiConsumer", 21: "WmiConsumerFilter", 22: "DNSQuery",
    23: "FileDelete", 24: "ClipboardChange", 25: "ProcessTampering",
    26: "FileDeleteDetected", 27: "FileBlockExecutable", 28: "FileBlockShredding",
    29: "FileExecutableDetected",
}


def _find_ns(parent: ET.Element, tag: str) -> ET.Element | None:
    """
    Find a child element by tag, trying the Windows event namespace first then
    the bare tag. Uses explicit `is not None` rather than `or` because an
    ElementTree element with no children is falsy — so `find(...) or find(...)`
    wrongly falls through for leaf elements like <EventID> and <TimeCreated>,
    silently dropping the namespaced match.
    """
    el = parent.find(f"e:{tag}", _NS)
    if el is None:
        el = parent.find(tag)
    return el


def _get_field(event_data: ET.Element | None, name: str) -> str | None:
    if event_data is None:
        return None
    # Sysmon fields use <Data Name="FieldName">value</Data>
    for elem in event_data:
        if elem.get("Name") == name:
            return (elem.text or "").strip() or None
    return None


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        raw = raw.rstrip("Z").replace(" ", "T")
        return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _extract_hash(hashes_str: str | None) -> str | None:
    """Parse "MD5=abc,SHA256=def" style hash strings, return SHA256 > MD5."""
    if not hashes_str:
        return None
    sha256_m = re.search(r"SHA256=([0-9a-fA-F]{64})", hashes_str, re.I)
    if sha256_m:
        return sha256_m.group(1).lower()
    md5_m = re.search(r"MD5=([0-9a-fA-F]{32})", hashes_str, re.I)
    if md5_m:
        return md5_m.group(1).lower()
    return None


def _event_to_log(event_el: ET.Element) -> LogEvent | None:
    try:
        sys_el = _find_ns(event_el, "System")
        data_el = _find_ns(event_el, "EventData")

        if sys_el is None:
            return None

        eid_el = _find_ns(sys_el, "EventID")
        event_id = int(eid_el.text or "0") if eid_el is not None and eid_el.text else 0

        ts_el = _find_ns(sys_el, "TimeCreated")
        ts_raw = ts_el.get("SystemTime") if ts_el is not None else None
        ts = _parse_ts(ts_raw)

        op_name = _EVENT_NAMES.get(event_id, f"Sysmon/{event_id}")

        # Extract fields based on EventID
        ip: str | None = None
        path: str | None = None
        user: str | None = None
        file_hash: str | None = None

        if event_id == 1:   # ProcessCreate
            # Prefer CommandLine — it carries the high-signal payload (e.g. encoded
            # PowerShell) that downstream scoring keys on; fall back to Image.
            path = _get_field(data_el, "CommandLine") or _get_field(data_el, "Image")
            user = _get_field(data_el, "User")
            file_hash = _extract_hash(_get_field(data_el, "Hashes"))

        elif event_id == 3:  # NetworkConnect
            ip = _get_field(data_el, "DestinationIp") or _get_field(data_el, "SourceIp")
            dest = _get_field(data_el, "DestinationIp")
            dport = _get_field(data_el, "DestinationPort")
            path = f"{dest}:{dport}" if dest and dport else dest or op_name
            user = _get_field(data_el, "User")

        elif event_id == 7:  # ImageLoad
            path = _get_field(data_el, "ImageLoaded") or _get_field(data_el, "Image")
            user = _get_field(data_el, "User")
            file_hash = _extract_hash(_get_field(data_el, "Hashes"))

        elif event_id == 8:  # CreateRemoteThread
            path = _get_field(data_el, "TargetImage") or op_name
            user = _get_field(data_el, "SourceUser")

        elif event_id == 10:  # ProcessAccess — lsass dump
            path = _get_field(data_el, "TargetImage") or op_name
            user = _get_field(data_el, "SourceUser")

        elif event_id == 22:  # DNSQuery
            path = _get_field(data_el, "QueryName")
            user = _get_field(data_el, "User")

        else:
            path = (
                _get_field(data_el, "TargetFilename")
                or _get_field(data_el, "Image")
                or _get_field(data_el, "TargetObject")   # registry
                or op_name
            )
            user = _get_field(data_el, "User")
            file_hash = _extract_hash(_get_field(data_el, "Hashes"))

        status = 403 if event_id in _BLOCK_STATUS_IDS else (401 if event_id in _MEDIUM_RISK_IDS else 200)

        return LogEvent(
            source_format=LogFormat.SYSMON,
            timestamp=ts,
            ip_address=ip,
            user_principal_name=user,
            path=path,
            http_method=op_name,
            status_code=status,
            resource_display_name="Sysmon",
            file_hash=file_hash,
        )

    except Exception as exc:
        logger.debug("Sysmon: skipping event: %s", exc)
        return None


def parse_sysmon(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    # Try as a single XML document first
    try:
        root = ET.fromstring(raw_text.strip())
        tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
        if tag == "Event":
            e = _event_to_log(root)
            if e:
                events.append(e)
            return events
        # <Events> wrapper
        for child in root:
            ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if ctag == "Event":
                e = _event_to_log(child)
                if e:
                    events.append(e)
        return events
    except ET.ParseError:
        pass

    # Fallback: extract individual <Event>…</Event> blocks
    for block in re.findall(r"<Event\b[^>]*>.*?</Event>", raw_text, re.DOTALL | re.IGNORECASE):
        try:
            el = ET.fromstring(block)
            e = _event_to_log(el)
            if e:
                events.append(e)
        except ET.ParseError:
            continue

    logger.info("Sysmon parser: %d events", len(events))
    return events


def _is_sysmon_xml(content: str) -> bool:
    # Fast string check before parsing XML
    return _SYSMON_PROVIDER in content and (
        "<EventID>" in content or "<EventID " in content
    )


class SysmonParser(BaseParser):
    format_name = "sysmon"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "sysmon" in filename.lower():
            return _is_sysmon_xml(content) or True
        return _is_sysmon_xml(content)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_sysmon(content)
