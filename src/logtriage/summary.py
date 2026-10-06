"""Quick local triage of a parsed log file: counts, time range and top values."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from logtriage.engine import ParsedFile

# (summary key, heading) for the ranked lists, in display order.
TOP_LISTS = (
    ("top_source_ips", "Top source IPs"),
    ("top_users", "Top users"),
    ("top_failure_reasons", "Top failure reasons"),
    ("top_user_agents", "Top user agents"),
    ("top_paths", "Top paths / actions"),
)

OUTCOME_LABELS = (
    ("success", "success (status < 400)"),
    ("failure", "failure (status >= 400)"),
    ("unknown", "no status"),
)


def _utc(ts: datetime) -> datetime:
    # A few formats carry no UTC offset; treat those timestamps as UTC.
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def _top(counter: Counter[Any], n: int) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(n)]


def summarize(parsed: ParsedFile, top: int = 10) -> dict[str, Any]:
    """Machine-readable summary of a parsed file (what ``summary --json`` prints)."""
    events = parsed.events
    ips: Counter[str] = Counter()
    users: Counter[str] = Counter()
    statuses: Counter[int] = Counter()
    failures: Counter[str] = Counter()
    agents: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    outcomes = {"success": 0, "failure": 0, "unknown": 0}
    first = last = None

    for event in events:
        if event.ip_address:
            ips[event.ip_address] += 1
        user = event.user_principal_name or event.user_id
        if user:
            users[user] += 1
        if event.status_code is None:
            outcomes["unknown"] += 1
        else:
            statuses[event.status_code] += 1
            outcomes["failure" if event.status_code >= 400 else "success"] += 1
        if event.failure_reason:
            failures[event.failure_reason] += 1
        if event.user_agent:
            agents[event.user_agent] += 1
        if event.path:
            paths[event.path] += 1
        ts = _utc(event.timestamp)
        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts

    time_range = None
    if first is not None and last is not None:
        time_range = {
            "first": first.isoformat(),
            "last": last.isoformat(),
            "duration_seconds": int((last - first).total_seconds()),
        }

    return {
        "file": str(parsed.path),
        "format": parsed.format_id,
        "format_name": parsed.format_name,
        "events": len(events),
        "time_range": time_range,
        "unique_source_ips": len(ips),
        "unique_users": len(users),
        "outcomes": outcomes,
        "status_codes": {str(code): statuses[code] for code in sorted(statuses)},
        "top_source_ips": _top(ips, top),
        "top_users": _top(users, top),
        "top_failure_reasons": _top(failures, top),
        "top_user_agents": _top(agents, top),
        "top_paths": _top(paths, top),
    }


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------


def _duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600:02d}h"


def _when(iso: str) -> str:
    return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S UTC")


def _clip(text: str, room: int | None) -> str:
    text = " ".join(str(text).split())  # one line, even for multi-line values
    if room is None or len(text) <= room:
        return text
    return text[: max(room - 3, 1)] + "..."


def _rows(items: list[tuple[str, int]], total: int, width: int | None) -> list[str]:
    if not items:
        return ["  (none)"]
    count_width = max(len(f"{count:,}") for _, count in items)
    lines = []
    for value, count in items:
        share = f"{100 * count / total:.1f}%" if total else "-"
        prefix = f"  {count:>{count_width},}  {share:>6}  "
        room = None if width is None else width - len(prefix)
        lines.append(prefix + _clip(value, room))
    return lines


def render(summary: dict[str, Any], width: int | None = None) -> str:
    """Human-readable summary. ``width`` clips long values (None: never clip)."""
    total = summary["events"]
    out = [
        summary["file"],
        f"  format      {summary['format']} ({summary['format_name']})",
        f"  events      {total:,}",
    ]
    time_range = summary["time_range"]
    if time_range:
        out.append(
            f"  time range  {_when(time_range['first'])} -> {_when(time_range['last'])}"
            f"  ({_duration(time_range['duration_seconds'])})"
        )
    out.append(
        f"  unique      {summary['unique_source_ips']:,} source IPs, "
        f"{summary['unique_users']:,} users"
    )

    outcomes = summary["outcomes"]
    out += ["", "Outcome"]
    out += _rows(
        [
            (label, outcomes[key])
            for key, label in OUTCOME_LABELS
            if outcomes[key] or key != "unknown"
        ],
        total,
        width,
    )

    out += ["", "Status codes"]
    out += _rows(list(summary["status_codes"].items()), total, width)

    for key, heading in TOP_LISTS:
        out += ["", heading]
        out += _rows([(row["value"], row["count"]) for row in summary[key]], total, width)
    return "\n".join(out) + "\n"
