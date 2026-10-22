# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Shared JSON input — the shapes a log export arrives in, parsed once per upload.

The same records reach us as a pretty-printed or compact JSON document (an
array, one object, or an envelope such as {"value": [...]}, {"Records": [...]}
or {"response": {"authlogs": [...]}}), or as NDJSON, one object per line.
Each JSON parser used to handle only the shape its own sample file had — some
only NDJSON, some only a whole document — so the same export saved another way
fell through to generic JSON or parsed to nothing (2026-10-22, found by
re-serialising every JSON sample in the corpus).

`load()` parses an upload once: detection asks every JSON parser in turn, and
each one re-parsing a 100 MB document would multiply the work.
`format_registry.detect_and_parse()` calls `release()` when it is done.
"""
from __future__ import annotations

import json
import threading
from typing import Any

_local = threading.local()
_BOM = chr(0xFEFF)


_MAX_PREFIX = 300  # characters before a line's JSON object that a prefix may take


def _prefixed_object(line: str) -> dict[str, Any] | None:
    """The JSON object a line ends with, after a prefix such as grep's `file.log:`,
    a timestamp, or a container runtime's `<time> stdout F `."""
    i = line.find("{")
    if i < 0 or i > _MAX_PREFIX or '"' in line[:i]:
        return None
    try:
        value = json.loads(line[i:])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _prefixed_lines(text: str) -> list[dict[str, Any]] | None:
    """JSON lines that each carry a prefix (`grep -H` over several files,
    `kubectl logs --timestamps`, CRI container logs, a CloudWatch export).
    Only when nearly every sampled line is one."""
    lines = [line for line in text.splitlines()[:200] if line.strip()][:20]
    if not lines or sum(_prefixed_object(line) is not None for line in lines) < 0.9 * len(lines):
        return None
    items = [obj for line in text.splitlines() if (obj := _prefixed_object(line)) is not None]
    return items or None


def _parse(content: str) -> Any:
    text = content.lstrip(_BOM).strip()
    if not text:
        return None
    if text[0] not in "[{":
        return _prefixed_lines(text) if "{" in text[:_MAX_PREFIX + 1] else None
    try:
        return json.loads(text)
    except ValueError:
        pass
    # NDJSON: one value per line; lines that are not JSON are skipped
    items: list[Any] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line[0] not in "[{":
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, list):
            items.extend(v for v in value if isinstance(v, dict))
        elif isinstance(value, dict):
            items.append(value)
    return items or None


def load(content: str) -> Any:
    """The upload as one JSON value, or the list of its NDJSON objects; None when it is not JSON."""
    entry = getattr(_local, "entry", None)
    if entry is not None and entry[0] is content:
        return entry[1]
    parsed = _parse(content)
    _local.entry = (content, parsed)  # holding `content` keeps its id from being reused
    return parsed


def release() -> None:
    """Drop the cached parse (called once detection and parsing are finished)."""
    _local.entry = None


def _at(obj: dict[str, Any], path: str) -> Any:
    node: Any = obj
    for key in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _unwrap(obj: dict[str, Any], envelopes: tuple[str, ...]) -> list[dict[str, Any]] | None:
    for path in envelopes:
        inner = _at(obj, path)
        if isinstance(inner, list) and all(isinstance(r, dict) for r in inner[:5]):
            return [r for r in inner if isinstance(r, dict)]
    return None


def records(content: str, envelopes: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Every record in the upload.

    `envelopes` are the keys (dotted for nested ones, e.g. "response.authlogs")
    under which this format's exports put their record list. An object holding
    one of them contributes its items; any other object is a record itself.
    """
    doc = load(content)
    if isinstance(doc, dict):
        doc = [doc]
    if not isinstance(doc, list):
        return []
    out: list[dict[str, Any]] = []
    for item in doc:
        if not isinstance(item, dict):
            continue
        inner = _unwrap(item, envelopes) if envelopes else None
        if inner is None:
            out.append(item)
        else:
            out.extend(inner)
    return out


def sample(content: str, envelopes: tuple[str, ...] = (), n: int = 5) -> list[dict[str, Any]]:
    """The first `n` records — what a `can_parse()` looks at."""
    return records(content, envelopes)[:n]
