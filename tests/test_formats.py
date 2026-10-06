from __future__ import annotations

import json

from logtriage.engine import parser_ids
from logtriage.formats import BY_ID, CATCH_ALL, FORMATS


def test_catalogue_matches_the_parser_registry() -> None:
    registry = parser_ids()
    assert len(registry) == len(set(registry)), "duplicate parser ids in the registry"
    assert sorted(registry) == sorted(f.id for f in FORMATS)
    assert len(BY_ID) == len(FORMATS) >= 50


def test_catalogue_entries_are_complete() -> None:
    for entry in FORMATS:
        assert entry.id and entry.slug and entry.name and entry.category
    assert len({f.slug for f in FORMATS}) == len(FORMATS)


def test_catch_all_parsers_are_tried_last() -> None:
    registry = parser_ids()
    assert set(registry[-len(CATCH_ALL):]) == CATCH_ALL


def test_formats_command(run) -> None:
    code, out, _ = run("formats")
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith(f"{len(FORMATS)} supported formats")
    assert lines[2].split() == ["ID", "FORMAT", "CATEGORY"]
    listed = {line.split()[0] for line in lines[3:]}
    assert listed == set(BY_ID)
    assert any(line.startswith("cloudtrail ") and "AWS CloudTrail" in line for line in lines)


def test_formats_json(run) -> None:
    code, out, _ = run("formats", "--json")
    assert code == 0
    rows = json.loads(out)
    assert len(rows) == len(FORMATS)
    assert {"id": "azure_signin", "name": "Azure AD Sign-In Logs", "category": "Identity"} in rows
