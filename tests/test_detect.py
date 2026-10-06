from __future__ import annotations

import codecs
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from conftest import FIXTURES

from logtriage.engine import LogTriageError, UnrecognisedFormat, UsageError, load
from logtriage.models import LogEvent


@pytest.mark.parametrize(("name", "expected"), sorted(FIXTURES.items()))
def test_load_detects_each_fixture(data: Path, name: str, expected: tuple[str, int]) -> None:
    parsed = load(data / name)
    assert (parsed.format_id, len(parsed.events)) == expected
    assert all(event.source_format.value == expected[0] for event in parsed.events)


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_same_result_as_the_upstream_normalizer(data: Path, name: str) -> None:
    # The CLI runs its own detection loop (for clearer errors); it must agree
    # with the service's entry point on every fixture.
    from logtriage.parsers.normalizer import normalize_log_file_with_format

    def comparable(event: LogEvent) -> dict:
        # Records whose timestamp a parser cannot read get the current time;
        # those differ between two runs, so compare them without it.
        dump = event.model_dump()
        ts = dump["timestamp"] if dump["timestamp"].tzinfo else dump["timestamp"].replace(tzinfo=timezone.utc)
        if abs((datetime.now(timezone.utc) - ts).total_seconds()) < 86400:
            del dump["timestamp"]
        return dump

    text = (data / name).read_text(encoding="utf-8")
    events, fmt = normalize_log_file_with_format(text, name)
    parsed = load(data / name)
    assert parsed.format_id == fmt
    assert [comparable(e) for e in parsed.events] == [comparable(e) for e in events]


def test_every_parser_can_be_forced_without_crashing(data: Path) -> None:
    from logtriage.formats import FORMATS

    for entry in FORMATS:
        try:
            load(data / "nginx_api_developer.log", entry.id)
        except LogTriageError:
            pass  # a clean "cannot be parsed as ..." is the expected outcome


def test_detect_table(run, data: Path) -> None:
    files = [data / name for name in sorted(FIXTURES)]
    code, out, err = run("detect", *files)
    assert code == 0, err
    lines = out.splitlines()
    assert lines[0].split() == ["FORMAT", "EVENTS", "FILE"]
    rows = {Path(line.split(None, 2)[2]).name: line.split()[:2] for line in lines[1:]}
    assert rows == {name: [fmt, str(count)] for name, (fmt, count) in FIXTURES.items()}


def test_detect_json(run, data: Path) -> None:
    code, out, _ = run("detect", "--json", data / "cloudtrail_normal_operations.json")
    assert code == 0
    [row] = json.loads(out)
    assert row["format"] == "cloudtrail"
    assert row["format_name"] == "AWS CloudTrail"
    assert row["events"] == 4


def test_detect_reports_unrecognised_and_missing_files(run, data: Path, tmp_path: Path) -> None:
    unknown = tmp_path / "notes.txt"
    unknown.write_text("this is not a log file\njust some notes\n", encoding="utf-8")
    missing = tmp_path / "missing.log"

    code, out, err = run("detect", data / "zeek_normal_http.log", unknown)
    assert code == 3
    assert "(unrecognised)" in out
    assert "format not recognised" in err and "logtriage formats" in err

    code, out, err = run("detect", data / "zeek_normal_http.log", unknown, missing)
    assert code == 1  # an unreadable file outranks an unrecognised one
    assert "no such file" in err


def test_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    with pytest.raises(UnrecognisedFormat, match="empty"):
        load(empty)


def test_binary_garbage_is_flagged(tmp_path: Path) -> None:
    blob = tmp_path / "blob.log"
    blob.write_bytes(bytes(range(256)) * 4)
    with pytest.raises(UnrecognisedFormat, match="binary"):
        load(blob)


def test_directory_is_an_error(tmp_path: Path, run) -> None:
    code, _, err = run("summary", tmp_path)
    assert code == 1
    assert "is a directory" in err


def test_gzip_is_read_transparently(data: Path, tmp_path: Path) -> None:
    # The ".gz" suffix is dropped for detection, so file-name hints still work.
    target = tmp_path / "auth.log.gz"
    target.write_bytes(gzip.compress((data / "authlog_normal.log").read_bytes()))
    parsed = load(target)
    assert (parsed.format_id, len(parsed.events)) == FIXTURES["authlog_normal.log"]


def test_corrupt_gzip_is_an_error(tmp_path: Path) -> None:
    target = tmp_path / "broken.log.gz"
    target.write_bytes(gzip.compress(b"x" * 1000)[:20])
    with pytest.raises(LogTriageError, match="gzip"):
        load(target)


@pytest.mark.parametrize("codec", ["utf-8-sig", "utf-16", "utf-16-be"])
def test_byte_order_marks(data: Path, tmp_path: Path, codec: str) -> None:
    text = (data / "nginx_api_developer.log").read_text(encoding="utf-8")
    raw = text.encode(codec)
    if codec == "utf-16-be":
        raw = codecs.BOM_UTF16_BE + raw
    target = tmp_path / "access.log"
    target.write_bytes(raw)
    parsed = load(target)
    assert (parsed.format_id, len(parsed.events)) == ("nginx", 15)


def test_forced_format(data: Path) -> None:
    parsed = load(data / "nginx_api_developer.log", "nginx")
    assert len(parsed.events) == 15
    with pytest.raises(UnrecognisedFormat, match="as Okta System Log"):
        load(data / "nginx_api_developer.log", "okta")


def test_unknown_format_id_suggests_a_close_match(data: Path) -> None:
    with pytest.raises(UsageError, match="Did you mean: cloudtrail"):
        load(data / "nginx_api_developer.log", "cloudtrial")


def test_binary_evtx_needs_the_extra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from logtriage.parsers import parser_evtx

    monkeypatch.setattr(parser_evtx, "_EVTX_AVAILABLE", False)
    target = tmp_path / "Security.evtx"
    target.write_bytes(b"ElfFile\x00" + b"\x00" * 4088)
    with pytest.raises(LogTriageError, match=r"logtriage\[evtx\]"):
        load(target)
