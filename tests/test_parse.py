from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from conftest import FIXTURES


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_json_output_for_every_fixture(run, data: Path, name: str) -> None:
    fmt, count = FIXTURES[name]
    code, out, err = run("parse", data / name)
    assert code == 0, err
    events = json.loads(out)
    assert len(events) == count
    for event in events:
        assert event["source_format"] == fmt
        assert "timestamp" in event
        assert "raw_line" not in event  # only with --include-raw
        assert None not in event.values()  # empty fields are left out


def test_json_values(run, data: Path) -> None:
    code, out, _ = run("parse", data / "cloudtrail_normal_operations.json")
    assert code == 0
    first = json.loads(out)[0]
    assert first == {
        "source_format": "cloudtrail",
        "timestamp": "2024-01-15T09:05:12Z",
        "ip_address": "203.0.113.10",
        "user_agent": "aws-cli/2.13.0 Python/3.11.4 Darwin/22.6.0",
        "path": "ListBuckets",
        "status_code": 200,
        "user_principal_name": "arn:aws:iam::123456789012:user/alice",
        "resource_display_name": "s3.amazonaws.com",
    }


def test_ndjson_output(run, data: Path) -> None:
    code, out, _ = run("parse", data / "nginx_api_developer.log", "--output", "ndjson")
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 15
    first = json.loads(lines[0])
    assert (first["ip_address"], first["http_method"], first["path"], first["status_code"]) == (
        "10.10.2.100",
        "GET",
        "/api/v1/users",
        200,
    )
    assert json.loads(lines[-1])["path"] == "/api/v1/feedback"


def test_csv_output(run, data: Path) -> None:
    code, out, _ = run("parse", data / "generic_normal_api.csv", "--output", "csv")
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 12
    header = out.splitlines()[0].split(",")
    assert header[:2] == ["timestamp", "source_format"]
    assert "raw_line" not in header
    assert rows[0]["ip_address"] == "10.10.1.50"
    assert rows[0]["user_principal_name"] == "alice@corp.com"
    assert rows[0]["status_code"] == "200"
    assert rows[-1]["http_method"] == "DELETE"
    assert {row["source_format"] for row in rows} == {"generic_csv"}


def test_csv_serialises_nested_values(run, data: Path) -> None:
    code, out, _ = run("parse", data / "windows_normal_logons.xml", "--output", "csv")
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 7
    assert rows[0]["user_principal_name"] == "alice.johnson@CONTOSO"
    assert rows[0]["path"] == "/windows/logon"


def test_limit(run, data: Path) -> None:
    code, out, _ = run("parse", data / "syslog_normal.log", "--limit", "3", "--output", "ndjson")
    assert code == 0
    assert len(out.splitlines()) == 3

    code, out, _ = run("parse", data / "syslog_normal.log", "--limit", "500")
    assert len(json.loads(out)) == 14

    code, _, err = run("parse", data / "syslog_normal.log", "--limit", "0")
    assert code == 2
    assert "must be 1 or more" in err


def test_include_raw(run, data: Path) -> None:
    code, out, _ = run("parse", data / "nginx_api_developer.log", "--include-raw", "--limit", "1")
    assert code == 0
    [event] = json.loads(out)
    assert event["raw_line"].startswith("10.10.2.100 - dev-alice [07/Jun/2026:14:00:00 +0000]")

    code, out, _ = run("parse", data / "nginx_api_developer.log", "--include-raw", "--output", "csv")
    assert out.splitlines()[0].endswith(",raw_line")


def test_forced_format_and_helpful_errors(run, data: Path) -> None:
    code, out, _ = run("parse", data / "vpc_flow_benign.log", "--format", "vpc_flow", "--output", "ndjson")
    assert code == 0
    assert len(out.splitlines()) == 10

    code, _, err = run("parse", data / "vpc_flow_benign.log", "--format", "csv")
    assert code == 2
    assert "--output csv" in err

    code, _, err = run("parse", data / "vpc_flow_benign.log", "--format", "vpcflow")
    assert code == 2
    assert "Did you mean: vpc_flow" in err


def test_windows_timestamps_keep_their_fraction(run, data: Path) -> None:
    # The sample uses 9-digit fractional seconds; on Python 3.10 this relies on
    # the fromisoformat backport in logtriage.engine.
    code, out, _ = run("parse", data / "windows_normal_logons.xml", "--limit", "1")
    assert code == 0
    assert json.loads(out)[0]["timestamp"] == "2024-03-20T07:58:01.123456Z"


def test_empty_output_is_valid_json() -> None:
    from logtriage.cli import write_events

    buffer = io.StringIO()
    write_events([], "json", buffer)
    assert json.loads(buffer.getvalue()) == []
