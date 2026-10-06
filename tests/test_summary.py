from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from conftest import FIXTURES

from logtriage.engine import load
from logtriage.summary import render, summarize


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_summary_runs_for_every_fixture(run, data: Path, name: str) -> None:
    fmt, count = FIXTURES[name]
    code, out, err = run("summary", data / name)
    assert code == 0, err
    assert f"format      {fmt} (" in out
    assert f"events      {count}" in out
    for heading in ("Outcome", "Status codes", "Top source IPs", "Top users", "Top failure reasons"):
        assert heading in out


def test_nginx_summary_numbers(data: Path) -> None:
    summary = summarize(load(data / "nginx_api_developer.log"))
    assert summary["events"] == 15
    assert summary["time_range"] == {
        "first": "2026-06-07T14:00:00+00:00",
        "last": "2026-06-07T14:15:20+00:00",
        "duration_seconds": 920,
    }
    assert summary["unique_source_ips"] == 3
    assert summary["top_source_ips"] == [
        {"value": "10.10.2.100", "count": 8},
        {"value": "10.10.2.101", "count": 4},
        {"value": "10.10.2.102", "count": 3},
    ]
    assert summary["status_codes"] == {"200": 9, "201": 4, "204": 1, "404": 1}
    assert summary["outcomes"] == {"success": 14, "failure": 1, "unknown": 0}
    assert summary["top_user_agents"] == [{"value": "PostmanRuntime/7.36.0", "count": 15}]
    assert summary["top_paths"][0] == {"value": "/api/v1/users/999", "count": 3}


def test_failures_users_and_outcomes(data: Path) -> None:
    summary = summarize(load(data / "authlog_normal.log"))
    assert summary["outcomes"]["failure"] == 2
    assert len(summary["top_failure_reasons"]) == 2
    assert any("Authentication failure" in row["value"] for row in summary["top_failure_reasons"])
    users = {row["value"] for row in summary["top_users"]}
    assert {"admin", "deploy", "jenkins"} <= users


def test_windows_summary(data: Path) -> None:
    summary = summarize(load(data / "windows_normal_logons.xml"))
    assert summary["time_range"]["first"] == "2024-03-20T07:58:01.123456+00:00"
    assert summary["time_range"]["last"] == "2024-03-20T10:00:01.456789+00:00"
    assert {"alice.johnson@CONTOSO", "bob.smith@CONTOSO"} <= {r["value"] for r in summary["top_users"]}


def test_naive_timestamps_are_treated_as_utc(data: Path) -> None:
    # Microsoft 365 audit records carry no UTC offset.
    summary = summarize(load(data / "m365_normal_activity.json"))
    assert summary["time_range"]["first"] == "2024-03-15T09:00:00+00:00"
    assert summary["time_range"]["last"] == "2024-03-15T14:00:00+00:00"
    assert summary["unique_users"] == 6


def test_top_limits_every_list(data: Path) -> None:
    summary = summarize(load(data / "vpc_flow_benign.log"), top=2)
    for key in ("top_source_ips", "top_users", "top_failure_reasons", "top_user_agents", "top_paths"):
        assert len(summary[key]) <= 2


def test_json_output(run, data: Path) -> None:
    code, out, _ = run("summary", data / "cloudtrail_normal_operations.json", "--json", "--top", "1")
    assert code == 0
    summary = json.loads(out)
    assert summary["format"] == "cloudtrail"
    assert summary["format_name"] == "AWS CloudTrail"
    assert summary["events"] == 4
    assert summary["top_source_ips"] == [{"value": "203.0.113.10", "count": 3}]
    assert summary["top_users"] == [{"value": "arn:aws:iam::123456789012:user/alice", "count": 3}]


def test_text_rendering(data: Path) -> None:
    text = render(summarize(load(data / "nginx_api_developer.log")))
    assert "time range  2026-06-07 14:00:00 UTC -> 2026-06-07 14:15:20 UTC  (15m 20s)" in text
    assert "unique      3 source IPs, 0 users" in text
    assert "\n  8   53.3%  10.10.2.100\n" in text
    assert "  14   93.3%  success (status < 400)" in text
    assert "(none)" in text  # no failure reasons in this file


def test_long_values_are_clipped_to_the_width(data: Path) -> None:
    text = render(summarize(load(data / "authlog_normal.log")), width=60)
    rows = [line for line in text.splitlines() if re.match(r"^ +\d", line)]
    assert rows and all(len(line) <= 60 for line in rows)
    assert any(line.endswith("...") for line in rows)
