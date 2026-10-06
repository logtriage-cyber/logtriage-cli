"""The ``logtriage`` command.

    logtriage formats                   list the supported log formats
    logtriage detect FILE...            detected format and event count per file
    logtriage parse FILE                normalised events as JSON, NDJSON or CSV
    logtriage summary FILE              quick local triage in the terminal
    logtriage analyze FILE              upload to the hosted service for an AI report

Only ``analyze`` uses the network.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any, TextIO

from logtriage import __version__, hosted
from logtriage.engine import (
    EVTX_MAGIC,
    EXIT_ERROR,
    EXIT_UNRECOGNISED,
    EXIT_USAGE,
    GZIP_MAGIC,
    LogTriageError,
    UsageError,
    load,
)
from logtriage.formats import FORMATS
from logtriage.models import LogEvent
from logtriage.summary import render, summarize

API_KEY_ENV = "LOGTRIAGE_API_KEY"
API_URL_ENV = "LOGTRIAGE_API_URL"
APP_URL_ENV = "LOGTRIAGE_APP_URL"

EPILOG = """\
exit codes:
  0  success
  1  error (unreadable file, parser failure, network or service error)
  2  usage error
  3  format not recognised, or no events parsed
  4  analyze timed out waiting for the result (the job keeps running)

Every command except 'analyze' runs locally; nothing leaves this machine.
Documentation: https://github.com/logtriage-cyber/logtriage-cli
"""


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _err(message: str) -> None:
    print(f"logtriage: {message}", file=sys.stderr)


def _configure_streams() -> None:
    # Never crash on a character the console cannot show. When output is
    # redirected on Windows, write UTF-8 rather than the legacy code page.
    for stream in (sys.stdout, sys.stderr):
        try:
            if sys.platform == "win32" and not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def _terminal_width() -> int | None:
    return shutil.get_terminal_size().columns if sys.stdout.isatty() else None


def _json_out(data: Any) -> None:
    sys.stdout.write(json.dumps(data, indent=2) + "\n")


_CSV_FIRST = ("timestamp", "source_format")


def _csv_columns(include_raw: bool) -> list[str]:
    fields = [name for name in LogEvent.model_fields if name not in _CSV_FIRST and name != "raw_line"]
    return [*_CSV_FIRST, *fields, *(["raw_line"] if include_raw else [])]


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return str(value)


def write_events(events: list[LogEvent], fmt: str, out: TextIO, include_raw: bool = False) -> None:
    """Write events as ``json`` (an array, one event per line), ``ndjson`` or ``csv``."""
    exclude = None if include_raw else {"raw_line"}
    if fmt == "csv":
        columns = _csv_columns(include_raw)
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(columns)
        for event in events:
            row = event.model_dump(mode="json")
            writer.writerow([_csv_cell(row.get(column)) for column in columns])
        return
    lines = (
        json.dumps(event.model_dump(mode="json", exclude_none=True, exclude=exclude))
        for event in events
    )
    if fmt == "ndjson":
        for line in lines:
            out.write(line + "\n")
        return
    out.write("[")
    for index, line in enumerate(lines):
        out.write(("\n" if index == 0 else ",\n") + line)
    out.write("\n]\n" if events else "]\n")


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _input_format(args: argparse.Namespace) -> str | None:
    """The --format value, with a pointer to --output for a common mix-up."""
    value = args.format
    if value in ("json", "ndjson", "csv"):
        raise UsageError(
            f"--format selects the input parser (see 'logtriage formats'); "
            f"to write {value}, use --output {value}"
        )
    return value


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_formats(args: argparse.Namespace) -> int:
    rows = sorted(FORMATS, key=lambda f: f.name.lower())
    if args.json:
        _json_out([{"id": f.id, "name": f.name, "category": f.category} for f in rows])
        return 0
    id_width = max(len(f.id) for f in rows)
    name_width = max(len(f.name) for f in rows)
    print(f"{len(rows)} supported formats. Detection is automatic; --format ID forces a parser.\n")
    print(f"{'ID':<{id_width}}  {'FORMAT':<{name_width}}  CATEGORY")
    for f in rows:
        print(f"{f.id:<{id_width}}  {f.name:<{name_width}}  {f.category}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    results: list[dict[str, Any]] = []
    exit_code = 0
    for name in args.files:
        try:
            parsed = load(name)
        except LogTriageError as exc:
            _err(str(exc))
            results.append({"file": name, "format": None, "events": 0, "error": str(exc)})
            if exc.exit_code == EXIT_UNRECOGNISED:
                exit_code = exit_code or EXIT_UNRECOGNISED
            else:
                exit_code = EXIT_ERROR
            continue
        results.append(
            {
                "file": name,
                "format": parsed.format_id,
                "format_name": parsed.format_name,
                "events": len(parsed.events),
            }
        )
        del parsed  # one file in memory at a time

    if args.json:
        _json_out(results)
        return exit_code
    labels = [row["format"] or "(unrecognised)" for row in results]
    counts = [f"{row['events']:,}" if row["format"] else "-" for row in results]
    format_width = max(len("FORMAT"), *(len(label) for label in labels))
    count_width = max(len("EVENTS"), *(len(count) for count in counts))
    print(f"{'FORMAT':<{format_width}}  {'EVENTS':>{count_width}}  FILE")
    for row, label, count in zip(results, labels, counts, strict=True):
        print(f"{label:<{format_width}}  {count:>{count_width}}  {row['file']}")
    return exit_code


def cmd_parse(args: argparse.Namespace) -> int:
    parsed = load(args.file, _input_format(args))
    events = parsed.events if args.limit is None else parsed.events[: args.limit]
    write_events(events, args.output, sys.stdout, include_raw=args.include_raw)
    sys.stdout.flush()
    if sys.stderr.isatty():
        shown = f", wrote {len(events):,}" if len(events) != len(parsed.events) else ""
        _err(f"{len(parsed.events):,} events parsed as {parsed.format_id} ({parsed.format_name}){shown}")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    parsed = load(args.file, _input_format(args))
    data = summarize(parsed, top=args.top)
    if args.json:
        _json_out(data)
    else:
        sys.stdout.write(render(data, width=_terminal_width()))
    return 0


def _check_uploadable(path: Path) -> int:
    """Refuse, before any network call, files the hosted service would reject."""
    if path.is_dir():
        raise LogTriageError(f"{path}: is a directory")
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            head = fh.read(8)
    except FileNotFoundError:
        raise LogTriageError(f"{path}: no such file") from None
    except OSError as exc:
        raise LogTriageError(f"{path}: cannot read file: {exc.strerror or exc}") from None
    if size == 0:
        raise UsageError(f"{path}: the file is empty")
    if head.startswith(GZIP_MAGIC):
        raise UsageError(
            f"{path}: the file is gzip-compressed; the hosted service needs the "
            "uncompressed log (gunzip it first)"
        )
    if head.startswith(EVTX_MAGIC) and path.suffix.lower() != ".evtx":
        raise UsageError(f"{path}: binary Windows event logs must have the .evtx extension")
    if size > hosted.MAX_UPLOAD_BYTES:
        raise UsageError(
            f"{path}: {_human_size(size)} is over the hosted service's 100 MB limit. "
            "'logtriage summary' works locally on files of any size."
        )
    return size


def _report_lines(job: dict[str, Any], report: dict[str, Any] | None, url: str) -> list[str]:
    severity = job.get("report_severity") or "unknown"
    extras = []
    if job.get("report_confidence"):
        extras.append(f"confidence {job['report_confidence']}")
    if job.get("report_risk_score_overall") is not None:
        extras.append(f"risk score {job['report_risk_score_overall']}/100")
    model = job.get("report_model_used") or "unknown"
    if model == "rule-based":
        model += " (no AI call was made)"
    events = f"{job.get('event_count', 0):,}"
    if job.get("log_format"):
        events += f" ({job['log_format']})"
    lines = [
        f"Severity        {severity}" + (f" ({', '.join(extras)})" if extras else ""),
        f"Attack pattern  {job.get('report_attack_pattern') or 'none identified'}",
        f"Model           {model}",
        f"Events          {events}",
        f"Report          {url}",
    ]
    summary = (report or {}).get("executive_summary")
    if summary:
        lines += ["", *textwrap.wrap(" ".join(str(summary).split()), width=78)]
    return lines


def cmd_analyze(args: argparse.Namespace) -> int:
    api_key = args.api_key or os.environ.get(API_KEY_ENV, "")
    if not api_key.strip():
        raise UsageError(
            f"analyze needs an API key: pass --api-key or set {API_KEY_ENV}. "
            f"Create one at {hosted.DEFAULT_APP_URL}/app/integrations"
        )
    path = Path(args.file)
    size = _check_uploadable(path)
    client = hosted.Client(
        api_key.strip(),
        api_url=args.api_url,
        app_url=os.environ.get(APP_URL_ENV) or hosted.DEFAULT_APP_URL,
    )
    _err(
        f"uploading {path.name} ({_human_size(size)}) to {client.api_url}; "
        "the file leaves this machine for analysis."
    )
    job_id = client.upload(path)
    _err(f"job {job_id}")
    job = client.wait(job_id, args.timeout, on_status=lambda status: _err(f"status: {status}"))
    if job.get("status") == "failed":
        raise LogTriageError(f"analysis failed: {job.get('error_message') or 'no details given'}")

    report: dict[str, Any] | None = None
    if job.get("has_report", True):
        try:
            report = client.report(job_id)
        except hosted.ApiError as exc:
            _err(f"could not fetch the full report: {exc}")
    url = client.report_url(job_id)
    if args.json:
        _json_out(
            {
                "job_id": job_id,
                "status": job.get("status"),
                "severity": job.get("report_severity"),
                "confidence": job.get("report_confidence"),
                "attack_pattern": job.get("report_attack_pattern"),
                "model_used": job.get("report_model_used"),
                "risk_score": job.get("report_risk_score_overall"),
                "events": job.get("event_count"),
                "format": job.get("log_format"),
                "report_url": url,
                "report": report,
            }
        )
    else:
        print("\n".join(_report_lines(job, report, url)))
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    verbose_help = "log parser diagnostics to stderr"
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS: a subcommand must not overwrite a -v given before it.
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help=verbose_help)

    parser = argparse.ArgumentParser(
        prog="logtriage",
        description=(
            f"Parse and triage security logs locally. {len(FORMATS)} formats are "
            "auto-detected and normalised to one schema."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"logtriage {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help=verbose_help)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add(name: str, help_text: str, func: Any) -> argparse.ArgumentParser:
        command = sub.add_parser(
            name,
            help=help_text,
            description=help_text[0].upper() + help_text[1:] + ".",
            parents=[common],
            epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        command.set_defaults(func=func)
        return command

    formats = add("formats", "list the supported log formats", cmd_formats)
    formats.add_argument("--json", action="store_true", help="machine-readable output")

    detect = add("detect", "detect the format of one or more files and count their events", cmd_detect)
    detect.add_argument("files", nargs="+", metavar="FILE")
    detect.add_argument("--json", action="store_true", help="machine-readable output")

    parse = add("parse", "parse a file into normalised events (JSON, NDJSON or CSV on stdout)", cmd_parse)
    parse.add_argument("file", metavar="FILE")
    parse.add_argument(
        "--output",
        choices=("json", "ndjson", "csv"),
        default="json",
        help="output format (default: json)",
    )
    parse.add_argument("--limit", type=_positive_int, metavar="N", help="write only the first N events")
    parse.add_argument("--format", metavar="ID", help="skip detection and use this parser (see 'logtriage formats')")
    parse.add_argument("--include-raw", action="store_true", help="include the original log line when the parser keeps it")

    summary = add("summary", "quick local triage: time range, top IPs, users, outcomes, failures", cmd_summary)
    summary.add_argument("file", metavar="FILE")
    summary.add_argument("--json", action="store_true", help="machine-readable output")
    summary.add_argument("--top", type=_positive_int, default=10, metavar="N", help="entries per list (default: 10)")
    summary.add_argument("--format", metavar="ID", help="skip detection and use this parser (see 'logtriage formats')")

    analyze = add(
        "analyze",
        "upload a file to the hosted LogTriage service for a threat-intel-enriched AI report",
        cmd_analyze,
    )
    analyze.add_argument("file", metavar="FILE")
    analyze.add_argument("--api-key", metavar="KEY", help=f"LogTriage API key, ltk_... (default: ${API_KEY_ENV})")
    analyze.add_argument(
        "--timeout",
        type=_positive_float,
        default=600.0,
        metavar="SECONDS",
        help="how long to wait for the result (default: 600)",
    )
    analyze.add_argument("--json", action="store_true", help="print the job summary and the full report as JSON")
    analyze.add_argument(
        "--api-url",
        default=os.environ.get(API_URL_ENV) or hosted.DEFAULT_API_URL,
        metavar="URL",
        help=f"service URL (default: ${API_URL_ENV} or {hosted.DEFAULT_API_URL})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --help, --version and usage errors
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    _configure_streams()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="logtriage %(levelname)s %(name)s: %(message)s",
    )
    try:
        return int(args.func(args))
    except LogTriageError as exc:
        _err(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except BrokenPipeError:
        # The reader went away (e.g. `logtriage parse big.log | head`): stop quietly.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
