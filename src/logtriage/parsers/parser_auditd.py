# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Linux Audit (auditd) log parser — /var/log/audit/audit.log.

Record format (Red Hat, "Understanding Audit log files",
https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening;
field meanings: https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv):

  type=USER_LOGIN msg=audit(1637584402.416:92): pid=1939 uid=0 auid=4294967295 ses=4294967295
      subj=... msg='op=login acct="(unknown)" exe="/usr/sbin/sshd" hostname=? addr=10.37.128.108
      terminal=ssh res=failed'

  - msg=audit(<epoch seconds>.<ms>:<serial>); records of one event share the serial
    (a SYSCALL with its EXECVE, CWD, PATH and PROCTITLE records)
  - optional "node=<host> " prefix (name_format), or a syslog header when forwarded by audisp
  - user-space records carry their details inside msg='...': op, acct, exe, hostname,
    addr, terminal, res (success/failed)
  - "encoded" fields (acct, addr, exe, comm, key, cmd, proctitle, EXECVE a0..aN) are
    double-quoted, or hex when the value has spaces or special characters
  - log_format = ENRICHED appends interpreted fields after a 0x1D separator: UID="root" AUID="unset"
  - `ausearch -i` output: msg=audit(10/22/2026 21:00:00.123:456) with interpreted values

Events (one LogEvent each):
  - login outcomes: USER_AUTH failures (each password tried), USER_LOGIN (the login result;
    a failure only when the same sshd process logged no USER_AUTH failure, so an attempt is
    counted once), USER_ACCT failures (account refused), ANOM_LOGIN_* records
  - commands: SYSCALL events (with the EXECVE arguments or the process title) and USER_CMD (sudo)
  - account and privilege changes, audit configuration changes, service start/stop,
    SELinux denials (AVC, USER_AVC), other ANOM_* records
  Session bookkeeping (CRED_*, USER_START/END, LOGIN, CRYPTO_*, USER_ERR for dropped
  connections) and auxiliary records are not events of their own.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# The record, anywhere in the line (a syslog header or "audispd: " may come first)
_RECORD_RE = re.compile(r"(?:node=(?P<node>\S+)\s+)?type=(?P<type>[A-Z_0-9]+)\s+msg=audit\((?P<ts>.+?):(?P<serial>\d+)\)\s*:\s*(?P<body>.*)$")
_PAIR_RE = re.compile(r"""([A-Za-z_][\w-]*)=('[^']*'|"[^"]*"|\S*)""")
_OP_RE = re.compile(r"(?:^|\s)op=(.+?)(?=\s+[A-Za-z_][\w-]*=|$)")
_HEX_RE = re.compile(r"^(?:[0-9A-F]{2})+$")
_ENCODED = {"acct", "addr", "exe", "comm", "key", "cmd", "proctitle", "name", "cwd", "data", "old", "new", "grp"}
_GROUP_SEP = chr(0x1D)  # ENRICHED log_format separator
_UNSET_IDS = {"4294967295", "-1", "unset", "?"}

_AUTH_ATTEMPT = {"USER_AUTH"}
_AUTH_RESULT = {"USER_LOGIN"}
_SKIP = {
    "CRED_ACQ", "CRED_DISP", "CRED_REFR", "USER_START", "USER_END", "LOGIN", "USER_LOGOUT",
    "CRYPTO_KEY_USER", "CRYPTO_SESSION", "USER_ERR", "EOE", "CWD", "PATH", "PROCTITLE",
    "EXECVE", "SOCKADDR", "BPRM_FCAPS", "MMAP", "OBJ_PID", "FD_PAIR", "SECCOMP",
    "TTY", "USER_TTY", "BPF", "NETFILTER_PKT", "TIME_INJOFFSET", "TIME_ADJNTPVAL",
}
_PRIVILEGED_GROUPS = re.compile(r'\b(?:grp|group)="?(?:wheel|sudo|admin|adm|root|docker|lxd)"?', re.IGNORECASE)


def _decode(key: str, value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    base = key.split("[")[0]
    if (base in _ENCODED or re.fullmatch(r"a\d+", base)) and _HEX_RE.match(value):
        try:
            return bytes.fromhex(value).decode("utf-8", "replace").replace("\x00", " ").strip()
        except ValueError:
            return value
    return value


def _fields(body: str) -> dict[str, str]:
    """Fields of a record; a user-space msg='...' payload is read into the same dict."""
    raw, _, enriched = body.partition(_GROUP_SEP)
    out: dict[str, str] = {}
    for key, value in _PAIR_RE.findall(raw):
        if key == "msg" and value.startswith("'"):
            payload = value[1:-1]
            for k2, v2 in _PAIR_RE.findall(payload):
                out[k2] = _decode(k2, v2)
            op = _OP_RE.search(payload)  # "op=adding user id=1002": op values may hold spaces
            if op:
                out["op"] = op.group(1)
            continue
        out.setdefault(key, _decode(key, value))
    for key, value in _PAIR_RE.findall(enriched):
        out[f"_{key}"] = _decode(key, value)  # interpreted: _UID, _AUID, _ID…
    return out


def _timestamp(raw: str) -> datetime:
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M:%S.%f"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _ip(value: str | None) -> str | None:
    if not value or value in ("?", "UNKNOWN"):
        return None
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _is_login(rtype: str) -> bool:
    return rtype in _AUTH_ATTEMPT | _AUTH_RESULT | {"USER_ACCT"} or rtype.startswith("ANOM_LOGIN")


def _user(rtype: str, f: dict[str, str]) -> str | None:
    """The account a login record is about (its uid is the daemon's own), else the
    login user (auid) who did it."""
    acct = f.get("acct")
    if _is_login(rtype):
        if acct and acct not in ("?", "(unknown)", "(invalid user)"):
            return acct
        value = f.get("_ID") or f.get("id")  # successful sshd logins: op=login id=1000
        return value if value and value not in _UNSET_IDS and not value.startswith("unknown(") else None
    for key in ("_AUID", "auid", "_UID", "uid"):
        value = f.get(key)
        if value and value not in _UNSET_IDS:
            return value
    return acct if acct and acct not in ("?", "(unknown)") else None


def _failed(f: dict[str, str]) -> bool:
    return f.get("res", "").lower() in ("failed", "fail", "0", "no") or f.get("success") == "no"


def _signals(rtype: str, f: dict[str, str], text: str) -> list[str]:
    op = f.get("op", "").lower()
    ok = not _failed(f)
    if rtype in ("DAEMON_END", "DAEMON_ABORT") or (
        rtype == "SERVICE_STOP" and f.get("unit") in ("auditd", "auditd.service")
    ) or (rtype == "CONFIG_CHANGE" and ok and (op.startswith("remove") or f.get("audit_enabled") == "0")):
        return ["auditd_audit_disabled"]
    if not ok:
        return []
    if rtype in ("ADD_GROUP", "USER_MGMT", "GRP_MGMT", "ADD_USER", "ROLE_ASSIGN") and _PRIVILEGED_GROUPS.search(text):
        return ["auditd_privileged_group"]
    if rtype == "ADD_USER" or "add-user" in op or op.startswith("adding user"):
        return ["auditd_account_created"]
    if rtype == "USER_CHAUTHTOK":
        return ["auditd_password_changed"]
    if rtype == "ANOM_PROMISCUOUS":
        return ["auditd_promiscuous"]
    if rtype in ("ANOM_LOGIN_FAILURES", "ANOM_MAX_DAC", "ANOM_MAX_MAC"):
        return ["auditd_login_failures_limit"]
    return []


def _command(group: list[tuple[str, dict[str, str]]]) -> str | None:
    execve = next((f for t, f in group if t == "EXECVE"), None)
    if execve:
        argc = int(execve.get("argc", "0") or 0)
        args = [execve.get(f"a{i}", "") for i in range(argc)] or [v for k, v in execve.items() if re.fullmatch(r"a\d+", k)]
        return " ".join(a for a in args if a) or None
    proctitle = next((f.get("proctitle") for t, f in group if t == "PROCTITLE"), None)
    return proctitle or None


def _event(rtype: str, f: dict[str, str], ts: datetime, node: str | None, line: str,
           group: list[tuple[str, dict[str, str]]] | None = None) -> LogEvent:
    failed = _failed(f)
    if rtype == "SYSCALL":
        command = _command(group or [])
        path = command or f.get("exe") or f.get("comm")
        resource = f.get("key") if f.get("key") not in (None, "(null)") else f.get("exe")
        status = 403 if failed else 200
        method = "EXECVE" if any(t == "EXECVE" for t, _ in group or []) else "SYSCALL"
    elif rtype in ("AVC", "USER_AVC", "SELINUX_ERR"):
        denied = "denied" in line
        perms = re.search(r"\{\s*([^}]*?)\s*\}", line)
        target = f.get("name") or f.get("path") or ""
        path = " ".join(p for p in ("denied" if denied else "granted", f"{{ {perms.group(1)} }}" if perms else "",
                                    f.get("tclass", ""), target) if p)
        resource = f.get("comm") or f.get("exe")
        status = 403 if denied else 200
        method = rtype
    else:
        method = rtype
        if rtype == "USER_CMD":
            path = f.get("cmd")
        elif _is_login(rtype):
            path = f.get("op") or rtype
        else:  # account changes name the account they changed: "adding user backdoor"
            target = f.get("acct") or f.get("id") or f.get("_ID") or f.get("grp")
            path = " ".join(p for p in (f.get("op") or f.get("unit") or rtype, target if target not in (None, "?") else "") if p)
        resource = f.get("exe") or f.get("comm") or f.get("terminal")
        status = (401 if _is_login(rtype) else 403) if failed else 200
    return LogEvent(
        source_format=LogFormat.AUDITD,
        timestamp=ts,
        ip_address=_ip(f.get("addr")) or _ip(f.get("hostname")),
        user_principal_name=_user(rtype, f),
        http_method=method,
        path=path,
        status_code=status,
        resource_display_name=resource or node,
        failure_reason=" ".join(p for p in (rtype, f.get("op"), "failed") if p) if failed and rtype != "SYSCALL" else None,
        raw_line=line[:2000],
        signals=_signals(rtype, f, line),
    )


def parse_auditd(raw_text: str) -> list[LogEvent]:
    # One audit event = the records sharing (node, serial); lines arrive grouped.
    groups: dict[tuple[str | None, str, str], list[tuple[str, dict[str, str]]]] = {}
    meta: dict[tuple[str | None, str, str], tuple[datetime, str]] = {}
    order: list[tuple[str | None, str, str]] = []
    # split on newlines only: str.splitlines() also breaks at 0x1D, the ENRICHED separator
    for line in raw_text.split("\n"):
        m = _RECORD_RE.search(line)
        if not m:
            continue
        key = (m.group("node"), m.group("ts"), m.group("serial"))  # serials restart at boot
        if key not in groups:
            groups[key] = []
            meta[key] = (_timestamp(m.group("ts")), line.strip())
            order.append(key)
        groups[key].append((m.group("type"), _fields(m.group("body"))))

    auth_failed_pids = {
        f.get("pid") for recs in groups.values() for t, f in recs if t in _AUTH_ATTEMPT and _failed(f)
    }
    events: list[LogEvent] = []
    for key in order:
        recs = groups[key]
        ts, first_line = meta[key]
        types = [t for t, _ in recs]
        if "SYSCALL" in types:
            sysf = next(f for t, f in recs if t == "SYSCALL")
            events.append(_event("SYSCALL", sysf, ts, key[0], first_line, recs))
        for rtype, f in recs:
            if rtype == "SYSCALL" or rtype in _SKIP:
                continue
            if rtype in _AUTH_ATTEMPT and not _failed(f):
                continue  # the login result (USER_LOGIN) carries the success
            if rtype in _AUTH_RESULT and _failed(f) and f.get("pid") in auth_failed_pids:
                continue  # its password attempts are already counted
            if rtype == "USER_ACCT" and not _failed(f):
                continue
            events.append(_event(rtype, f, ts, key[0], first_line))
    logger.info("auditd parser: %d events from %d audit events", len(events), len(order))
    return events


def _is_auditd(content: str) -> bool:
    lines = [line for line in content[: 1 << 20].split("\n") if line.strip()][:20]
    return bool(lines) and sum(1 for line in lines if _RECORD_RE.search(line)) >= 0.6 * len(lines)


class AuditdParser(BaseParser):
    format_name = "auditd"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        return _is_auditd(content)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_auditd(content)

