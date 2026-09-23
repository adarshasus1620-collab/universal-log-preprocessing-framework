"""Parser for Cisco ASA syslog-text logs.

Cisco ASA logs are free text, not key=value. The %ASA-x-xxxxxx message ID
tells us what kind of event it is; everything else is pulled out with regex.
"""
import hashlib
import re
from datetime import datetime
from pathlib import Path

from schema import Endpoint, SourceMeta, UnifiedEvent

HEADER_RE = re.compile(
    r'^(?P<mon>\w+) (?P<day>\d+) (?P<year>\d+) (?P<time>[\d:]+) '
    r'(?P<device>\S+) : %ASA-(?P<level>\d)-(?P<msgid>\d+): (?P<body>.*)$'
)
CONN_RE = re.compile(
    r'.*for outside:(?P<src_ip>[\d.]+)/(?P<src_port>\d+).*to inside:(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)'
)
DENY_RE = re.compile(
    r'Deny (?P<proto>\w+) src outside:(?P<src_ip>[\d.]+)/(?P<src_port>\d+) '
    r'dst inside:(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+) by access-group "(?P<group>[^"]+)"'
)

# message id -> (class, activity, action, severity, protocol default)
MSGID_INFO = {
    "302013": ("Network Activity", "Open", "allowed", "Low", "TCP"),
    "302014": ("Network Activity", "Close", "closed", "Low", "TCP"),
    "106023": ("Network Activity", "Refuse", "blocked", "Medium", "TCP"),
}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def to_iso(mon: str, day: str, year: str, time_: str) -> str:
    dt = datetime.strptime(f"{mon} {day} {year} {time_}", "%b %d %Y %H:%M:%S")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_cisco_asa_line(raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
    m = HEADER_RE.match(raw_line)
    if not m:
        raise ValueError("line does not match the expected Cisco ASA header format")
    g = m.groupdict()
    iso_time = to_iso(g["mon"], g["day"], g["year"], g["time"])
    msgid, body = g["msgid"], g["body"]

    cls, activity, action, severity, default_proto = MSGID_INFO.get(
        msgid, ("Uncategorized", "Unknown", "unknown", "Medium", None))

    src = dst = Endpoint()
    protocol = default_proto
    ext = {"device": g["device"], "message_id": msgid}

    if msgid in ("302013", "302014"):
        cm = CONN_RE.match(body)
        if cm:
            c = cm.groupdict()
            src = Endpoint(ip=c["src_ip"], port=int(c["src_port"]))
            dst = Endpoint(ip=c["dst_ip"], port=int(c["dst_port"]))
        conn_id = re.search(r"connection (\d+)", body)
        if conn_id:
            ext["connection_id"] = int(conn_id.group(1))
        if msgid == "302014":
            dur = re.search(r"duration (\S+)", body)
            byt = re.search(r"bytes (\d+)", body)
            if dur:
                ext["duration"] = dur.group(1)
            if byt:
                ext["bytes"] = int(byt.group(1))
            message = "Teardown TCP connection (TCP FINs)" if "FINs" in body else "Teardown TCP connection"
        else:
            message = "Built outbound TCP connection"
    elif msgid == "106023":
        dm = DENY_RE.match(body)
        if dm:
            d = dm.groupdict()
            src = Endpoint(ip=d["src_ip"], port=int(d["src_port"]))
            dst = Endpoint(ip=d["dst_ip"], port=int(d["dst_port"]))
            protocol = d["proto"].upper()
            ext["access_group"] = d["group"]
            message = f"Denied by access-group {d['group']}"
        else:
            message = "Denied by access-group"
    else:
        message = body

    return UnifiedEvent(
        time=iso_time,
        **{"class": cls},
        activity=activity,
        action=action,
        severity=severity,
        src=src,
        dst=dst,
        protocol=protocol,
        user=None,
        message=message,
        metadata=SourceMeta(vendor="Cisco", product="ASA",
                            raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
        extensions={**ext, "tz_assumed": "UTC"},
    )


if __name__ == "__main__":
    log_path = Path(__file__).resolve().parent.parent / "sample_logs" / "cisco_asa.log"
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    ok, failed = 0, 0
    for i, line in enumerate(lines, start=1):
        try:
            event = parse_cisco_asa_line(line, "cisco_asa.log", i)
            print(f"--- line {i}: OK ---")
            print(event.model_dump_json(indent=2, by_alias=True))
            ok += 1
        except Exception as exc:
            print(f"--- line {i}: FAILED ({exc}) ---")
            failed += 1
    print(f"\nParsed {ok} of {len(lines)} lines ({failed} failed).")