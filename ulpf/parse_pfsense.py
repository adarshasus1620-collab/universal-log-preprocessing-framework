"""Parser for pfSense filterlog (CSV-inside-syslog) logs.

pfSense writes one comma-separated line per filtered packet. The columns
are positional (no field names), so we index into them directly. The
column layout differs slightly depending on whether it's an IPv4 TCP,
UDP, or ICMP line, so this parser handles the common case seen in our
sample logs (IPv4, rule action logged) and falls back gracefully if a
field is missing.
"""
import hashlib
import re
from datetime import datetime
from pathlib import Path

from schema import Endpoint, SourceMeta, UnifiedEvent

HEADER_RE = re.compile(
    r'^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+pfSense\s+filterlog\[\d+\]:\s*(?P<csv>.*)$'
)
ACTION_MAP = {"pass": "allowed", "block": "blocked", "reject": "blocked"}
CURRENT_YEAR = datetime.now().year


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def to_iso(mon: str, day: str, time_: str) -> str:
    dt = datetime.strptime(f"{mon} {day} {CURRENT_YEAR} {time_}", "%b %d %Y %H:%M:%S")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_pfsense_line(raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
    m = HEADER_RE.match(raw_line)
    if not m:
        raise ValueError("line does not match the expected pfSense filterlog header")
    g = m.groupdict()
    iso_time = to_iso(g["mon"], g["day"], g["time"])

    cols = g["csv"].split(",")
    if len(cols) < 22:
        raise ValueError(f"expected at least 22 CSV fields, got {len(cols)}")

    raw_action = cols[6]          # "block" / "pass"
    direction = cols[7]           # "in" / "out"
    protocol = cols[16].upper()   # "tcp" / "udp" / ...
    src_ip, dst_ip = cols[18], cols[19]
    src_port = int(cols[20]) if cols[20].isdigit() else None
    dst_port = int(cols[21]) if cols[21].isdigit() else None

    action = ACTION_MAP.get(raw_action, raw_action)
    severity = "Medium" if action == "blocked" else "Low"
    message = f"{protocol} {direction}bound traffic {raw_action}ed"

    return UnifiedEvent(
        time=iso_time,
        **{"class": "Network Activity"},
        activity="Traffic",
        action=action,
        severity=severity,
        src=Endpoint(ip=src_ip, port=src_port),
        dst=Endpoint(ip=dst_ip, port=dst_port),
        protocol=protocol,
        user=None,
        message=message,
        metadata=SourceMeta(vendor="pfSense", product="Firewall",
                            raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
        extensions={"direction": direction, "rule_tracking_id": cols[3], "interface": cols[4],
                    "tz_assumed": "UTC", "year_assumed": str(CURRENT_YEAR)},
    )


if __name__ == "__main__":
    log_path = Path(__file__).resolve().parent.parent / "sample_logs" / "pfsense.log"
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    ok, failed = 0, 0
    for i, line in enumerate(lines, start=1):
        try:
            event = parse_pfsense_line(line, "pfsense.log", i)
            print(f"--- line {i}: OK ---")
            print(event.model_dump_json(indent=2, by_alias=True))
            ok += 1
        except Exception as exc:
            print(f"--- line {i}: FAILED ({exc}) ---")
            failed += 1
    print(f"\nParsed {ok} of {len(lines)} lines ({failed} failed).")