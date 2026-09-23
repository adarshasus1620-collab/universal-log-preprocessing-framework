"""Parser for Fortinet FortiGate key=value logs.

Reads a raw line, pulls out the key=value pairs, and maps them onto the
UnifiedEvent schema. Anything that does not map to a named field is kept
in `extensions`, so nothing from the raw line is lost.
"""
import hashlib
import re
from pathlib import Path

from schema import Endpoint, SourceMeta, UnifiedEvent

KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

MAPPED_KEYS = {"date", "time", "srcip", "srcport", "dstip", "dstport",
              "proto", "action", "type", "remip", "user", "reason"}

PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}
ACTION_MAP = {"accept": "allowed", "deny": "blocked", "ssl-login-fail": "failed"}
LEVEL_SEVERITY = {"information": "Low", "notice": "Low", "warning": "Medium",
                  "error": "High", "critical": "High"}
CLASS_ACTIVITY = {
    ("traffic", "forward"): ("Network Activity", "Traffic"),
    ("event", "vpn"): ("Authentication", "Logon"),
}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def kv_parse(line: str) -> dict:
    """Turn 'a=1 b="two words" c=3' into {'a': '1', 'b': 'two words', 'c': '3'}."""
    out = {}
    for key, quoted, bare in KV_RE.findall(line):
        out[key] = quoted if quoted != "" or bare == "" else bare
        if quoted == "" and bare != "":
            out[key] = bare
    return out


def cast(value: str):
    """Turn digit-only strings into int, so extensions keep useful types."""
    return int(value) if value.isdigit() else value


def parse_fortinet_line(raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
    kv = kv_parse(raw_line)

    date, time_ = kv.get("date"), kv.get("time")
    iso_time = f"{date}T{time_}Z" if date and time_ else time_ or "1970-01-01T00:00:00Z"

    log_type, subtype = kv.get("type", ""), kv.get("subtype", "")
    cls, activity = CLASS_ACTIVITY.get((log_type, subtype), ("Uncategorized", log_type.title() or "Unknown"))

    raw_action = kv.get("action", "unknown")
    action = ACTION_MAP.get(raw_action, raw_action)
    severity = LEVEL_SEVERITY.get(kv.get("level", ""), "Medium")

    if "srcip" in kv:
        src = Endpoint(ip=kv["srcip"], port=int(kv["srcport"]) if "srcport" in kv else None)
    elif "remip" in kv:
        src = Endpoint(ip=kv["remip"])
    else:
        src = Endpoint()

    dst = Endpoint(ip=kv.get("dstip"), port=int(kv["dstport"]) if "dstport" in kv else None) \
        if "dstip" in kv else Endpoint()

    protocol = PROTO_MAP.get(kv.get("proto"), kv.get("proto"))

    if log_type == "traffic" and action == "allowed":
        message = f"Forwarded traffic to {kv['service']} service" if "service" in kv else "Forwarded traffic"
    elif log_type == "traffic" and action == "blocked":
        message = f"{kv.get('service', 'Traffic')} connection denied"
    elif subtype == "vpn":
        message = f"SSL VPN login failed: {kv['reason']}" if "reason" in kv else f"VPN event: {raw_action}"
    else:
        message = f"{activity} event ({raw_action})"

    extensions = {k: cast(v) for k, v in kv.items() if k not in MAPPED_KEYS}
    extensions["vendor_action"] = raw_action
    extensions["tz_assumed"] = "UTC"

    return UnifiedEvent(
        time=iso_time,
        **{"class": cls},
        activity=activity,
        action=action,
        severity=severity,
        src=src,
        dst=dst,
        protocol=protocol,
        user=kv.get("user"),
        message=message,
        metadata=SourceMeta(vendor="Fortinet", product="FortiGate",
                            raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
        extensions=extensions,
    )


if __name__ == "__main__":
    log_path = Path(__file__).resolve().parent.parent / "sample_logs" / "fortinet.log"
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    ok, failed = 0, 0
    for i, line in enumerate(lines, start=1):
        try:
            event = parse_fortinet_line(line, "fortinet.log", i)
            print(f"--- line {i}: OK ---")
            print(event.model_dump_json(indent=2, by_alias=True))
            ok += 1
        except Exception as exc:
            print(f"--- line {i}: FAILED ({exc}) ---")
            failed += 1
    print(f"\nParsed {ok} of {len(lines)} lines ({failed} failed).")