"""Parser for Suricata IDS/IPS EVE JSON logs.

Each line is one JSON object (JSON Lines format). Suricata already gives us
structured fields, so this parser is mostly about renaming and nesting,
not regex.
"""
import hashlib
import json
from pathlib import Path

from schema import Endpoint, SourceMeta, UnifiedEvent

SEVERITY_MAP = {1: "High", 2: "Medium", 3: "Low"}
MAPPED_KEYS = {"timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port",
              "proto", "alert"}
MAPPED_ALERT_KEYS = {"action", "signature", "signature_id", "rev", "gid", "category", "severity"}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_suricata_line(raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
    data = json.loads(raw_line)
    alert = data.get("alert", {})

    # Suricata timestamps already look like "...+0000"; turn that into "...Z"
    iso_time = data["timestamp"].replace("+0000", "Z")

    action = alert.get("action", "unknown")
    severity = SEVERITY_MAP.get(alert.get("severity"), "Medium")

    src = Endpoint(ip=data.get("src_ip"), port=data.get("src_port"))
    dst = Endpoint(ip=data.get("dest_ip"), port=data.get("dest_port"))

    extensions = {k: v for k, v in alert.items() if k not in MAPPED_ALERT_KEYS}
    extensions.update({k: v for k, v in data.items() if k not in MAPPED_KEYS})
    extensions["vendor_severity"] = alert.get("severity")

    return UnifiedEvent(
        time=iso_time,
        **{"class": "Detection Finding"},
        activity="Alert",
        action=action,
        severity=severity,
        src=src,
        dst=dst,
        protocol=data.get("proto"),
        user=None,
        message=alert.get("signature", "Suricata alert"),
        metadata=SourceMeta(vendor="Suricata", product="IDS (EVE JSON)",
                            raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
        extensions=extensions,
    )


if __name__ == "__main__":
    log_path = Path(__file__).resolve().parent.parent / "sample_logs" / "suricata_eve.json"
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    ok, failed = 0, 0
    for i, line in enumerate(lines, start=1):
        try:
            event = parse_suricata_line(line, "suricata_eve.json", i)
            print(f"--- line {i}: OK ---")
            print(event.model_dump_json(indent=2, by_alias=True))
            ok += 1
        except Exception as exc:
            print(f"--- line {i}: FAILED ({exc}) ---")
            failed += 1
    print(f"\nParsed {ok} of {len(lines)} lines ({failed} failed).")