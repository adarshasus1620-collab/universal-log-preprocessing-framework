"""Format auto-detection: given one raw log line, say which vendor wrote it.

Detection order matters: check the most specific signal first. JSON lines
are checked by a quick structural test (starts with '{' and parses as JSON)
rather than a text search, since that is more reliable than a keyword.
"""
import json


def detect_source(raw_line: str) -> str:
    """Returns 'fortinet', 'cisco_asa', 'suricata', or 'unknown'."""
    stripped = raw_line.strip()

    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return "unknown"
        if "event_type" in data and "src_ip" in data:
            return "suricata"
        return "unknown"

    if "%ASA-" in stripped:
        return "cisco_asa"

    if "devname=" in stripped and "logid=" in stripped:
        return "fortinet"

    return "unknown"


if __name__ == "__main__":
    samples = {
        "fortinet": 'date=2026-09-19 time=10:15:32 devname="FGT-HQ" logid="0000000013" type="traffic"',
        "cisco_asa": "Sep 19 2026 10:15:32 ASA01 : %ASA-6-302013: Built outbound TCP connection",
        "suricata": '{"timestamp":"2026-09-19T10:17:05Z","event_type":"alert","src_ip":"198.51.100.7"}',
        "garbage": "this line matches nothing we know about",
    }
    for expected, line in samples.items():
        got = detect_source(line)
        mark = "OK" if got == expected or (expected == "garbage" and got == "unknown") else "MISMATCH"
        print(f"{mark:8} expected={expected:10} got={got:10} | {line[:60]}")