"""ULPF command-line tool.

Reads one or more log files, auto-detects each line's format, routes it to
the matching parser, and prints (or saves) the normalized events.

Usage:
    python cli.py ..\\sample_logs\\fortinet.log
    python cli.py ..\\sample_logs\\fortinet.log ..\\sample_logs\\cisco_asa.log ..\\sample_logs\\suricata_eve.json
    python cli.py ..\\sample_logs\\fortinet.log --out ..\\output\\events.jsonl
"""
import argparse
import sys
from pathlib import Path

from detect import detect_source
from vault import store_raw_event
from parse import parse_fortinet_line
from parse_cisco import parse_cisco_asa_line
from parse_suricata import parse_suricata_line
from parse_pfsense import parse_pfsense_line

PARSERS = {
    "fortinet": parse_fortinet_line,
    "cisco_asa": parse_cisco_asa_line,
    "suricata": parse_suricata_line,
    "pfsense": parse_pfsense_line,
}


def process_file(path: Path):
    events, errors = [], []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        store_raw_event(line, path.name, i)
        parser = PARSERS.get(detect_source(line))
        if parser is None:
            errors.append((path.name, i, "unknown format", line[:80]))
            continue
        try:
            events.append(parser(line, path.name, i))
        except Exception as exc:
            errors.append((path.name, i, str(exc), line[:80]))
    return events, errors


def main():
    ap = argparse.ArgumentParser(description="Parse mixed perimeter-device logs into unified events.")
    ap.add_argument("files", nargs="+", help="log files to parse")
    ap.add_argument("--out", help="write normalized events as JSON Lines to this file")
    args = ap.parse_args()

    all_events, all_errors = [], []
    for f in args.files:
        path = Path(f)
        if not path.exists():
            print(f"SKIP: {f} not found", file=sys.stderr)
            continue
        events, errors = process_file(path)
        all_events.extend(events)
        all_errors.extend(errors)
        print(f"{path.name}: {len(events)} parsed, {len(errors)} failed")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for e in all_events:
                f.write(e.model_dump_json(by_alias=True) + "\n")
        print(f"\nWrote {len(all_events)} normalized events to {out_path}")
    else:
        for e in all_events:
            print(e.model_dump_json(by_alias=True))

    if all_errors:
        print(f"\n{len(all_errors)} line(s) could not be parsed:", file=sys.stderr)
        for fname, lineno, msg, snippet in all_errors:
            print(f"  {fname}:{lineno}  {msg}  | {snippet}", file=sys.stderr)

    print(f"\nTOTAL: {len(all_events)} events parsed, {len(all_errors)} failed, "
          f"from {len(args.files)} file(s).")


if __name__ == "__main__":
    main()