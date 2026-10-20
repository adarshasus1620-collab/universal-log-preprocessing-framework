"""Output connectors: send normalized events to external systems.

This demonstrates two realistic integration paths without requiring a
licensed SIEM to be running:

1. CSV export - works with Excel, data-lake ingestion tools, or any
   system that accepts flat files.
2. Splunk HEC-style batch - formats events exactly as Splunk's HTTP
   Event Collector expects them, and POSTs them if a HEC URL/token is
   configured; otherwise it writes the same payload to a local file so
   the format can be inspected and reused once a real Splunk instance
   is available.
"""
import argparse
import csv
import json
import os
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


def load_events(events_path: Path) -> list[dict]:
    lines = [l for l in events_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


# ---------------------------------------------------------------------------
# CSV export (data-lake / spreadsheet friendly)
# ---------------------------------------------------------------------------
CSV_COLUMNS = ["time", "class", "activity", "action", "severity",
              "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
              "user", "message", "vendor", "product", "raw_ref", "raw_sha256"]


def to_csv(events: list[dict], out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for e in events:
            src, dst, meta = e.get("src", {}), e.get("dst", {}), e["metadata"]
            writer.writerow({
                "time": e["time"], "class": e["class"], "activity": e["activity"],
                "action": e["action"], "severity": e["severity"],
                "src_ip": src.get("ip"), "src_port": src.get("port"),
                "dst_ip": dst.get("ip"), "dst_port": dst.get("port"),
                "protocol": e.get("protocol"), "user": e.get("user"), "message": e["message"],
                "vendor": meta["vendor"], "product": meta["product"],
                "raw_ref": meta["raw_ref"], "raw_sha256": meta["raw_sha256"],
            })
    return len(events)


# ---------------------------------------------------------------------------
# Splunk HEC-style batch (SIEM connector pattern)
# ---------------------------------------------------------------------------
def to_splunk_hec_batch(events: list[dict], source: str = "ulpf") -> list[dict]:
    """Shape each event the way Splunk's HTTP Event Collector expects:
    {"time": <epoch>, "source": ..., "sourcetype": ..., "event": {...}}."""
    import datetime
    batch = []
    for e in events:
        try:
            epoch = datetime.datetime.fromisoformat(e["time"].replace("Z", "+00:00")).timestamp()
        except ValueError:
            epoch = 0
        batch.append({
            "time": epoch,
            "source": source,
            "sourcetype": "ulpf:unified_event",
            "event": e,
        })
    return batch


def send_to_splunk(batch: list[dict], out_path: Path) -> str:
    """POSTs to Splunk HEC if HEC_URL and HEC_TOKEN are set in the
    environment; otherwise writes the batch to a local file so the exact
    payload can be inspected (and replayed once a real HEC is available)."""
    hec_url = os.environ.get("HEC_URL")
    hec_token = os.environ.get("HEC_TOKEN")

    if hec_url and hec_token and requests is not None:
        headers = {"Authorization": f"Splunk {hec_token}"}
        payload = "\n".join(json.dumps(b) for b in batch)
        resp = requests.post(hec_url, headers=headers, data=payload, timeout=10, verify=False)
        return f"POSTed {len(batch)} events to {hec_url} (status {resp.status_code})"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for b in batch:
            f.write(json.dumps(b) + "\n")
    return (f"No HEC_URL/HEC_TOKEN configured, so {len(batch)} Splunk-HEC-formatted "
            f"events were written to {out_path} for inspection.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Export normalized ULPF events to external systems.")
    ap.add_argument("--events", default="../output/events.jsonl", help="path to events.jsonl")
    ap.add_argument("--csv-out", default="../output/events.csv")
    ap.add_argument("--splunk-out", default="../output/splunk_hec_batch.jsonl")
    args = ap.parse_args()

    events_path = Path(args.events)
    if not events_path.exists():
        raise SystemExit(f"{events_path} not found - run cli.py first.")

    events = load_events(events_path)
    print(f"Loaded {len(events)} normalized events from {events_path}")

    n = to_csv(events, Path(args.csv_out))
    print(f"CSV export: wrote {n} rows to {args.csv_out}")

    batch = to_splunk_hec_batch(events)
    msg = send_to_splunk(batch, Path(args.splunk_out))
    print(f"Splunk HEC export: {msg}")