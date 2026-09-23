"""ULPF prototype UI (Streamlit) - skeuomorphic dark SOC-panel theme.

Frontend-first demo. The events below are SAMPLE data: raw lines are copied from
sample_logs/, and the normalized fields were filled in by hand for this demo.
The SHA-256 hashes and the integrity check are computed live in this file.
The real parsing engine is still under development.

This version deliberately avoids pandas / pyarrow (Streamlit's st.dataframe and
st.bar_chart use them internally). Tables and charts are built by hand as HTML
and inline SVG instead, so the app also runs on machines where pyarrow's
compiled extension gets blocked (for example by Windows Smart App Control).
"""
import hashlib
from collections import Counter
from html import escape

import streamlit as st
import json
from pathlib import Path

st.set_page_config(page_title="ULPF - Universal Log Pre-processing Framework",
                   page_icon=":satellite:", layout="wide")

CYAN = "#3ba7ff"

# ---------------------------------------------------------------------------
# Skeuomorphic dark "control panel" styling
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
      .stApp { background:
          radial-gradient(circle at 15% -10%, #1c2430 0%, #0b0d10 55%) fixed; }
      .block-container { padding-top: 4.5rem; max-width: 1250px; }

      /* --- Hero plaque --- */
      .ulpf-hero { position: relative; margin-bottom: 1rem; padding: 1.5rem 1.9rem;
        border-radius: 14px; background: linear-gradient(155deg, #262b33 0%, #14171c 100%);
        border: 1px solid rgba(255,255,255,0.06);
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.08),
                    inset 0 -3px 8px rgba(0,0,0,0.65),
                    0 12px 28px rgba(0,0,0,0.55); }
      .ulpf-hero h1 { color: #eaf2ff; font-size: 1.75rem; margin: 0 0 .3rem 0; padding: 0;
        text-shadow: 0 1px 0 rgba(0,0,0,0.8), 0 0 20px rgba(59,167,255,0.30); }
      .ulpf-hero p { color: #9aa5b3; margin: 0; font-size: 1rem; }
      .rivet { position: absolute; width: 9px; height: 9px; border-radius: 50%;
        background: radial-gradient(circle at 35% 30%, #7a828d 0%, #2c3138 60%, #14171a 100%);
        box-shadow: 0 1px 1px rgba(255,255,255,0.15), 0 1px 2px rgba(0,0,0,0.8) inset; }
      .rivet.tl { top: 10px; left: 10px; } .rivet.tr { top: 10px; right: 10px; }
      .rivet.bl { bottom: 10px; left: 10px; } .rivet.br { bottom: 10px; right: 10px; }
      .status-led { display: inline-flex; align-items: center; gap: .45rem; margin-top: .6rem;
        padding: .25rem .65rem; border-radius: 20px; background: #0d0f12;
        border: 1px solid rgba(255,255,255,0.06); box-shadow: inset 0 1px 4px rgba(0,0,0,0.7); }
      .status-led .dot { width: 8px; height: 8px; border-radius: 50%; background: #3ddc84;
        box-shadow: 0 0 6px 2px rgba(61,220,132,0.7); animation: pulse 1.8s infinite ease-in-out; }
      .status-led span.label { color: #8b93a1; font-size: .74rem; letter-spacing: .08em; }
      @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .45; } }

      /* --- Metric "LCD" readouts --- */
      div[data-testid="stMetric"] { background: linear-gradient(180deg, #14171c, #0d0f12);
        border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: .8rem .9rem .6rem;
        box-shadow: inset 0 2px 6px rgba(0,0,0,0.7), inset 0 -1px 0 rgba(255,255,255,0.04); }
      div[data-testid="stMetricValue"] { color: #7fd1ff !important;
        text-shadow: 0 0 12px rgba(59,167,255,0.55); font-family: 'Courier New', monospace; }
      div[data-testid="stMetricLabel"] { text-transform: uppercase; letter-spacing: .08em;
        font-size: .72rem !important; color: #8b93a1 !important; }
      div[data-testid="stMetricLabel"]::before { content: "\\25CF"; color: #3ddc84;
        margin-right: .4rem; font-size: .6rem; vertical-align: middle; }

      /* --- Tabs as a rocker-switch bar --- */
      .stTabs [data-baseweb="tab-list"] { background: linear-gradient(180deg,#1a1e24,#101317);
        border-radius: 10px; padding: 6px; gap: 4px; border: 1px solid rgba(255,255,255,0.05);
        box-shadow: inset 0 2px 6px rgba(0,0,0,0.65); }
      .stTabs [data-baseweb="tab"] { background: linear-gradient(180deg,#262b32,#1c2026);
        border-radius: 8px !important; color: #9aa5b3 !important;
        box-shadow: 0 1px 0 rgba(255,255,255,0.05) inset, 0 2px 3px rgba(0,0,0,0.4); }
      .stTabs [aria-selected="true"] { background: linear-gradient(180deg,#0d3a5c,#0a2c47) !important;
        color: #a9e0ff !important; box-shadow: inset 0 2px 6px rgba(0,0,0,0.75),
        0 0 10px rgba(59,167,255,0.35) !important; }
      .stTabs [data-baseweb="tab-highlight"] { background-color: transparent !important; }

      /* --- Terminal-style code / raw log panels --- */
      div[data-testid="stCodeBlock"] pre, div[data-testid="stCodeBlock"] code {
        background: #060809 !important; border-radius: 8px;
        border: 1px solid rgba(59,167,255,0.22);
        box-shadow: inset 0 0 14px rgba(0,0,0,0.85);
        color: #7ee787 !important; font-family: 'Courier New', monospace !important; }

      /* --- Buttons: raised metal --- */
      .stButton > button { background: linear-gradient(180deg,#2c323a,#191d22);
        border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; color: #dfe6ee;
        box-shadow: 0 3px 0 rgba(0,0,0,0.55), inset 0 1px 0 rgba(255,255,255,0.08); }
      .stButton > button:active { box-shadow: inset 0 2px 4px rgba(0,0,0,0.7);
        transform: translateY(2px); }

      /* --- Alerts: keep semantic colour, add panel depth --- */
      div[data-testid="stAlert"] { border-radius: 10px;
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 6px 16px rgba(0,0,0,0.4); }

      /* --- Inputs styled as inset dials --- */
      div[data-baseweb="select"] > div, textarea, div[data-testid="stTextArea"] textarea {
        background: #0c0f12 !important; border-radius: 8px !important;
        border: 1px solid rgba(255,255,255,0.07) !important;
        box-shadow: inset 0 2px 6px rgba(0,0,0,0.7) !important; }
      textarea { color: #cdeccd !important; font-family: 'Courier New', monospace !important; }

      div[data-testid="stJson"] { border-radius: 10px; border: 1px solid rgba(255,255,255,0.06);
        box-shadow: 0 6px 18px rgba(0,0,0,0.45); padding: 6px; background: #12151a; }

      h2, h3 { letter-spacing: .01em; }

      /* --- Hand-built table panel --- */
      .ulpf-table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid rgba(255,255,255,0.06);
        box-shadow: 0 6px 18px rgba(0,0,0,0.45); background: #12151a; margin-bottom: .6rem; }
      table.ulpf-table { border-collapse: collapse; width: 100%; font-size: .86rem;
        font-family: 'Segoe UI', sans-serif; white-space: nowrap; }
      table.ulpf-table th { text-align: left; padding: .55rem .75rem; color: #8b93a1;
        text-transform: uppercase; font-size: .68rem; letter-spacing: .06em;
        background: linear-gradient(180deg,#1c2026,#14171b); border-bottom: 1px solid rgba(255,255,255,0.08);
        position: sticky; top: 0; }
      table.ulpf-table td { padding: .5rem .75rem; color: #d7dce3; border-bottom: 1px solid rgba(255,255,255,0.04); }
      table.ulpf-table td.wrap { white-space: normal; min-width: 220px; }
      table.ulpf-table tr:hover td { background: rgba(59,167,255,0.06); }
      .chip { display: inline-block; padding: .15rem .55rem; border-radius: 20px; font-size: .74rem;
        font-weight: 600; letter-spacing: .02em; border: 1px solid rgba(255,255,255,0.08); }
      .chip-good { background: rgba(61,220,132,0.12); color: #5be998; box-shadow: 0 0 6px rgba(61,220,132,0.25); }
      .chip-warn { background: rgba(255,193,64,0.12); color: #ffcf5c; box-shadow: 0 0 6px rgba(255,193,64,0.20); }
      .chip-bad  { background: rgba(255,84,112,0.14); color: #ff7c93; box-shadow: 0 0 6px rgba(255,84,112,0.25); }
      .chip-neutral { background: rgba(255,255,255,0.06); color: #aab2bd; }

      /* --- Hand-built SVG chart panel --- */
      .ulpf-chart-panel { border-radius: 10px; border: 1px solid rgba(255,255,255,0.06);
        box-shadow: 0 6px 18px rgba(0,0,0,0.45), inset 0 0 20px rgba(0,0,0,0.3);
        background: #12151a; padding: 10px 14px; }
    </style>
    <div class="ulpf-hero">
      <span class="rivet tl"></span><span class="rivet tr"></span>
      <span class="rivet bl"></span><span class="rivet br"></span>
      <h1>Universal Log Pre-processing Framework</h1>
      <p>Any perimeter-device log in, one lossless, analytics-ready event out.</p>
      <div class="status-led"><span class="dot"></span><span class="label">LIVE UI PROTOTYPE</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.info("Prototype UI with sample data. The parsing engine is under development. "
        "Hashes and the integrity check on the Trace tab are computed live.")

# ---------------------------------------------------------------------------
# Sample data: raw line (copied from sample_logs) + hand-normalized fields
# ---------------------------------------------------------------------------
DATA_PATH = Path(__file__).resolve().parent / "output" / "events.jsonl"


def load_events() -> list[dict]:
    """Load normalized events produced by cli.py. Falls back to a small
    built-in sample if the pipeline has not been run yet, so the demo
    never shows an empty screen."""
    if DATA_PATH.exists():
        lines = [ln for ln in DATA_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            events = []
            for ln in lines:
                rec = json.loads(ln)
                src, dst, meta = rec.get("src", {}), rec.get("dst", {}), rec["metadata"]
                events.append(dict(
                    vendor=meta["vendor"], product=meta["product"],
                    file=meta["raw_ref"].split(":")[0], line=int(meta["raw_ref"].split(":")[1]),
                    raw=None, time=rec["time"], cls=rec["class"], activity=rec["activity"],
                    action=rec["action"], severity=rec["severity"],
                    src_ip=src.get("ip"), src_port=src.get("port"),
                    dst_ip=dst.get("ip"), dst_port=dst.get("port"),
                    proto=rec.get("protocol"), user=rec.get("user"), message=rec["message"],
                    ext=rec.get("extensions", {}), raw_sha256=meta["raw_sha256"],
                ))
            return events
    return SAMPLE_EVENTS


SAMPLE_EVENTS = [
    dict(
        vendor="Fortinet", product="FortiGate", file="fortinet.log", line=1,
        raw='''date=2026-09-19 time=10:15:32 devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.1.5 srcport=51234 dstip=8.8.8.8 dstport=443 proto=6 action="accept" policyid=12 service="HTTPS" sentbyte=1200 rcvdbyte=5400''',
        time="2026-09-19T10:15:32Z", cls="Network Activity", activity="Traffic", action="allowed",
        severity="Low", src_ip="10.1.1.5", src_port=51234, dst_ip="8.8.8.8", dst_port=443,
        proto="TCP", user=None, message="Forwarded traffic to HTTPS service",
        ext={"devname": "FGT-HQ", "logid": "0000000013", "policyid": 12, "service": "HTTPS",
             "sentbyte": 1200, "rcvdbyte": 5400, "tz_assumed": "UTC"},
    ),
    dict(
        vendor="Fortinet", product="FortiGate", file="fortinet.log", line=2,
        raw='''date=2026-09-19 time=10:15:40 devname="FGT-HQ" logid="0000000013" type="traffic" subtype="forward" level="warning" srcip=198.51.100.7 srcport=44321 dstip=10.1.1.20 dstport=22 proto=6 action="deny" policyid=0 service="SSH" sentbyte=0 rcvdbyte=0''',
        time="2026-09-19T10:15:40Z", cls="Network Activity", activity="Traffic", action="blocked",
        severity="Medium", src_ip="198.51.100.7", src_port=44321, dst_ip="10.1.1.20", dst_port=22,
        proto="TCP", user=None, message="Inbound SSH connection denied",
        ext={"devname": "FGT-HQ", "logid": "0000000013", "policyid": 0, "service": "SSH",
             "sentbyte": 0, "rcvdbyte": 0, "tz_assumed": "UTC"},
    ),
    dict(
        vendor="Fortinet", product="FortiGate", file="fortinet.log", line=3,
        raw='''date=2026-09-19 time=10:16:20 devname="FGT-HQ" logid="0101000000" type="event" subtype="vpn" level="error" user="rahul" remip=203.0.113.50 action="ssl-login-fail" reason="login permission denied"''',
        time="2026-09-19T10:16:20Z", cls="Authentication", activity="Logon", action="failed",
        severity="High", src_ip="203.0.113.50", src_port=None, dst_ip=None, dst_port=None,
        proto=None, user="rahul", message="SSL VPN login failed: login permission denied",
        ext={"devname": "FGT-HQ", "logid": "0101000000", "subtype": "vpn",
             "vendor_action": "ssl-login-fail", "tz_assumed": "UTC"},
    ),
    dict(
        vendor="Cisco", product="ASA", file="cisco_asa.log", line=1,
        raw='''Sep 19 2026 10:15:32 ASA01 : %ASA-6-302013: Built outbound TCP connection 8811 for outside:8.8.8.8/443 (8.8.8.8/443) to inside:10.1.1.5/51234 (203.0.113.10/51234)''',
        time="2026-09-19T10:15:32Z", cls="Network Activity", activity="Open", action="allowed",
        severity="Low", src_ip="10.1.1.5", src_port=51234, dst_ip="8.8.8.8", dst_port=443,
        proto="TCP", user=None, message="Built outbound TCP connection",
        ext={"device": "ASA01", "message_id": "302013", "connection_id": 8811,
             "nat_src_ip": "203.0.113.10", "tz_assumed": "UTC"},
    ),
    dict(
        vendor="Cisco", product="ASA", file="cisco_asa.log", line=2,
        raw='''Sep 19 2026 10:15:40 ASA01 : %ASA-4-106023: Deny tcp src outside:198.51.100.7/44321 dst inside:10.1.1.20/22 by access-group "OUTSIDE_IN" [0x0, 0x0]''',
        time="2026-09-19T10:15:40Z", cls="Network Activity", activity="Refuse", action="blocked",
        severity="Medium", src_ip="198.51.100.7", src_port=44321, dst_ip="10.1.1.20", dst_port=22,
        proto="TCP", user=None, message="Denied by access-group OUTSIDE_IN",
        ext={"device": "ASA01", "message_id": "106023", "access_group": "OUTSIDE_IN",
             "tz_assumed": "UTC"},
    ),
    dict(
        vendor="Cisco", product="ASA", file="cisco_asa.log", line=3,
        raw='''Sep 19 2026 10:16:02 ASA01 : %ASA-6-302014: Teardown TCP connection 8811 for outside:8.8.8.8/443 to inside:10.1.1.5/51234 duration 0:00:30 bytes 6600 TCP FINs''',
        time="2026-09-19T10:16:02Z", cls="Network Activity", activity="Close", action="closed",
        severity="Low", src_ip="10.1.1.5", src_port=51234, dst_ip="8.8.8.8", dst_port=443,
        proto="TCP", user=None, message="Teardown TCP connection (TCP FINs)",
        ext={"device": "ASA01", "message_id": "302014", "connection_id": 8811,
             "duration": "0:00:30", "bytes": 6600, "tz_assumed": "UTC"},
    ),
    dict(
        vendor="Suricata", product="IDS (EVE JSON)", file="suricata_eve.json", line=1,
        raw='''{"timestamp":"2026-09-19T10:17:05.123456+0000","event_type":"alert","src_ip":"198.51.100.7","src_port":44321,"dest_ip":"10.1.1.20","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":20,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}''',
        time="2026-09-19T10:17:05.123456Z", cls="Detection Finding", activity="Alert", action="allowed",
        severity="Medium", src_ip="198.51.100.7", src_port=44321, dst_ip="10.1.1.20", dst_port=22,
        proto="TCP", user=None, message="ET SCAN Potential SSH Scan",
        ext={"signature_id": 2001219, "rev": 20, "gid": 1,
             "category": "Attempted Information Leak", "vendor_severity": 2},
    ),
    dict(
        vendor="Suricata", product="IDS (EVE JSON)", file="suricata_eve.json", line=2,
        raw='''{"timestamp":"2026-09-19T10:17:41.654321+0000","event_type":"alert","src_ip":"203.0.113.77","src_port":50110,"dest_ip":"10.1.1.40","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"GPL ATTACK_RESPONSE id check returned root","category":"Potentially Bad Traffic","severity":2}}''',
        time="2026-09-19T10:17:41.654321Z", cls="Detection Finding", activity="Alert", action="allowed",
        severity="Medium", src_ip="203.0.113.77", src_port=50110, dst_ip="10.1.1.40", dst_port=80,
        proto="TCP", user=None, message="GPL ATTACK_RESPONSE id check returned root",
        ext={"signature_id": 2100498, "rev": 7, "gid": 1,
             "category": "Potentially Bad Traffic", "vendor_severity": 2},
    ),
]


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

EVENTS = load_events()

# Derived fields: event id, raw hash, and a hash chain over the raw events
_prev = "0" * 64
for i, e in enumerate(EVENTS):
    e["event_id"] = f"evt-{i + 1:04d}"
    e["raw_ref"] = f"{e['file']}:{e['line']}"
    e["raw_sha256"] = e.get("raw_sha256") or sha256(e["raw"])
    _prev = sha256(_prev + e["raw_sha256"])
    e["chain_hash"] = _prev


def unified(e: dict) -> dict:
    """The normalized record shown to the user (empty fields are omitted)."""
    rec = {
        "event_id": e["event_id"],
        "time": e["time"],
        "class": e["cls"],
        "activity": e["activity"],
        "action": e["action"],
        "severity": e["severity"],
        "src": {"ip": e["src_ip"], "port": e["src_port"]},
        "dst": {"ip": e["dst_ip"], "port": e["dst_port"]},
        "protocol": e["proto"],
        "user": e["user"],
        "message": e["message"],
        "metadata": {
            "vendor": e["vendor"], "product": e["product"],
            "raw_ref": e["raw_ref"], "raw_sha256": e["raw_sha256"],
        },
        "extensions": e["ext"],
    }
    for k in ("src", "dst"):
        rec[k] = {a: b for a, b in rec[k].items() if b is not None}
        if not rec[k]:
            del rec[k]
    return {k: v for k, v in rec.items() if v is not None}


# ---------------------------------------------------------------------------
# Hand-built HTML table and SVG bar chart (no pandas / pyarrow needed)
# ---------------------------------------------------------------------------
ACTION_CHIP = {"allowed": "chip-good", "blocked": "chip-warn", "failed": "chip-bad", "closed": "chip-neutral"}
SEVERITY_CHIP = {"Low": "chip-neutral", "Medium": "chip-warn", "High": "chip-bad"}

TABLE_COLS = ["event_id", "time", "vendor", "class", "activity", "action", "severity",
              "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "message"]


def cell(col: str, e: dict) -> str:
    if col == "protocol":
        v = e["proto"]
    else:
        v = e.get(col, e.get("cls") if col == "class" else None)
    if v is None:
        return "<td>-</td>"
    if col == "action":
        return f'<td><span class="chip {ACTION_CHIP.get(v, "chip-neutral")}">{escape(str(v))}</span></td>'
    if col == "severity":
        return f'<td><span class="chip {SEVERITY_CHIP.get(v, "chip-neutral")}">{escape(str(v))}</span></td>'
    if col == "message":
        return f'<td class="wrap">{escape(str(v))}</td>'
    return f"<td>{escape(str(v))}</td>"


def html_table(events: list, columns: list) -> str:
    head = "".join(f"<th>{escape(c)}</th>" for c in columns)
    rows = []
    for e in events:
        rows.append("<tr>" + "".join(cell(c, e) for c in columns) + "</tr>")
    return (f'<div class="ulpf-table-wrap"><table class="ulpf-table">'
            f"<thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>")


def svg_hbar(counts: list, color: str = CYAN) -> str:
    """counts: list of (label, value) tuples, already sorted for display."""
    if not counts:
        return "<div class='ulpf-chart-panel'>No data</div>"
    max_v = max(v for _, v in counts) or 1
    row_h, gap, label_w, right_pad = 30, 10, 92, 46
    width = 460
    bar_area = width - label_w - right_pad
    svg_h = len(counts) * (row_h + gap)
    parts = [f'<svg viewBox="0 0 {width} {svg_h}" width="100%" height="{svg_h}" '
             f'xmlns="http://www.w3.org/2000/svg">',
             '<defs><linearGradient id="ulpfBarGrad" x1="0" y1="0" x2="1" y2="0">'
             f'<stop offset="0%" stop-color="{color}" stop-opacity="0.45"/>'
             f'<stop offset="100%" stop-color="{color}" stop-opacity="1"/></linearGradient></defs>']
    for i, (label, v) in enumerate(counts):
        y = i * (row_h + gap)
        bar_w = max(6, bar_area * v / max_v)
        parts.append(f'<text x="{label_w - 10}" y="{y + row_h / 2 + 5}" text-anchor="end" '
                     f'fill="#9aa5b3" font-size="13" font-family="Segoe UI, sans-serif">{escape(str(label))}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{bar_w:.1f}" height="{row_h - 8}" '
                     f'rx="6" fill="url(#ulpfBarGrad)" />')
        parts.append(f'<text x="{label_w + bar_w + 10}" y="{y + row_h / 2 + 5}" fill="#7fd1ff" '
                     f'font-size="13" font-family=\'Courier New,monospace\'>{v}</text>')
    parts.append("</svg>")
    return '<div class="ulpf-chart-panel">' + "".join(parts) + "</div>"


tab_overview, tab_before, tab_events, tab_trace, tab_packs = st.tabs(
    ["Overview", "Before and after", "Events", "Trace and integrity", "Parser packs"]
)

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
with tab_overview:
    vendors_all = sorted({e["vendor"] for e in EVENTS})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events normalized", len(EVENTS))
    c2.metric("Sources", len(vendors_all))
    c3.metric("Blocked or failed", sum(1 for e in EVENTS if e["action"] in ("blocked", "failed")))
    c4.metric("IDS alerts", sum(1 for e in EVENTS if e["cls"] == "Detection Finding"))

    left, right = st.columns(2)
    with left:
        st.subheader("Events per source")
        counts = Counter(e["vendor"] for e in EVENTS)
        st.markdown(svg_hbar(sorted(counts.items(), key=lambda kv: -kv[1])), unsafe_allow_html=True)
    with right:
        st.subheader("Actions taken")
        counts = Counter(e["action"] for e in EVENTS)
        st.markdown(svg_hbar(sorted(counts.items(), key=lambda kv: -kv[1])), unsafe_allow_html=True)

    st.subheader("One attacker, three devices")
    ip_vendors: dict = {}
    for e in EVENTS:
        ip_vendors.setdefault(e["src_ip"], set()).add(e["vendor"])
    top_ip, top_vendors = max(ip_vendors.items(), key=lambda kv: len(kv[1]))
    st.write(f"**{top_ip}** was seen by **{len(top_vendors)}** different vendors. "
             "Because every event uses the same field names, one filter finds all of them.")
    matching = [e for e in EVENTS if e["src_ip"] == top_ip]
    st.markdown(html_table(matching, ["time", "vendor", "activity", "action", "dst_ip", "dst_port", "message"]),
                unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Before and after
# ---------------------------------------------------------------------------
with tab_before:
    st.subheader("The same SSH probe, as three devices wrote it")
    probe = [e for e in EVENTS if e["src_ip"] == "198.51.100.7" and e["dst_port"] == 22]
    cols = st.columns(len(probe))
    styles = {"Fortinet": "key=value", "Cisco": "syslog text", "Suricata": "JSON"}
    for col, e in zip(cols, probe):
        with col:
            st.markdown(f"**{e['vendor']}** ({styles[e['vendor']]})")
            st.code(e["raw"], language=None, wrap_lines=True)
    st.markdown("<div style='text-align:center; font-size:1.6rem; color:#3ba7ff; "
                "text-shadow:0 0 14px rgba(59,167,255,0.5);'>&#8595; ULPF &#8595;</div>",
                unsafe_allow_html=True)
    st.subheader("Same event, one schema")
    st.markdown(html_table(probe, [c for c in TABLE_COLS if c != "event_id"]), unsafe_allow_html=True)
    st.caption("Fields that do not fit the common schema stay in extensions, "
               "so nothing from the original is lost.")

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
with tab_events:
    f1, f2, f3 = st.columns(3)
    all_vendors = sorted({e["vendor"] for e in EVENTS})
    all_actions = sorted({e["action"] for e in EVENTS})
    vendors = f1.multiselect("Source", all_vendors, default=all_vendors)
    actions = f2.multiselect("Action", all_actions, default=all_actions)
    sev = f3.multiselect("Severity", ["Low", "Medium", "High"], default=["Low", "Medium", "High"])
    view = [e for e in EVENTS if e["vendor"] in vendors and e["action"] in actions and e["severity"] in sev]
    st.write(f"Showing {len(view)} of {len(EVENTS)} events")
    st.markdown(html_table(view, TABLE_COLS), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Trace and integrity
# ---------------------------------------------------------------------------
with tab_trace:
    st.write("Pick an event to see its original raw line next to the normalized record. "
             "Edit the raw text to test tamper detection.")
    labels = {e["event_id"]: f"{e['event_id']}  |  {e['vendor']}  |  {e['message']}" for e in EVENTS}
    chosen = st.selectbox("Event", list(labels), format_func=lambda k: labels[k])
    ev = next(e for e in EVENTS if e["event_id"] == chosen)
    key = f"raw_edit_{chosen}"

    left, right = st.columns(2)
    with left:
        st.markdown("**Original raw event**")
        if st.button("Reset raw text", key=f"reset_{chosen}"):
            st.session_state.pop(key, None)
        edited = st.text_area("Raw text (editable for the tamper test)", value=ev["raw"] or "",
                              height=170, key=key, label_visibility="collapsed")

        st.markdown("**Integrity check**")
        current = sha256(edited)
        st.caption("SHA-256 stored when the event was ingested")
        st.code(ev["raw_sha256"], language=None, wrap_lines=True)
        st.caption("SHA-256 of the raw text right now")
        st.code(current, language=None, wrap_lines=True)
        if current == ev["raw_sha256"]:
            st.success("Verified: the raw event matches the hash stored at ingestion.")
        else:
            st.error("Tamper detected: the raw text no longer matches the stored hash.")
        st.caption(f"Trace link: {ev['raw_ref']}   |   Vault chain hash: {ev['chain_hash'][:24]}...")
    with right:
        st.markdown("**Normalized event**")
        st.json(unified(ev), expanded=2)

# ---------------------------------------------------------------------------
# Parser packs (planned format)
# ---------------------------------------------------------------------------
with tab_packs:
    st.subheader("Adding a new source means adding a file")
    st.write("Each source is described by a small YAML parser pack, not by new code. "
             "This is the planned format, shown as an example.")
    st.code('''source: fortinet_fortigate
version: 1
detect:
  contains: ["devname=", "logid="]
format: key_value
map:
  time: "{date}T{time}Z"
  src.ip: srcip
  src.port: srcport
  dst.ip: dstip
  dst.port: dstport
  action:
    accept: allowed
    deny: blocked
unmapped: extensions      # nothing is dropped''', language="yaml")

st.divider()
st.caption("Sample logs are simplified and illustrative, not captured from real devices. "
           "Timestamps without a timezone are assumed to be UTC.")