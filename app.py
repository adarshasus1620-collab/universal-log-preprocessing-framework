"""ULPF prototype UI (Streamlit).

Frontend-first demo. The events below are SAMPLE data: raw lines are copied from
sample_logs/, and the normalized fields were filled in by hand for this demo.
The SHA-256 hashes and the integrity check are computed live in this file.
The real parsing engine is still under development.
"""
import hashlib

import pandas as pd
import streamlit as st

st.set_page_config(page_title="ULPF - Universal Log Pre-processing Framework",
                   page_icon=":shield:", layout="wide")

NAVY = "#1F497D"
BLUE = "#0070C0"

st.markdown(
    f"""
    <style>
      .block-container {{ padding-top: 4.5rem; max-width: 1250px; }}
      .ulpf-hero {{ background: {NAVY}; color: white; padding: 1.4rem 1.6rem;
                    border-radius: 8px; margin-bottom: 1rem; }}
      .ulpf-hero h1 {{ color: white; font-size: 1.7rem; margin: 0 0 .25rem 0; padding: 0; }}
      .ulpf-hero p {{ color: #D6E4F3; margin: 0; font-size: 1rem; }}
      div[data-testid="stMetricValue"] {{ color: {BLUE}; }}
    </style>
    <div class="ulpf-hero">
      <h1>Universal Log Pre-processing Framework</h1>
      <p>Any perimeter-device log in, one lossless, analytics-ready event out.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.info("Prototype UI with sample data. The parsing engine is under development. "
        "Hashes and the integrity check on the Trace tab are computed live.")

# ---------------------------------------------------------------------------
# Sample data: raw line (copied from sample_logs) + hand-normalized fields
# ---------------------------------------------------------------------------
EVENTS = [
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


# Derived fields: event id, raw hash, and a hash chain over the raw events
_prev = "0" * 64
for i, e in enumerate(EVENTS):
    e["event_id"] = f"evt-{i + 1:04d}"
    e["raw_ref"] = f"{e['file']}:{e['line']}"
    e["raw_sha256"] = sha256(e["raw"])
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


TABLE_COLS = ["event_id", "time", "vendor", "class", "activity", "action", "severity",
              "src_ip", "src_port", "dst_ip", "dst_port", "proto", "message"]


def to_df(events) -> pd.DataFrame:
    """Table for display: every cell is text, and empty cells show a dash."""
    df = pd.DataFrame(events).rename(columns={"cls": "class"})[TABLE_COLS]
    df = df.rename(columns={"proto": "protocol"})
    for c in df.columns:
        df[c] = df[c].map(lambda v: "-" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v))
    return df


DF = to_df(EVENTS)
MSG_CFG = {"message": st.column_config.TextColumn("message", width="large")}

tab_overview, tab_before, tab_events, tab_trace, tab_packs = st.tabs(
    ["Overview", "Before and after", "Events", "Trace and integrity", "Parser packs"]
)

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
with tab_overview:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events normalized", len(DF))
    c2.metric("Sources", DF["vendor"].nunique())
    c3.metric("Blocked or failed", int(DF["action"].isin(["blocked", "failed"]).sum()))
    c4.metric("IDS alerts", int((DF["class"] == "Detection Finding").sum()))

    left, right = st.columns(2)
    with left:
        st.subheader("Events per source")
        st.bar_chart(DF["vendor"].value_counts(), color=BLUE, horizontal=True, height=220)
    with right:
        st.subheader("Actions taken")
        st.bar_chart(DF["action"].value_counts(), color=BLUE, horizontal=True, height=220)

    st.subheader("One attacker, three devices")
    by_ip = DF.groupby("src_ip")["vendor"].nunique().sort_values(ascending=False)
    top_ip = by_ip.index[0]
    st.write(f"**{top_ip}** was seen by **{by_ip.iloc[0]}** different vendors. "
             "Because every event uses the same field names, one filter finds all of them.")
    st.dataframe(DF[DF["src_ip"] == top_ip][["time", "vendor", "activity", "action", "dst_ip",
                                             "dst_port", "message"]],
                 hide_index=True, width="stretch", column_config=MSG_CFG)

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
    st.markdown("<div style='text-align:center; font-size:1.6rem; color:#0070C0;'>&#8595; ULPF &#8595;</div>",
                unsafe_allow_html=True)
    st.subheader("Same event, one schema")
    st.dataframe(to_df(probe).drop(columns=["event_id"]), hide_index=True, width="stretch",
                 column_config=MSG_CFG)
    st.caption("Fields that do not fit the common schema stay in extensions, "
               "so nothing from the original is lost.")

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
with tab_events:
    f1, f2, f3 = st.columns(3)
    vendors = f1.multiselect("Source", sorted(DF["vendor"].unique()), default=sorted(DF["vendor"].unique()))
    actions = f2.multiselect("Action", sorted(DF["action"].unique()), default=sorted(DF["action"].unique()))
    sev = f3.multiselect("Severity", ["Low", "Medium", "High"], default=["Low", "Medium", "High"])
    view = DF[DF["vendor"].isin(vendors) & DF["action"].isin(actions) & DF["severity"].isin(sev)]
    st.write(f"Showing {len(view)} of {len(DF)} events")
    st.dataframe(view, hide_index=True, width="stretch", column_config=MSG_CFG)

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
        edited = st.text_area("Raw text (editable for the tamper test)", value=ev["raw"],
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