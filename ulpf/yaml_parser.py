"""Generic, YAML-driven parser engine.

Instead of writing a new Python parser for every vendor, an analyst can
write a small YAML "parser pack" describing how to detect and map that
vendor's log format. This engine reads the pack and does the parsing.

Three formats are supported, each as its own handler:
  - key_value   e.g. Fortinet: date=... srcip=10.1.1.5 action="accept"
  - json        e.g. Suricata EVE: {"event_type":"alert","alert":{...}}
  - csv_positional   e.g. pfSense filterlog: comma-separated fields inside
                     a syslog header, picked out by column index
"""
import hashlib
import json
import re
from pathlib import Path

import yaml

from schema import Endpoint, SourceMeta, UnifiedEvent

KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def kv_parse(line: str) -> dict:
    """Turn 'a=1 b="two words" c=3' into {'a': '1', 'b': 'two words', 'c': '3'}."""
    out = {}
    for key, quoted, bare in KV_RE.findall(line):
        out[key] = quoted if quoted != "" or bare == "" else bare
    return out


def cast(value):
    """Turn digit-only strings into int, so extensions keep useful types."""
    return int(value) if isinstance(value, str) and value.isdigit() else value


def get_path(obj, dotted: str):
    """Look up a dotted path like 'alert.signature' inside a nested dict."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


class YamlParserPack:
    """Loads one .yaml parser pack and can detect + parse lines with it."""

    def __init__(self, pack_path: Path):
        self.pack_path = pack_path
        self.spec = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
        self.source_name = self.spec["source"]
        self.vendor = self.spec.get("vendor", self.spec["source"])
        self.product = self.spec.get("product", self.vendor)
        self.detect_contains = self.spec.get("detect", {}).get("contains", [])
        self.field_map = self.spec.get("map", {})
        self.format = self.spec.get("format", "key_value")

    def matches(self, raw_line: str) -> bool:
        return all(token in raw_line for token in self.detect_contains)

    def parse(self, raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
        if self.format == "json":
            return self._parse_json(raw_line, file_name, line_no)
        if self.format == "csv_positional":
            return self._parse_csv_positional(raw_line, file_name, line_no)
        if self.format != "key_value":
            raise ValueError(f"format '{self.format}' is not supported yet")
        return self._parse_key_value(raw_line, file_name, line_no)

    # ------------------------------------------------------------------
    # Format: key_value  (e.g. Fortinet, Acme Firewall)
    # ------------------------------------------------------------------
    def _parse_key_value(self, raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
        kv = kv_parse(raw_line)
        mapped_keys = set()

        def field(name, default=None):
            rule = self.field_map.get(name)
            if isinstance(rule, str):
                mapped_keys.add(rule)
                return kv.get(rule, default)
            return default

        time_rule = self.field_map.get("time")
        iso_time = (time_rule.format(**kv) if time_rule and "{" in time_rule
                    else kv.get(time_rule, "1970-01-01T00:00:00Z"))

        action_rule = self.field_map.get("action", {})
        raw_action = None
        for src_field in ("action", "act", "verdict"):
            if src_field in kv:
                raw_action = kv[src_field]
                mapped_keys.add(src_field)
                break
        action = (action_rule.get(raw_action, raw_action)
                  if isinstance(action_rule, dict) else (raw_action or "unknown"))

        src_ip, src_port_raw = field("src.ip"), field("src.port")
        dst_ip, dst_port_raw = field("dst.ip"), field("dst.port")

        extensions = {k: cast(v) for k, v in kv.items() if k not in mapped_keys}
        extensions["parsed_by"] = f"yaml_pack:{self.source_name}"

        return UnifiedEvent(
            time=iso_time,
            **{"class": "Network Activity"},
            activity="Traffic",
            action=action,
            severity="Medium",
            src=Endpoint(ip=src_ip, port=int(src_port_raw) if src_port_raw else None),
            dst=Endpoint(ip=dst_ip, port=int(dst_port_raw) if dst_port_raw else None),
            protocol=None,
            user=None,
            message=f"{self.vendor} event ({raw_action or 'unknown'})",
            metadata=SourceMeta(vendor=self.vendor, product=self.product,
                                raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
            extensions=extensions,
        )

    # ------------------------------------------------------------------
    # Format: json  (e.g. Suricata EVE JSON)
    # ------------------------------------------------------------------
    def _parse_json(self, raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
        data = json.loads(raw_line)
        alert_key = self.spec.get("alert_key", "alert")
        alert = data.get(alert_key, {})

        time_rule = self.field_map.get("time")
        raw_time = get_path(data, time_rule) if time_rule else None
        iso_time = str(raw_time).replace("+0000", "Z") if raw_time else "1970-01-01T00:00:00Z"

        action_rule = self.field_map.get("action", {})
        raw_action = alert.get("action")
        action = (action_rule.get(raw_action, raw_action)
                  if isinstance(action_rule, dict) else (raw_action or "unknown"))

        def mapped(name):
            rule = self.field_map.get(name)
            return get_path(data, rule) if rule else None

        src_ip, src_port = mapped("src.ip"), mapped("src.port")
        dst_ip, dst_port = mapped("dst.ip"), mapped("dst.port")
        message = alert.get(self.spec.get("message_field", "signature"), f"{self.vendor} event")

        extra_keys = self.spec.get("extensions", [])
        extensions = {k: alert.get(k) for k in extra_keys if k in alert}
        extensions["parsed_by"] = f"yaml_pack:{self.source_name}"

        return UnifiedEvent(
            time=iso_time,
            **{"class": "Detection Finding"},
            activity="Alert",
            action=action,
            severity="Medium",
            src=Endpoint(ip=src_ip, port=src_port),
            dst=Endpoint(ip=dst_ip, port=dst_port),
            protocol=data.get("proto"),
            user=None,
            message=message,
            metadata=SourceMeta(vendor=self.vendor, product=self.product,
                                raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
            extensions=extensions,
        )

    # ------------------------------------------------------------------
    # Format: csv_positional  (e.g. pfSense filterlog)
    # ------------------------------------------------------------------
    def _parse_csv_positional(self, raw_line: str, file_name: str, line_no: int) -> UnifiedEvent:
        header = self.spec.get("header", {})
        header_re = re.compile(header.get("regex", ""))
        m = header_re.match(raw_line)
        if not m:
            raise ValueError("line does not match this pack's header regex")
        g = m.groupdict()
        cols = g["csv"].split(",")

        col_map = self.spec.get("columns", {})

        def col(name, cast_int=False):
            idx = col_map.get(name)
            if idx is None or idx >= len(cols):
                return None
            val = cols[idx]
            if cast_int:
                return int(val) if val.isdigit() else None
            return val or None

        if "mon" in g and "day" in g and "time" in g:
            from datetime import datetime
            year = g.get("year") or str(datetime.now().year)
            dt = datetime.strptime(f"{g['mon']} {g['day']} {year} {g['time']}", "%b %d %Y %H:%M:%S")
            iso_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            iso_time = "1970-01-01T00:00:00Z"

        action_rule = self.spec.get("action", {})
        raw_action = col("action")
        action = action_rule.get(raw_action, raw_action) if raw_action else "unknown"
        severity = "Medium" if action == "blocked" else "Low"
        protocol = (col("protocol") or "").upper() or None
        direction = col("direction")
        message = f"{protocol or ''} {direction + 'bound ' if direction else ''}traffic {raw_action or ''}ed".strip()

        extensions = {"parsed_by": f"yaml_pack:{self.source_name}"}
        if direction:
            extensions["direction"] = direction

        return UnifiedEvent(
            time=iso_time,
            **{"class": "Network Activity"},
            activity="Traffic",
            action=action,
            severity=severity,
            src=Endpoint(ip=col("src_ip"), port=col("src_port", cast_int=True)),
            dst=Endpoint(ip=col("dst_ip"), port=col("dst_port", cast_int=True)),
            protocol=protocol,
            user=None,
            message=message,
            metadata=SourceMeta(vendor=self.vendor, product=self.product,
                                raw_ref=f"{file_name}:{line_no}", raw_sha256=sha256(raw_line)),
            extensions=extensions,
        )


def load_parser_packs(packs_dir: Path) -> list[YamlParserPack]:
    if not packs_dir.exists():
        return []
    return [YamlParserPack(p) for p in sorted(packs_dir.glob("*.yaml"))]


if __name__ == "__main__":
    packs_dir = Path(__file__).resolve().parent.parent / "parsers"
    packs = load_parser_packs(packs_dir)
    print(f"Loaded {len(packs)} parser pack(s): {[p.source_name for p in packs]}")

    if packs:
        test_line = 'date=2026-09-19 time=09:00:00 devname="TEST" logid="1" type="traffic" srcip=10.0.0.1 srcport=1111 dstip=10.0.0.2 dstport=2222 action="accept"'
        for pack in packs:
            if pack.matches(test_line):
                event = pack.parse(test_line, "test.log", 1)
                print(f"\nMatched pack '{pack.source_name}':")
                print(event.model_dump_json(indent=2, by_alias=True))