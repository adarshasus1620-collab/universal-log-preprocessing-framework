"""Generic, YAML-driven parser engine.

Instead of writing a new Python parser for every vendor, an analyst can
write a small YAML "parser pack" describing how to detect and map that
vendor's log format. This engine reads the pack and does the parsing.

This currently supports the key=value format (like Fortinet). Other
formats (CSV, JSON) can be added the same way, as new format handlers.
"""
import hashlib
import re
from pathlib import Path

import yaml

from schema import Endpoint, SourceMeta, UnifiedEvent

KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def kv_parse(line: str) -> dict:
    out = {}
    for key, quoted, bare in KV_RE.findall(line):
        out[key] = quoted if quoted != "" or bare == "" else bare
    return out


def cast(value: str):
    return int(value) if value.isdigit() else value


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
        if self.format != "key_value":
            raise ValueError(f"format '{self.format}' is not supported yet")
        kv = kv_parse(raw_line)
        mapped_keys = set()

        def get_mapped(rule):
            """Resolve one field's value using its mapping rule, which can
            be a plain source-field name, a "{a}T{b}" template, or a
            value-lookup table (e.g. accept -> allowed)."""
            if isinstance(rule, str) and "{" in rule:
                return rule.format(**{k: kv.get(k, "") for k in kv})
            if isinstance(rule, dict):
                src_field = rule.pop("_field", None)
                return rule
            mapped_keys.add(rule)
            return kv.get(rule)

        time_rule = self.field_map.get("time")
        iso_time = time_rule.format(**kv) if time_rule and "{" in time_rule else kv.get(time_rule, "1970-01-01T00:00:00Z")

        def field(name, default=None):
            rule = self.field_map.get(name)
            if rule is None:
                return default
            if isinstance(rule, str):
                mapped_keys.add(rule)
                return kv.get(rule, default)
            return default

        def mapped_value(name, value_map, default=None):
            """For fields like action, where raw values (accept/deny) map
            to unified values (allowed/blocked) via a lookup table."""
            rule = self.field_map.get(name)
            if isinstance(rule, dict):
                src_field = None
                for candidate in kv:
                    pass
            return default

        action_rule = self.field_map.get("action", {})
        raw_action = None
        for src_field in ("action", "act", "verdict"):
            if src_field in kv:
                raw_action = kv[src_field]
                mapped_keys.add(src_field)
                break
        action = action_rule.get(raw_action, raw_action) if isinstance(action_rule, dict) else (raw_action or "unknown")

        src_ip = field("src.ip")
        src_port_raw = field("src.port")
        dst_ip = field("dst.ip")
        dst_port_raw = field("dst.port")

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