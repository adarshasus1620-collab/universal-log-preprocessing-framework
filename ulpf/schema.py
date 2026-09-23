"""Unified event schema for ULPF.

Every parser must produce a dict that fits this schema. Fields the parser
could not map go into `extensions`, so nothing from the raw log is dropped.
"""
from typing import Optional
from pydantic import BaseModel, Field


class SourceMeta(BaseModel):
    vendor: str
    product: str
    raw_ref: str          # e.g. "fortinet.log:2" -> which file and line
    raw_sha256: str        # hash of the exact raw line, for the trace/tamper check


class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None


class UnifiedEvent(BaseModel):
    time: str                       # ISO 8601, e.g. "2026-09-19T10:15:32Z"
    cls: str = Field(alias="class") # e.g. "Network Activity", "Authentication"
    activity: str                   # e.g. "Traffic", "Logon", "Alert"
    action: str                     # e.g. "allowed", "blocked", "failed"
    severity: str                   # "Low" | "Medium" | "High"
    src: Endpoint = Endpoint()
    dst: Endpoint = Endpoint()
    protocol: Optional[str] = None
    user: Optional[str] = None
    message: str
    metadata: SourceMeta
    extensions: dict = {}

    class Config:
        populate_by_name = True


if __name__ == "__main__":
    # Quick self-test: build one event and print it.
    ev = UnifiedEvent(
        time="2026-09-19T10:15:32Z",
        **{"class": "Network Activity"},
        activity="Traffic",
        action="allowed",
        severity="Low",
        src=Endpoint(ip="10.1.1.5", port=51234),
        dst=Endpoint(ip="8.8.8.8", port=443),
        protocol="TCP",
        message="Forwarded traffic to HTTPS service",
        metadata=SourceMeta(vendor="Fortinet", product="FortiGate",
                            raw_ref="fortinet.log:1", raw_sha256="abc123"),
    )
    print(ev.model_dump_json(indent=2, by_alias=True))