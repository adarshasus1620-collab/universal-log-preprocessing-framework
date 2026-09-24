"""Raw event vault: stores every raw log line exactly as it arrived, plus
its SHA-256 hash, and chains each entry to the one before it (like a simple
blockchain). This makes the vault tamper-evident: changing or deleting any
past entry breaks the chain from that point onward.

Storage format: one JSON object per line (JSON Lines) in output/vault.jsonl.
"""
import hashlib
import json
from pathlib import Path

VAULT_PATH = Path(__file__).resolve().parent.parent / "output" / "vault.jsonl"
GENESIS_HASH = "0" * 64


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _last_chain_hash() -> str:
    """The chain_hash of the last entry currently in the vault, or the
    genesis hash if the vault is empty. New entries build on this."""
    if not VAULT_PATH.exists():
        return GENESIS_HASH
    last = None
    with VAULT_PATH.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = line
    if last is None:
        return GENESIS_HASH
    return json.loads(last)["chain_hash"]


def store_raw_event(raw_line: str, source_file: str, source_line: int) -> dict:
    """Append one raw event to the vault and return its vault record,
    including the trace_id other code should save alongside the
    normalized event."""
    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    raw_sha256 = sha256(raw_line)
    prev_chain_hash = _last_chain_hash()
    chain_hash = sha256(prev_chain_hash + raw_sha256)
    trace_id = f"{source_file}:{source_line}:{raw_sha256[:12]}"

    record = {
        "trace_id": trace_id,
        "source_file": source_file,
        "source_line": source_line,
        "raw": raw_line,
        "raw_sha256": raw_sha256,
        "prev_chain_hash": prev_chain_hash,
        "chain_hash": chain_hash,
    }
    with VAULT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


def load_vault() -> list[dict]:
    if not VAULT_PATH.exists():
        return []
    return [json.loads(line) for line in VAULT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def verify_chain() -> tuple[bool, str]:
    """Replay the whole vault and confirm every chain_hash is correct.
    Returns (is_valid, message)."""
    records = load_vault()
    prev = GENESIS_HASH
    for i, r in enumerate(records, start=1):
        expected_raw_hash = sha256(r["raw"])
        if expected_raw_hash != r["raw_sha256"]:
            return False, f"Entry {i} ({r['trace_id']}): raw text does not match its stored hash."
        expected_chain_hash = sha256(prev + r["raw_sha256"])
        if expected_chain_hash != r["chain_hash"]:
            return False, f"Entry {i} ({r['trace_id']}): chain is broken here."
        prev = r["chain_hash"]
    return True, f"All {len(records)} vault entries verified. Chain is intact."


if __name__ == "__main__":
    # Self-test: reset, store 3 fake events, verify, then tamper and verify again.
    if VAULT_PATH.exists():
        VAULT_PATH.unlink()

    store_raw_event("first test line", "test.log", 1)
    store_raw_event("second test line", "test.log", 2)
    store_raw_event("third test line", "test.log", 3)

    ok, msg = verify_chain()
    print(f"Before tampering: {ok} | {msg}")

    # Simulate tampering: change one character in entry 2, leave the hash as-is.
    records = load_vault()
    records[1]["raw"] = "second test LINE (tampered)"
    VAULT_PATH.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    ok, msg = verify_chain()
    print(f"After tampering:  {ok} | {msg}")