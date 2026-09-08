"""
audit_log.py - Layer 3: Tamper-evident cryptographic ledger.
Records security events and tool invocations linked sequentially with
SHA-256 hashes so any retroactive changes break the chain.
"""

"""

Evolution Log:
- v1.0: Initial implementation of sequential SHA-256 hash chaining anchored at genesis.
- v1.1: Streamlined dictionary serialization to ensure deterministic JSON hashing across platforms.
- v1.2: Replaced complex nested keys with flat audit event records.
- v1.3: Aligned log entry fields with EU AI Act Article 12 compliance (retaining documented owner_id gap).
"""

import hashlib
import json
import time
from typing import Dict, List, Any, Optional

# Standard genesis seed for the initial chain link
genesis_hash = "0" * 64


def hash_entry(prev_hash: str, entry_data: Dict[str, Any]) -> str:
    """Build a deterministic SHA-256 digest from previous hash and entry data."""
    serialized = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
    payload = f"{prev_hash}:{serialized}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditLedger:
    def __init__(self):
        self.entries: List[Dict[str, Any]] = []

    @property
    def latest_hash(self) -> str:
        if not self.entries:
            return genesis_hash
        return self.entries[-1]["entry_hash"]

    def record_event(
        self,
        event_type: str,
        tool_name: str,
        decision: str,
        details: Optional[Dict[str, Any]] = None,
        reason: str = ""
    ) -> Dict[str, Any]:
        """Creates and appends a verified, hash-chained log entry."""
        prev = self.latest_hash

        entry_body = {
            "index": len(self.entries),
            "timestamp": time.time(),
            "event_type": event_type,
            "tool_name": tool_name,
            "decision": decision,
            "reason": reason,
            "details": details or {}
        }

        current_hash = hash_entry(prev, entry_body)

        log_record = {
            **entry_body,
            "prev_hash": prev,
            "entry_hash": current_hash
        }

        self.entries.append(log_record)
        return log_record

    def verify_integrity(self) -> Dict[str, Any]:
        """Checks each link in the chain to confirm no records were modified."""
        if not self.entries:
            return {"valid": True, "count": 0, "broken_index": None}

        expected_prev = genesis_hash

        for idx, item in enumerate(self.entries):
            if item["prev_hash"] != expected_prev:
                return {"valid": False, "count": len(self.entries), "broken_index": idx}

            body = {
                "index": item["index"],
                "timestamp": item["timestamp"],
                "event_type": item["event_type"],
                "tool_name": item["tool_name"],
                "decision": item["decision"],
                "reason": item["reason"],
                "details": item["details"]
            }

            computed = hash_entry(expected_prev, body)
            if computed != item["entry_hash"]:
                return {"valid": False, "count": len(self.entries), "broken_index": idx}

            expected_prev = item["entry_hash"]

        return {"valid": True, "count": len(self.entries), "broken_index": None}


# Shared default ledger instance
ledger = AuditLedger()
