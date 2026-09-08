"""
verify_chain.py - Standalone tool to inspect and verify audit ledger integrity.
Loads log entries, verifies sequential SHA-256 hashes, and checks for tampering.
"""
"""

Evolution Log:
- v1.0: Initial verification routine validating sequential SHA-256 digests.
- v1.1: Simplified verification loop and removed unnecessary nested underscores.
- v1.2: Added CLI entrypoint with exit codes (0 for valid, 1 for broken) for CI/CD pipelines.
- v1.3: Enhanced tamper reporting to pinpoint exact record indices on mutation or deletion.
"""

import json
import sys
from typing import List, Dict, Any
from audit_log import hash_entry, genesis_hash, AuditLedger


def verify_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validates a list of log entries against sequential SHA-256 hashes.
    Returns validation status, total checked count, and the first broken index if any.
    """
    if not records:
        return {"valid": True, "count": 0, "broken_index": None, "message": "Log ledger is empty"}

    expected_prev = genesis_hash

    for idx, item in enumerate(records):
        # 1. Check parent pointer
        if item.get("prev_hash") != expected_prev:
            return {
                "valid": False,
                "count": len(records),
                "broken_index": idx,
                "message": f"Pointer mismatch at record {idx}: expected {expected_prev[:12]}..., got {item.get('prev_hash', '')[:12]}..."
            }

        # 2. Re-compute payload hash
        payload = {
            "index": item["index"],
            "timestamp": item["timestamp"],
            "event_type": item["event_type"],
            "tool_name": item["tool_name"],
            "decision": item["decision"],
            "reason": item["reason"],
            "details": item["details"]
        }

        recalculated = hash_entry(expected_prev, payload)
        if recalculated != item.get("entry_hash"):
            return {
                "valid": False,
                "count": len(records),
                "broken_index": idx,
                "message": f"Hash mismatch at record {idx}: entry data was modified"
            }

        expected_prev = item["entry_hash"]

    return {
        "valid": True,
        "count": len(records),
        "broken_index": None,
        "message": f"All {len(records)} records verified successfully"
    }


def verify_file(filepath: str) -> bool:
    """Loads a JSON ledger file and prints the verification results."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            entries = data if isinstance(data, list) else data.get("entries", [])
    except Exception as err:
        print(f"Error reading {filepath}: {err}")
        return False

    report = verify_records(entries)
    if report["valid"]:
        print(f"[OK] {filepath}: {report['message']}")
        return True
    else:
        print(f"[FAIL] {filepath}: {report['message']} (broken at index {report['broken_index']})")
        return False


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        ok = verify_file(target_file)
        sys.exit(0 if ok else 1)
    else:
        # Default self-test using a small in-memory ledger
        test_ledger = AuditLedger()
        test_ledger.record_event("tool_call", "lookup_ip_reputation", "allow", {"ip": "192.0.2.1"})
        test_ledger.record_event("tool_call", "create_service_ticket", "allow", {"title": "Test Ticket"})

        result = verify_records(test_ledger.entries)
        print(f"Self-check: {result['message']}")
        sys.exit(0 if result["valid"] else 1)
