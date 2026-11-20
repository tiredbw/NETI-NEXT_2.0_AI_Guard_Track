"""Clear an uncertain inference latch only after local operator recovery."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4


def process_alive(pid):
    if type(pid) is not int or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def recover(path, acknowledged):
    if not acknowledged:
        raise ValueError("Stop the gateway and backend first; explicit acknowledgement is required")
    if not path.is_file() or path.is_symlink():
        raise ValueError("Existing regular database file required")
    db = sqlite3.connect(path, timeout=2)
    try:
        with db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT operation_id,owner_pid FROM detector_operations WHERE model=?",
                             ("qwen3.5:4b",)).fetchone()
            if not row:
                return False
            if process_alive(row[1]):
                raise ValueError("The owning gateway process is still alive; stop it before recovery")
            event = {"id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
                     "event_type": "detector_recovery", "decision": "REVIEW", "risk": "unknown",
                     "reason_codes": ["DETECTOR_QUARANTINED"], "operation_id": row[0],
                     "operator_acknowledged_backend_stopped": True}
            db.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                       (event["id"], "local-console", "control", None, json.dumps(event)))
            db.execute("DELETE FROM detector_operations WHERE model=? AND operation_id=?",
                       ("qwen3.5:4b", row[0]))
        return True
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path(__file__).resolve().parents[1] / "data/audit.sqlite3")
    parser.add_argument("--acknowledge-backend-stopped", action="store_true")
    args = parser.parse_args()
    try:
        changed = recover(args.database, args.acknowledge_backend_stopped)
    except (ValueError, sqlite3.Error) as error:
        parser.exit(1, str(error) + "\n")
    print("Recovery acknowledgement recorded; latch cleared." if changed else "No latch found; nothing changed.")


if __name__ == "__main__":
    main()
