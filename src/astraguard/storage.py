import hashlib
import hmac
import json
import os
import sqlite3
import math
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path


class AuditStore:
    def __init__(self, path: Path, key: bytes, retention_days=7):
        if type(retention_days) is not int or not 1 <= retention_days <= 30:
            raise ValueError("Retention must be 1..30 days")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.touch(mode=0o600, exist_ok=True)
        os.chmod(path, 0o600)
        self.path, self.key, self.retention_days = path, key, retention_days
        with self.connect() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] > 4:
                raise ValueError("Unsupported database schema version")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, subject TEXT, tenant TEXT, payload_hmac TEXT, result TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS policies (id TEXT, version INTEGER, config TEXT, PRIMARY KEY(id, version))")
            db.execute("CREATE TABLE IF NOT EXISTS active_policies (id TEXT PRIMARY KEY, version INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS policy_metadata (id TEXT, version INTEGER, created_at TEXT, author TEXT, content_hash TEXT, PRIMARY KEY(id,version))")
            db.execute("CREATE TABLE IF NOT EXISTS detector_operations (model TEXT PRIMARY KEY, operation_id TEXT NOT NULL, owner_pid INTEGER NOT NULL, digest TEXT, started_at TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS events_scope ON events(tenant,subject)")
            db.execute("CREATE TABLE IF NOT EXISTS resources (id TEXT PRIMARY KEY, tenant TEXT, kind TEXT, content TEXT)")
            if "version" not in [row[1] for row in db.execute("PRAGMA table_info(resources)")]:
                db.execute("ALTER TABLE resources ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
            db.execute("CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, check_id TEXT UNIQUE, tenant TEXT, requester TEXT, reviewer TEXT, binding TEXT, policy_hash TEXT, resource_version INTEGER, expires REAL, consumed INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS executions (tenant TEXT, requester TEXT, key TEXT, binding TEXT, result TEXT, expires REAL, PRIMARY KEY(tenant,requester,key))")
            db.executemany("INSERT OR IGNORE INTO resources (id,tenant,kind,content) VALUES (?,?,?,?)", [
                ("A1", "A", "document", "Синтетический документ организации A."),
                ("B1", "B", "document", "Синтетический документ организации B."),
                ("A2", "A", "draft", "Синтетический черновик A."),
                ("B2", "B", "draft", "Синтетический черновик B."),
            ])
            db.execute("PRAGMA user_version=4")
        self.cleanup()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        try:
            with db:
                yield db
        finally:
            db.close()

    def seed_policy(self, policy):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO policies VALUES (?,?,?)", (policy.id, policy.version, policy.model_dump_json()))
            db.execute("INSERT OR IGNORE INTO active_policies SELECT id,MAX(version) FROM policies WHERE id=? GROUP BY id", (policy.id,))
            return self.policy_config(policy.id, db)

    def policy_config(self, policy_id, db=None, *, allow_legacy=False):
        if db is None:
            with self.connect() as connection:
                return self.policy_config(policy_id, connection, allow_legacy=allow_legacy)
        row = db.execute("SELECT p.config FROM policies p JOIN active_policies a ON p.id=a.id AND p.version=a.version WHERE p.id=?", (policy_id,)).fetchone()
        if row:
            return row[0]
        if db.execute("SELECT 1 FROM active_policies WHERE id=?", (policy_id,)).fetchone():
            return None
        if not allow_legacy:
            return None
        # Older databases have versions but no active pointer yet.
        row = db.execute("SELECT config FROM policies WHERE id=? ORDER BY version DESC LIMIT 1", (policy_id,)).fetchone()
        return row[0] if row else None

    def cleanup(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        with self.connect() as db:
            db.execute("DELETE FROM events WHERE julianday(json_extract(result,'$.created_at')) < julianday(?)", (cutoff,))
            db.execute("DELETE FROM approvals WHERE expires < ?", (time.time(),))
            db.execute("DELETE FROM executions WHERE expires < ?", (time.time(),))

    def detector_operation(self, model):
        with self.connect() as db:
            return db.execute("SELECT operation_id,owner_pid,digest,started_at FROM detector_operations WHERE model=?", (model,)).fetchone()

    def claim_detector(self, model, operation_id, digest):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM detector_operations WHERE model=?", (model,)).fetchone():
                return False
            db.execute("INSERT INTO detector_operations VALUES (?,?,?,?,?)", (model, operation_id, os.getpid(),
                       digest, datetime.now(timezone.utc).isoformat()))
        return True

    def release_detector(self, model, operation_id):
        with self.connect() as db:
            cursor = db.execute("DELETE FROM detector_operations WHERE model=? AND operation_id=?",
                                (model, operation_id))
            return cursor.rowcount == 1

    def save(self, principal, text, result):
        with self.connect() as db:
            self.insert(db, principal, text, result)

    def insert(self, db, principal, text, result):
        digest = hmac.new(self.key, text.encode(), hashlib.sha256).hexdigest()
        db.execute("INSERT INTO events VALUES (?,?,?,?,?)", (
            result["id"], principal.subject_id, principal.tenant_id, digest, json.dumps(result)))

    def get(self, principal, event_id):
        with self.connect() as db:
            row = db.execute("SELECT result FROM events WHERE id=? AND tenant=? AND (subject=? OR ?)", (
                event_id, principal.tenant_id, principal.subject_id, principal.role == "security_reviewer")).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, principal, limit):
        with self.connect() as db:
            rows = db.execute("SELECT result FROM events WHERE tenant=? AND (subject=? OR ?) ORDER BY rowid DESC LIMIT ?", (
                principal.tenant_id, principal.subject_id, principal.role == "security_reviewer", limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def statistics(self, principal):
        window = min(7, self.retention_days)
        since = (datetime.now(timezone.utc) - timedelta(days=window)).isoformat()
        with self.connect() as db:
            rows = db.execute("SELECT result FROM events WHERE tenant=? AND json_extract(result,'$.created_at') >= ?",
                              (principal.tenant_id, since)).fetchall()
        events = [json.loads(row[0]) for row in rows]
        checks = [e for e in events if e.get("event_type", "request_check") == "request_check" and not e.get("approved_check_id")]
        counts = Counter(e["decision"] for e in checks)
        times = sorted(e["timing_ms"]["total"] for e in checks if "total" in e.get("timing_ms", {}))
        size = len(checks)
        return {"window_days": window, "retention_days": self.retention_days, "sample_size": size,
                "decisions": {d: counts[d] for d in ("ALLOW", "REVIEW", "BLOCK")},
                "review_rate": counts["REVIEW"] / size if size else None,
                "latency_ms": {"sample_size": len(times),
                               "p50": times[math.ceil(len(times) * .5) - 1] if times else None,
                               "p95": times[math.ceil(len(times) * .95) - 1] if times else None},
                "note": "Операционная статистика проверок; это не оценка Precision/Recall."}
