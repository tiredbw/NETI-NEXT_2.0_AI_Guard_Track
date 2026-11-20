import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

from astraguard.storage import AuditStore


def recovery_module():
    spec = importlib.util.spec_from_file_location("detector_recovery", "scripts/reset_detector.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recovery_requires_ack_and_stopped_gateway(tmp_path):
    module = recovery_module()
    store = AuditStore(tmp_path / "db", b"h" * 32)
    store.claim_detector("qwen3.5:4b", "operation", "d" * 64)
    with pytest.raises(ValueError):
        module.recover(store.path, False)
    with pytest.raises(ValueError):
        module.recover(store.path, True)
    assert store.detector_operation("qwen3.5:4b")


def test_recovery_is_audited_and_atomic(tmp_path, monkeypatch):
    module = recovery_module()
    store = AuditStore(tmp_path / "db", b"h" * 32)
    store.claim_detector("qwen3.5:4b", "operation", "d" * 64)
    monkeypatch.setattr(module, "process_alive", lambda pid: False)
    with store.connect() as db:
        db.execute("CREATE TRIGGER fail_recovery BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'disk error'); END")
    with pytest.raises(sqlite3.Error):
        module.recover(store.path, True)
    assert store.detector_operation("qwen3.5:4b")
    with store.connect() as db:
        db.execute("DROP TRIGGER fail_recovery")
    assert module.recover(store.path, True)
    assert store.detector_operation("qwen3.5:4b") is None
    with store.connect() as db:
        event = json.loads(db.execute("SELECT result FROM events").fetchone()[0])
    assert event["event_type"] == "detector_recovery"
    assert event["operator_acknowledged_backend_stopped"] is True
    assert not module.recover(store.path, True)
