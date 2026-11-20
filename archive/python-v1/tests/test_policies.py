from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time
from uuid import uuid4

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from astraguard.engines import load_policy
from astraguard.main import create_app
from astraguard.policies import policy_etag
from astraguard.schemas import Principal
from astraguard.storage import AuditStore
from test_core import FakeDetector


@pytest.fixture
def control(tmp_path):
    identities = {
        "a" * 32: Principal(subject_id="admin", tenant_id="control", role="policy_admin"),
        "v" * 32: Principal(subject_id="viewer", tenant_id="A", role="viewer"),
        "r" * 32: Principal(subject_id="reviewer", tenant_id="A", role="security_reviewer"),
    }
    detector = FakeDetector()
    kwargs = dict(credentials=identities, db_path=tmp_path / "audit.db", hmac_key=b"h" * 32, detector=detector)
    app = create_app(**kwargs)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + "a" * 32
        yield client, app, detector, kwargs


def read_policy(client):
    response = client.get("/v1/policies/strict-demo-v1")
    assert response.status_code == 200
    return response.json(), response.headers["ETag"]


def update(client, body, etag):
    return client.put("/v1/policies/strict-demo-v1", json=body, headers={"If-Match": etag})


def test_immutable_update_and_restart(control, tmp_path):
    client, app, _, kwargs = control
    original, etag = read_policy(client)
    changed = json.loads(json.dumps(original))
    changed["roles"]["viewer"]["allowed_tools"] = []
    response = update(client, changed, etag)
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2
    assert response.headers["ETag"] != etag
    with app.state.store.connect() as db:
        assert json.loads(db.execute("SELECT config FROM policies WHERE version=1").fetchone()[0]) == original
        assert db.execute("SELECT author FROM policy_metadata WHERE version=2").fetchone()[0] == "admin"
    assert update(client, changed, etag).status_code == 412
    invalid_seed = tmp_path / "invalid.yaml"
    invalid_seed.write_text("!!python/object:invalid {}")
    restarted = create_app(**kwargs, policy_path=invalid_seed)
    with TestClient(restarted) as other:
        other.headers["Authorization"] = "Bearer " + "v" * 32
        assert other.get("/v1/policies").json()[0]["version"] == 2
        sid = other.post("/v1/sessions").json()["session_id"]
        result = other.post("/v1/agent/turns", json={"text": "/read A1", "session_id": sid, "policy_id": "strict-demo-v1"}).json()
        assert result["check"]["decision"] == "BLOCK"
        assert result["execution"]["target_invocations"] == 0


@pytest.mark.parametrize("role", ["v", "r"])
def test_only_admin_can_read_or_update_full_policy(control, role):
    client, _, _, _ = control
    body, etag = read_policy(client)
    client.headers["Authorization"] = "Bearer " + role * 32
    assert client.get("/v1/policies/strict-demo-v1").status_code == 403
    assert update(client, body, etag).status_code == 403


def test_admin_has_no_tool_or_reviewer_privileges(control):
    client, _, detector, _ = control
    sid = client.post("/v1/sessions").json()["session_id"]
    assert client.post("/v1/agent/turns", json={"text": "/read B1", "session_id": sid, "policy_id": "strict-demo-v1"}).status_code == 403
    assert client.post("/v1/reviews/unknown/approve", json={}).status_code == 403
    assert detector.calls == 0


def test_if_match_required_and_version_is_server_assigned(control):
    client, _, _, _ = control
    body, etag = read_policy(client)
    assert client.put("/v1/policies/strict-demo-v1", json=body).status_code == 428
    assert update(client, body, "*").status_code == 412
    assert update(client, body | {"version": 999}, etag).status_code == 412
    assert client.get("/v1/policies/unknown").status_code == 404
    assert update(client, body, etag).json()["version"] == 2


@pytest.mark.parametrize("attack", ["scope", "tool", "viewer_write", "confirmation", "admin_role", "extra"])
def test_non_overridable_limits(control, attack):
    client, _, _, _ = control
    body, etag = read_policy(client)
    if attack == "scope":
        body["roles"]["viewer"]["resource_scope"] = "all_tenants"
    elif attack == "tool":
        body["roles"]["operator"]["allowed_tools"] = ["shell.exec"]
    elif attack == "viewer_write":
        body["roles"]["viewer"] = body["roles"]["operator"]
    elif attack == "confirmation":
        body["roles"]["operator"]["confirmation_actions"] = []
    elif attack == "admin_role":
        body["roles"]["policy_admin"] = body["roles"]["viewer"]
    else:
        body["bypass_acl"] = True
    assert update(client, body, etag).status_code == 422
    assert read_policy(client)[0]["version"] == 1


def test_failed_audit_rolls_back_policy_activation(control, monkeypatch):
    client, app, _, _ = control
    body, etag = read_policy(client)
    def fail(*args):
        raise sqlite3.OperationalError("sensitive-error-sentinel")
    monkeypatch.setattr(app.state.store, "insert", fail)
    response = update(client, body, etag)
    assert response.status_code == 503
    assert "sensitive-error-sentinel" not in response.text
    assert read_policy(client)[1] == etag
    with app.state.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 1


def test_concurrent_update_has_one_winner(control):
    _, app, _, kwargs = control
    current = app.state.policies.snapshot()
    admin = kwargs["credentials"]["a" * 32]
    def write(_):
        try:
            app.state.policies.replace(current, policy_etag(current), admin)
            return 200
        except HTTPException as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(write, range(2))) == [200, 412]
    assert app.state.policies.snapshot().version == 2


def test_detached_snapshot_cannot_change_active_permissions(control):
    _, app, _, _ = control
    snapshot = app.state.policies.snapshot()
    snapshot.roles["viewer"].allowed_tools.clear()
    assert app.state.policies.snapshot().roles["viewer"].allowed_tools == ["documents.read"]


@pytest.mark.parametrize("change", ["UPDATE active_policies SET version=999", "DELETE FROM active_policies"])
def test_dangling_active_pointer_is_fail_closed(control, change):
    client, app, _, _ = control
    with app.state.store.connect() as db:
        db.execute(change)
    assert client.get("/health/ready").status_code == 503
    assert client.get("/v1/policies/strict-demo-v1").status_code == 503


def test_policy_change_during_detector_stops_forwarding(control, monkeypatch):
    client, app, detector, kwargs = control
    original = detector.analyze
    async def changing(text):
        policy = app.state.policies.snapshot()
        app.state.policies.replace(policy, policy_etag(policy), kwargs["credentials"]["a" * 32])
        return await original(text)
    monkeypatch.setattr(detector, "analyze", changing)
    client.headers["Authorization"] = "Bearer " + "v" * 32
    sid = client.post("/v1/sessions").json()["session_id"]
    result = client.post("/v1/agent/turns", json={"text": "/read A1", "session_id": sid, "policy_id": "strict-demo-v1"}).json()
    assert result["check"]["decision"] == "REVIEW"
    assert result["check"]["reason_codes"] == ["POLICY_CHANGED"]
    assert not result["execution"]["forwarded"]
    assert app.state.agent.invocations == 0


def test_policy_change_after_check_is_rechecked_in_executor(control, monkeypatch):
    client, app, _, kwargs = control
    original = app.state.agent.invoke
    def changing(*args):
        policy = app.state.policies.snapshot()
        app.state.policies.replace(policy, policy_etag(policy), kwargs["credentials"]["a" * 32])
        return original(*args)
    monkeypatch.setattr(app.state.agent, "invoke", changing)
    client.headers["Authorization"] = "Bearer " + "v" * 32
    sid = client.post("/v1/sessions").json()["session_id"]
    result = client.post("/v1/agent/turns", json={"text": "/read A1", "session_id": sid, "policy_id": "strict-demo-v1"}).json()
    assert result["check"]["decision"] == "ALLOW"
    assert result["execution"]["status"] == "failed"
    assert result["execution"]["tool_check"]["reason_codes"] == ["POLICY_CHANGED"]
    assert result["execution"]["result"] is None


@pytest.mark.parametrize("raw", [
    "id: strict-demo-v1\nid: other\nversion: 1\nroles: {}",
    "id: strict-demo-v1\nversion: 1\nroles: {<<: {viewer: {}}}",
    "a: " + "[" * 50 + "0" + "]" * 50,
])
def test_unsafe_yaml_structure(tmp_path, raw):
    path = tmp_path / "policy.yaml"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_policy(path)


def test_audit_retention_preserves_recent_events_and_policies(tmp_path):
    store = AuditStore(tmp_path / "audit.db", b"h" * 32)
    store.seed_policy(load_policy(Path("policies/strict-demo.yaml")))
    principal = Principal(subject_id="alice", tenant_id="A", role="viewer")
    old_id, new_id = str(uuid4()), str(uuid4())
    for event_id, days in [(old_id, 8), (new_id, 1)]:
        store.save(principal, "sensitive-source", {"id": event_id, "decision": "ALLOW",
            "created_at": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()})
    with store.connect() as db:
        db.execute("INSERT INTO approvals(id,expires) VALUES ('old',?)", (time.time() - 1,))
        db.execute("INSERT INTO approvals(id,expires) VALUES ('new',?)", (time.time() + 120,))
        db.execute("INSERT INTO executions VALUES ('A','alice','old','hash','{}',?)", (time.time() - 1,))
    restarted = AuditStore(store.path, store.key)
    assert restarted.get(principal, old_id) is None
    assert restarted.get(principal, new_id) is not None
    with restarted.connect() as db:
        assert db.execute("SELECT id FROM approvals").fetchall() == [("new",)]
        assert db.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 1
    assert "sensitive-source" not in store.path.read_bytes().decode("latin-1")


@pytest.mark.parametrize("days", [0, 31, True])
def test_invalid_retention_rejected(tmp_path, days):
    with pytest.raises(ValueError):
        AuditStore(tmp_path / "db", b"h" * 32, retention_days=days)
