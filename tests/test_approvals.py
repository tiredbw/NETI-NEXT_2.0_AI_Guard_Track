import pytest
from fastapi.testclient import TestClient

from astraguard.main import create_app
from astraguard.schemas import Principal
from test_core import FakeDetector


@pytest.fixture
def flow(tmp_path):
    roles = {"o": ("operator", "A", "operator"), "r": ("reviewer", "A", "security_reviewer"),
             "x": ("foreign", "B", "security_reviewer"), "s": ("operator", "A", "security_reviewer")}
    identities = {k * 32: Principal(subject_id=v[0], tenant_id=v[1], role=v[2]) for k, v in roles.items()}
    detector = FakeDetector()
    app = create_app(credentials=identities, db_path=tmp_path / "db", hmac_key=b"h" * 32, detector=detector)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + "o" * 32
        sid = client.post("/v1/sessions").json()["session_id"]
        body = {"text": "/write A2 synthetic-new", "session_id": sid, "policy_id": "strict-demo-v1"}
        check = client.post("/v1/agent/turns", json=body).json()["check"]
        assert check["review"]["approvable"]
        yield client, app, detector, body, check


def grant(client, check):
    client.headers["Authorization"] = "Bearer " + "r" * 32
    response = client.post(f'/v1/reviews/{check["id"]}/approve', json={})
    assert response.status_code == 201, response.text
    client.headers["Authorization"] = "Bearer " + "o" * 32
    return response.json()["approval_id"]


def execute(client, body, approval, key="operation-0001"):
    return client.post("/v1/agent/turns", json=body | {"approval_id": approval}, headers={"Idempotency-Key": key})


def test_approval_write_and_retry(flow):
    client, app, _, body, check = flow
    approval = grant(client, check)
    first = execute(client, body, approval)
    assert first.status_code == 200, first.text
    assert first.json()["check"]["approved_check_id"] == check["id"]
    assert first.json()["check"]["decision"] == "ALLOW"
    second = execute(client, body, approval)
    assert second.status_code == 200 and second.json()["execution"]["replayed"]
    assert first.json()["execution"]["tool_invocations"] == 1
    assert second.json()["execution"]["tool_invocations"] == 0
    assert second.json()["execution"]["target_invocations"] == 0
    assert app.state.agent.invocations == 1
    with app.state.store.connect() as db:
        assert db.execute("SELECT content,version FROM resources WHERE id='A2'").fetchone() == ("synthetic-new", 2)
    assert execute(client, body, approval, "different-key").status_code == 409
    original = client.get("/v1/checks/" + check["id"]).json()
    assert original["decision"] == "REVIEW"


@pytest.mark.parametrize("who,status", [("o", 403), ("x", 404), ("s", 403)])
def test_reviewer_separation(flow, who, status):
    client, app, _, _, check = flow
    client.headers["Authorization"] = "Bearer " + who * 32
    assert client.post(f'/v1/reviews/{check["id"]}/approve', json={}).status_code == status
    assert app.state.agent.invocations == 0


@pytest.mark.parametrize("change", [{"text": "/write A2 other"}, {"text": "/write B2 synthetic-new"}, {"policy_id": "other"}])
def test_binding(flow, change):
    client, app, _, body, check = flow
    approval = grant(client, check)
    assert execute(client, body | change, approval).status_code in (403, 409)
    assert app.state.agent.invocations == 0


def test_expiry_and_duplicate_grant(flow):
    client, app, _, body, check = flow
    approval = grant(client, check)
    client.headers["Authorization"] = "Bearer " + "r" * 32
    assert client.post(f'/v1/reviews/{check["id"]}/approve', json={}).status_code == 409
    client.headers["Authorization"] = "Bearer " + "o" * 32
    with app.state.store.connect() as db:
        db.execute("UPDATE approvals SET expires=0")
    assert execute(client, body, approval).status_code == 409


@pytest.mark.parametrize("mutation", ["tenant", "version", "policy", "context"])
def test_changed_authority_or_context(flow, mutation):
    client, app, _, body, check = flow
    approval = grant(client, check)
    with app.state.store.connect() as db:
        if mutation == "tenant":
            db.execute("UPDATE resources SET tenant='B' WHERE id='A2'")
        if mutation == "version":
            db.execute("UPDATE resources SET version=version+1 WHERE id='A2'")
    if mutation == "policy":
        from astraguard.policies import policy_etag
        current = app.state.policies.snapshot()
        app.state.policies.replace(current, policy_etag(current),
                                   Principal(subject_id="admin", tenant_id="control", role="policy_admin"))
    if mutation == "context":
        assert client.post("/v1/agent/turns", json=body | {"text": "Другой вопрос"}).status_code == 200
    assert execute(client, body, approval).status_code == 409


def test_rollback_on_persistence_failure(flow):
    client, app, _, body, check = flow
    approval = grant(client, check)
    with app.state.store.connect() as db:
        db.execute("CREATE TRIGGER fail_execution BEFORE INSERT ON executions BEGIN SELECT RAISE(ABORT,'disk failure'); END")
    assert execute(client, body, approval).status_code == 503
    assert app.state.agent.invocations == 0
    with app.state.store.connect() as db:
        assert db.execute("SELECT version FROM resources WHERE id='A2'").fetchone()[0] == 1
        assert db.execute("SELECT consumed FROM approvals").fetchone()[0] == 0
        db.execute("DROP TRIGGER fail_execution")
    assert execute(client, body, approval).status_code == 200


def test_idempotency_conflict(flow):
    client, app, _, body, check = flow
    approval = grant(client, check)
    assert execute(client, body, approval).status_code == 200
    assert execute(client, body | {"text": "/write A2 changed"}, approval).status_code == 409
    assert app.state.agent.invocations == 1


def test_no_idempotency_key(flow):
    client, _, _, body, check = flow
    approval = grant(client, check)
    assert client.post("/v1/agent/turns", json=body | {"approval_id": approval}).status_code == 400


def test_detector_error_not_approvable(flow):
    client, _, detector, body, _ = flow
    detector.failure = "timeout"
    check = client.post("/v1/agent/turns", json=body).json()["check"]
    assert not check["review"]["approvable"]
    client.headers["Authorization"] = "Bearer " + "r" * 32
    assert client.post(f'/v1/reviews/{check["id"]}/approve', json={}).status_code == 404


def test_review_description_is_bound_and_private(flow):
    client, _, _, _, check = flow
    client.headers["Authorization"] = "Bearer " + "r" * 32
    result = client.get(f'/v1/reviews/{check["id"]}').json()
    assert result["tool"] == "drafts.update" and result["resource_id"] == "A2"
    assert len(result["binding_hmac"]) == 64
    assert "synthetic-new" not in str(result)
    client.headers["Authorization"] = "Bearer " + "x" * 32
    assert client.get(f'/v1/reviews/{check["id"]}').status_code == 404


def test_restart_loses_pending_safely(flow):
    client, app, _, body, check = flow
    approval = grant(client, check)
    # New process has no pending content, even when sessions are recreated.
    from astraguard.approvals import ApprovalService
    from astraguard.schemas import TurnRequest
    service = ApprovalService(app.state.store, app.state.policies, app.state.agent)
    principal = Principal(subject_id="operator", tenant_id="A", role="operator")
    request = TurnRequest.model_validate(body | {"approval_id": approval})
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        service.execute(request, principal, "restart-test", [])
    assert error.value.status_code == 409
    assert app.state.agent.invocations == 0


def test_concurrent_consumption_only_writes_once(flow):
    from concurrent.futures import ThreadPoolExecutor
    from fastapi import HTTPException
    from astraguard.schemas import TurnRequest
    client, app, _, body, check = flow
    approval = grant(client, check)
    request = TurnRequest.model_validate(body | {"approval_id": approval})
    principal = Principal(subject_id="operator", tenant_id="A", role="operator")
    def run(key):
        try:
            app.state.approvals.execute(request, principal, key, [])
            return 200
        except HTTPException as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(run, ["concurrent-one", "concurrent-two"])) == [200, 409]
    with app.state.store.connect() as db:
        assert db.execute("SELECT version FROM resources WHERE id='A2'").fetchone()[0] == 2
    assert app.state.agent.invocations == 1


def test_stats_scope_and_approval_not_double_counted(flow):
    client, _, _, body, check = flow
    assert client.get("/v1/stats").status_code == 403
    approval = grant(client, check)
    assert execute(client, body, approval).status_code == 200
    client.headers["Authorization"] = "Bearer " + "r" * 32
    response = client.get("/v1/stats")
    assert response.status_code == 200
    assert response.json()["sample_size"] == 1
    assert response.json()["decisions"] == {"ALLOW": 0, "REVIEW": 1, "BLOCK": 0}
    client.headers["Authorization"] = "Bearer " + "x" * 32
    stats = client.get("/v1/stats").json()
    assert stats["sample_size"] == 0
    assert stats["latency_ms"]["p95"] is None


def test_policy_change_during_approval_grant_is_atomic(flow, monkeypatch):
    client, app, _, _, check = flow
    from astraguard.policies import policy_etag
    original = app.state.approvals.describe
    def changing(check_id, reviewer):
        details = original(check_id, reviewer)
        policy = app.state.policies.snapshot()
        app.state.policies.replace(policy, policy_etag(policy),
                                   Principal(subject_id="admin", tenant_id="control", role="policy_admin"))
        return details
    monkeypatch.setattr(app.state.approvals, "describe", changing)
    client.headers["Authorization"] = "Bearer " + "r" * 32
    assert client.post(f'/v1/reviews/{check["id"]}/approve', json={}).status_code == 409
    with app.state.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
