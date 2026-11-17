import json
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.concurrency import run_in_threadpool

from .engines import DetectorFailure, OllamaDetector, Policy, decide, load_policy, rule_signal
from .schemas import CheckRequest, Principal, StrictModel, TurnRequest
from .storage import AuditStore
from .demo import DemoAgent, plan
from .approvals import ApprovalService
import asyncio


def create_app(*, credentials=None, db_path=None, hmac_key=None, detector=None, policy_path=None):
    credentials = credentials if credentials is not None else {
        token: Principal.model_validate(value)
        for token, value in json.loads(os.environ.get("ASTRAGUARD_IDENTITIES", "{}")).items()
    }
    if not credentials or any(len(token) < 24 for token in credentials):
        raise ValueError("Configure ASTRAGUARD_IDENTITIES with random credentials (>=24 characters)")
    key = hmac_key or os.environ.get("ASTRAGUARD_HMAC_KEY", "").encode()
    if len(key) < 32:
        raise ValueError("Configure ASTRAGUARD_HMAC_KEY (>=32 bytes)")
    store = AuditStore(Path(db_path or os.environ.get("ASTRAGUARD_DB_PATH", "data/audit.sqlite3")), key)
    seed = load_policy(Path(policy_path or "policies/strict-demo.yaml"))
    policy = Policy.model_validate_json(store.seed_policy(seed))
    detector = detector or OllamaDetector()
    app = FastAPI(title="AstraGuard", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.store = store
    app.state.detector_status = "unavailable"
    agent = DemoAgent(store, policy)
    app.state.agent = agent
    approvals = ApprovalService(store, policy, agent)
    app.state.approvals = approvals
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def home():
        return FileResponse(static_dir / "index.html")

    @app.get("/docs", include_in_schema=False)
    def api_documentation():
        return FileResponse(static_dir / "api.html")
    sessions = {}
    histories = {}
    session_locks = {}
    requests = defaultdict(deque)

    @app.middleware("http")
    async def body_limit(request, call_next):
        request.state.request_id = str(uuid4())
        if request.method in ("POST", "PUT"):
            chunks, size = [], 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 65536:
                    return error(413, "INPUT_TOO_LARGE", request)
                chunks.append(chunk)
            if size and request.headers.get("content-type", "").split(";")[0] != "application/json":
                return error(415, "UNSUPPORTED_MEDIA_TYPE", request)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def error(status, code, request):
        return JSONResponse(status_code=status, content={"error": {
            "code": code, "message": code, "request_id": request.state.request_id}},
            headers={"Retry-After": "2"} if status == 429 else None)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        return error(exc.status_code, str(exc.detail), request)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        status = 400 if any(e["type"] == "json_invalid" for e in exc.errors()) else 422
        return error(status, "INVALID_REQUEST", request)

    @app.exception_handler(sqlite3.Error)
    async def db_error(request, exc):
        return error(503, "AUDIT_UNAVAILABLE", request)

    def identity(request: Request):
        authorization = request.headers.get("authorization", "")
        token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        principal = next((p for credential, p in credentials.items() if secrets.compare_digest(token, credential)), None)
        if principal is None:
            raise HTTPException(401, "UNAUTHORIZED")
        return principal

    @app.get("/health/live")
    def live():
        return {"status": "live"}

    @app.get("/health/ready")
    def ready():
        with store.connect() as db:
            db.execute("SELECT 1")
        ok = app.state.detector_status == "ok"
        return JSONResponse(status_code=200 if ok else 503, content={
            "status": "ready" if ok else "degraded", "database": "ok", "policy": "ok",
            "detector": app.state.detector_status})

    @app.get("/v1/me")
    def me(principal=Depends(identity)):
        return {"subject_id": principal.subject_id, "tenant_id": principal.tenant_id,
                "roles": [principal.role], "policy_ids": [policy.id]}

    @app.post("/v1/sessions", status_code=201)
    def session(principal=Depends(identity)):
        now = time.time()
        for sid in list(sessions):
            if sessions[sid][1] < now:
                del sessions[sid]
                histories.pop(sid, None)
                session_locks.pop(sid, None)
        if len(sessions) >= 1000:
            raise HTTPException(429, "SESSION_CAPACITY")
        sid = str(uuid4())
        sessions[sid] = (principal, now + 1800)
        histories[sid] = []
        session_locks[sid] = asyncio.Lock()
        return {"session_id": sid, "expires_at": datetime.fromtimestamp(now + 1800, timezone.utc).isoformat()}

    @app.get("/v1/policies")
    def policies(principal=Depends(identity)):
        return [{"id": policy.id, "version": policy.version}]

    @app.get("/v1/stats")
    def statistics(principal=Depends(identity)):
        if principal.role != "security_reviewer":
            raise HTTPException(403, "REVIEWER_REQUIRED")
        return store.statistics(principal)

    async def evaluate(body, principal, gate=None):
        started = time.monotonic()
        if len(body.text) > 6000:
            raise HTTPException(413, "INPUT_TOO_LARGE")
        if not body.text.strip():
            raise HTTPException(422, "EMPTY_TEXT")
        current = sessions.get(str(body.session_id))
        if not current or current[0] != principal or current[1] < time.time():
            raise HTTPException(404, "SESSION_NOT_FOUND")
        if body.policy_id != policy.id or principal.role not in policy.roles:
            raise HTTPException(403, "POLICY_NOT_ASSIGNED")
        bucket = requests[(principal.tenant_id, principal.subject_id)]
        while bucket and bucket[0] < started - 60:
            bucket.popleft()
        if len(bucket) >= 30:
            raise HTTPException(429, "RATE_LIMIT")
        bucket.append(started)
        rule = rule_signal(body.text)
        rule_ms = (time.monotonic() - started) * 1000
        result, failure = None, None
        status = "skipped_hard_deny"
        llm_started = time.monotonic()
        history = histories[str(body.session_id)]
        incomplete = len(history) >= 4 or sum(len(t) for t in history) + len(body.text) > 6000
        hard_policy = gate and gate[0] == "BLOCK"
        if incomplete and not rule and not hard_policy:
            status = "unavailable"
        if not rule and not hard_policy and not incomplete:
            try:
                context = json.dumps({"previous_allowed_turns": history, "current_text": body.text}, ensure_ascii=False) if history else body.text
                result = await detector.analyze(context)
                status = "ok"
            except DetectorFailure as exc:
                if exc.status == "overloaded":
                    raise HTTPException(429, "DETECTOR_CAPACITY") from None
                failure = status = exc.status
            app.state.detector_status = status
        decision, risk, reasons = decide(rule, result, failure)
        if hard_policy:
            decision, risk, reasons = "BLOCK", "high", [gate[1]]
        elif incomplete and not rule:
            decision, risk, reasons = "REVIEW", "unknown", ["CONTEXT_INCOMPLETE"]
        elif gate and gate[0] == "REVIEW" and decision == "ALLOW":
            decision, risk, reasons = "REVIEW", "medium", [gate[1]]
        categories = result.categories if result else (["system_extraction"] if rule == "SYSTEM_EXTRACTION" else ["direct_injection"] if rule else [])
        if hard_policy:
            categories = ["unauthorized_data" if gate[1] == "RESOURCE_NOT_FOUND_OR_HIDDEN" else "tool_misuse"]
        response = {
            "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
            "session_id": str(body.session_id),
            "decision": decision, "risk": risk,
            "threats": [{"category": c, "severity": risk, "source": "policy" if hard_policy else "rules" if rule else "llm", "rule_id": rule} for c in categories],
            "reason_codes": reasons,
            "explanation": {"ALLOW": "Обязательные проверки пройдены.", "BLOCK": "Обнаружена активная запрещённая инструкция.",
                            "REVIEW": "Запрос остановлен: требуется дополнительная проверка."}[decision],
            "policy_ids": [gate[1]] if gate and gate[0] != "ALLOW" else [], "policy_version": policy.version,
            "detector": {"status": status, "model": "qwen3.5:4b", "digest": None},
            "timing_ms": {"rules": rule_ms, "llm": (time.monotonic() - llm_started) * 1000,
                          "total": (time.monotonic() - started) * 1000},
            "review": {"approvable": False, "expires_at": None},
        }
        if gate and gate[0] != "ALLOW" and reasons == [gate[1]]:
            response["explanation"] = {
                "RESOURCE_NOT_FOUND_OR_HIDDEN": "Ресурс недоступен в рамках ваших полномочий.",
                "TOOL_NOT_ALLOWED": "Этот инструмент или действие не разрешены вашей роли.",
                "ACTION_REQUIRES_APPROVAL": "Действие остановлено: требуется подтверждение отдельного reviewer.",
            }[gate[1]]
        if decision == "REVIEW" and reasons == ["ACTION_REQUIRES_APPROVAL"] and status == "ok":
            response["review"] = {"approvable": True, "expires_at": datetime.fromtimestamp(time.time() + 120, timezone.utc).isoformat()}
        await run_in_threadpool(store.save, principal, body.text, response)
        return response

    @app.post("/v1/checks", status_code=201)
    async def check(body: CheckRequest, principal=Depends(identity)):
        return await evaluate(body, principal)

    @app.post("/v1/agent/turns")
    async def turn(body: TurnRequest, request: Request, principal=Depends(identity)):
        sid = str(body.session_id)
        current = sessions.get(sid)
        if not current or current[0] != principal or current[1] < time.time():
            raise HTTPException(404, "SESSION_NOT_FOUND")
        lock = session_locks[sid]
        if lock.locked():
            raise HTTPException(409, "SESSION_BUSY")
        async with lock:
            if body.approval_id is not None:
                if body.policy_id != policy.id or principal.role not in policy.roles:
                    raise HTTPException(403, "POLICY_NOT_ASSIGNED")
                result = await run_in_threadpool(approvals.execute, body, principal,
                                                request.headers.get("Idempotency-Key"), histories[sid])
                if not result["execution"]["replayed"]:
                    histories[sid].append(body.text)
                return result
            intent = plan(body.text)
            gate = await run_in_threadpool(agent.preflight, principal, intent)
            result = await evaluate(body, principal, gate)
            if result["review"]["approvable"]:
                await run_in_threadpool(approvals.remember, body, principal, result, histories[sid])
            execution = {"status": "not_forwarded", "forwarded": False, "agent_invocation_id": None,
                         "target_invocations": 0, "result": None}
            if result["decision"] == "ALLOW":
                execution = await run_in_threadpool(agent.invoke, principal, intent, result)
                if execution["status"] == "completed":
                    histories[sid].append(body.text)
            return {"check": result, "execution": execution}

    @app.post("/v1/reviews/{check_id}/approve", status_code=201)
    def approve(check_id: str, body: StrictModel, principal=Depends(identity)):
        return approvals.approve(check_id, principal)

    @app.get("/v1/reviews/{check_id}")
    def review_details(check_id: str, principal=Depends(identity)):
        return approvals.describe(check_id, principal)

    @app.get("/v1/checks")
    def history(limit: int = Query(20, ge=1, le=100), principal=Depends(identity)):
        return {"items": store.list(principal, limit), "next_cursor": None}

    @app.get("/v1/checks/{event_id}")
    def event(event_id: str, principal=Depends(identity)):
        result = store.get(principal, event_id)
        if result is None:
            raise HTTPException(404, "CHECK_NOT_FOUND")
        return result

    return app
