import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException

from .demo import plan, tool_policy


class ApprovalService:
    def __init__(self, store, policy, agent):
        self.store, self.policy, self.agent = store, policy, agent
        self.pending = {}

    def binding(self, body):
        raw = json.dumps({"text": body.text, "session_id": str(body.session_id), "policy_id": body.policy_id},
                         sort_keys=True, ensure_ascii=False)
        return hmac.new(self.store.key, raw.encode(), hashlib.sha256).hexdigest()

    def policy_hash(self):
        return hashlib.sha256(self.policy.model_dump_json().encode()).hexdigest()

    def remember(self, body, principal, check, history):
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v["expires"] > now}
        if len(self.pending) >= 1000:
            raise HTTPException(429, "PENDING_CAPACITY")
        intent = plan(body.text)
        with self.store.connect() as db:
            if tool_policy(db, self.policy, principal, intent)[0] != "REVIEW":
                raise HTTPException(409, "RESOURCE_CHANGED")
            version = db.execute("SELECT version FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0]
        self.pending[check["id"]] = {"body": body, "principal": principal, "check": check,
                                      "version": version, "hash": self.policy_hash(), "expires": now + 120,
                                      "history": list(history)}

    def approve(self, check_id, reviewer):
        self.describe(check_id, reviewer)
        pending = self.pending[check_id]
        approval_id = str(uuid4())
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM approvals WHERE check_id=?", (check_id,)).fetchone():
                raise HTTPException(409, "ALREADY_APPROVED")
            db.execute("INSERT INTO approvals(id,check_id,tenant,requester,reviewer,binding,policy_hash,resource_version,expires) VALUES (?,?,?,?,?,?,?,?,?)",
                       (approval_id, check_id, reviewer.tenant_id, pending["principal"].subject_id, reviewer.subject_id,
                        self.binding(pending["body"]), pending["hash"], pending["version"], pending["expires"]))
            self.store.insert(db, reviewer, check_id, {"id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
                "event_type": "approval_granted", "parent_id": check_id, "decision": "REVIEW", "risk": "medium",
                "reason_codes": ["ACTION_REQUIRES_APPROVAL"], "policy_version": self.policy.version})
        return {"approval_id": approval_id, "expires_at": datetime.fromtimestamp(pending["expires"], timezone.utc).isoformat()}

    def describe(self, check_id, reviewer):
        if reviewer.role != "security_reviewer":
            raise HTTPException(403, "REVIEWER_REQUIRED")
        pending = self.pending.get(check_id)
        if not pending or pending["principal"].tenant_id != reviewer.tenant_id:
            raise HTTPException(404, "REVIEW_NOT_FOUND")
        if pending["principal"].subject_id == reviewer.subject_id:
            raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")
        if pending["expires"] <= time.time() or pending["hash"] != self.policy_hash():
            raise HTTPException(409, "REVIEW_EXPIRED_OR_CHANGED")
        intent = plan(pending["body"].text)
        return {"check_id": check_id, "requester_id": pending["principal"].subject_id,
                "tool": intent.tool, "resource_id": intent.resource_id, "resource_version": pending["version"],
                "content_length": len(intent.content), "binding_hmac": self.binding(pending["body"]),
                "expires_at": datetime.fromtimestamp(pending["expires"], timezone.utc).isoformat()}

    def execute(self, body, principal, key, history):
        if not key or not 8 <= len(key) <= 128:
            raise HTTPException(400, "IDEMPOTENCY_KEY_REQUIRED")
        binding = self.binding(body)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM executions WHERE expires < ?", (time.time(),))
            cached = db.execute("SELECT binding,result FROM executions WHERE tenant=? AND requester=? AND key=?",
                                (principal.tenant_id, principal.subject_id, key)).fetchone()
            if cached:
                if not hmac.compare_digest(cached[0], binding + str(body.approval_id)):
                    raise HTTPException(409, "IDEMPOTENCY_CONFLICT")
                result = json.loads(cached[1])
                result["execution"]["replayed"] = True
                return result
            row = db.execute("SELECT check_id,tenant,requester,binding,policy_hash,resource_version,expires,consumed FROM approvals WHERE id=?",
                             (str(body.approval_id),)).fetchone()
            if not row or row[1:3] != (principal.tenant_id, principal.subject_id):
                raise HTTPException(409, "APPROVAL_UNAVAILABLE")
            check_id, _, _, expected, policy_hash, version, expires, consumed = row
            pending = self.pending.get(check_id)
            if consumed or expires <= time.time() or not pending:
                raise HTTPException(409, "APPROVAL_EXPIRED_OR_USED")
            if pending["history"] != history:
                raise HTTPException(409, "SESSION_CONTEXT_CHANGED")
            if not hmac.compare_digest(expected, binding) or policy_hash != self.policy_hash():
                raise HTTPException(409, "APPROVAL_MISMATCH")
            intent = plan(body.text)
            if intent is None or intent.tool != "drafts.update" or tool_policy(db, self.policy, principal, intent) != ("REVIEW", "ACTION_REQUIRES_APPROVAL"):
                raise HTTPException(409, "ACTION_NO_LONGER_PERMITTED")
            current = db.execute("SELECT version FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0]
            if current != version:
                raise HTTPException(409, "RESOURCE_CHANGED")
            check = dict(pending["check"])
            check.update(id=str(uuid4()), created_at=datetime.now(timezone.utc).isoformat(), decision="ALLOW", risk="low",
                         reason_codes=["BENIGN_REQUEST"], explanation="Действие подтверждено отдельным reviewer и повторно авторизовано.",
                         approved_check_id=check_id, policy_ids=[], review={"approvable": False, "expires_at": None})
            self.store.insert(db, principal, body.text, check)
            db.execute("UPDATE resources SET content=?,version=version+1 WHERE id=?", (intent.content, intent.resource_id))
            db.execute("UPDATE approvals SET consumed=1 WHERE id=?", (str(body.approval_id),))
            execution = {"status": "completed", "forwarded": True, "agent_invocation_id": str(uuid4()),
                         "target_invocations": 1, "replayed": False,
                         "result": {"adapter": "deterministic-demo", "updated": True}}
            result = {"check": check, "execution": execution}
            db.execute("INSERT INTO executions VALUES (?,?,?,?,?,?)", (principal.tenant_id, principal.subject_id, key,
                       binding + str(body.approval_id), json.dumps(result), time.time() + 86400))
        self.agent.invocations += 1
        return result
