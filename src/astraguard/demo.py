import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from .engines import authorize_tool


@dataclass(frozen=True)
class ToolIntent:
    tool: str
    resource_id: str
    content: str | None = None


def plan(text: str) -> ToolIntent | None:
    match = re.fullmatch(r"/read ([A-Za-z0-9_-]{1,64})", text.strip())
    if match:
        return ToolIntent("documents.read", match[1])
    match = re.fullmatch(r"/write ([A-Za-z0-9_-]{1,64}) (.+)", text.strip(), re.DOTALL)
    if match:
        return ToolIntent("drafts.update", match[1], match[2])
    if text.lstrip().startswith("/"):
        return ToolIntent("unknown", "")
    return None


def tool_policy(db, policy, principal, intent):
    if intent.tool not in ("documents.read", "drafts.update"):
        return "BLOCK", "TOOL_NOT_ALLOWED"
    row = db.execute("SELECT tenant, kind FROM resources WHERE id=?", (intent.resource_id,)).fetchone()
    if not row or row[0] != principal.tenant_id:
        return "BLOCK", "RESOURCE_NOT_FOUND_OR_HIDDEN"
    if row[1] != ("document" if intent.tool == "documents.read" else "draft"):
        return "BLOCK", "TOOL_NOT_ALLOWED"
    return authorize_tool(policy, principal.role, intent.tool, principal.tenant_id, row[0])


class DemoAgent:
    def __init__(self, store, policy):
        self.store, self.policy = store, policy
        self.invocations = 0

    def preflight(self, principal, intent):
        if intent is None:
            return None
        with self.store.connect() as db:
            return tool_policy(db, self.policy, principal, intent)

    def invoke(self, principal, intent, parent):
        invocation_id = str(uuid4())
        child = {
            "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
            "parent_id": parent["id"], "session_id": parent["session_id"],
            "policy_version": self.policy.version, "policy_ids": [],
            "detector": {"status": "skipped_hard_deny", "model": None, "digest": None},
            "threats": [], "timing_ms": {},
        }
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            decision, reason = tool_policy(db, self.policy, principal, intent) if intent else ("ALLOW", "BENIGN_REQUEST")
            child.update(decision=decision, risk="low" if decision == "ALLOW" else "high",
                         reason_codes=[reason], event_type="tool_execution" if intent else "agent_execution",
                         agent_invocation_id=invocation_id,
                         explanation="Проверка допуска перед исполнением демонстрационного действия.")
            if decision != "ALLOW":
                child["policy_ids"] = [reason]
            self.store.insert(db, principal, intent.resource_id if intent else "demo_reply", child)
            content = None
            if decision == "ALLOW" and intent:
                content = db.execute("SELECT content FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0]
        self.invocations += 1
        return {
            "status": "completed" if decision == "ALLOW" else "failed", "forwarded": True,
            "agent_invocation_id": invocation_id, "target_invocations": 1,
            "tool_check": child if intent else None,
            "result": ({"adapter": "deterministic-demo", "content": content if intent else
                        "Демонстрационный агент получил разрешённый запрос. Это синтетический ответ, не генерация LLM."}
                       if decision == "ALLOW" else None),
        }
