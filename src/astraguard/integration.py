import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

from .demo import ToolIntent, tool_policy
from .engines import DetectorFailure, decide, rule_signal


class IntegrationChecks:
    def __init__(self, store, policies, detector):
        self.store, self.policies, self.detector = store, policies, detector

    def inspect(self, db, principal, body, expires):
        if expires < time.time():
            raise HTTPException(404, "SESSION_NOT_FOUND")
        # Reviewers may inspect tenant audits, but cannot act as another event's owner.
        row = db.execute("SELECT result FROM events WHERE id=? AND tenant=? AND subject=?",
                         (str(body.parent_check_id), principal.tenant_id, principal.subject_id)).fetchone()
        if not row:
            raise HTTPException(404, "PARENT_CHECK_NOT_FOUND")
        parent = json.loads(row[0])
        if (parent.get("session_id") != str(body.session_id)
                or parent.get("event_type", "request_check") != "request_check"
                or parent.get("approved_check_id") or parent.get("decision") != "ALLOW"):
            raise HTTPException(409, "PARENT_CHECK_NOT_ALLOWED")
        policy = self.policies.snapshot(db)
        if principal.role not in policy.roles:
            raise HTTPException(403, "POLICY_NOT_ASSIGNED")
        if hasattr(body, "tool"):
            args = body.arguments
            intent = ToolIntent(body.tool, args.get("document_id", args.get("draft_id", "")), args.get("content"))
            gate = tool_policy(db, policy, principal, intent)
            if gate[0] == "BLOCK":
                return policy, gate
            if parent.get("policy_version") != policy.version:
                return policy, ("REVIEW", "POLICY_CHANGED")
            return policy, gate
        if parent.get("policy_version") != policy.version:
            return policy, ("REVIEW", "POLICY_CHANGED")
        return policy, ("ALLOW", "BENIGN_REQUEST")

    def snapshot(self, principal, body, expires):
        with self.store.connect() as db:
            return self.inspect(db, principal, body, expires)

    async def check(self, principal, body, expires):
        started = time.monotonic()
        policy, gate = await run_in_threadpool(self.snapshot, principal, body, expires)
        is_tool = hasattr(body, "tool")
        text = body.arguments.get("content") if is_tool else body.text
        signal, result, failure = None, None, None
        status = "skipped_deterministic"
        if gate[0] == "BLOCK":
            status = "skipped_hard_deny"
        elif gate[1] != "POLICY_CHANGED" and text is not None:
            if not text.strip():
                raise HTTPException(422, "EMPTY_TEXT")
            signal = rule_signal(text)
            if signal and signal != "UNTRUSTED_ROLE_CLAIM":
                status = "skipped_hard_deny"
            else:
                try:
                    # Provenance is an untrusted data label, never a message role.
                    result = await self.detector.analyze(json.dumps({
                        "untrusted_source": "tool_arguments" if is_tool else body.source,
                        "current_text": text}, ensure_ascii=False))
                    status = "ok"
                except DetectorFailure as exc:
                    if exc.status == "overloaded":
                        raise HTTPException(429, "DETECTOR_CAPACITY") from None
                    failure = status = exc.status
        decision, risk, reasons = decide(signal, result, failure) if text is not None else ("ALLOW", "low", ["BENIGN_REQUEST"])
        if gate[0] == "BLOCK":
            decision, risk, reasons = "BLOCK", "high", [gate[1]]
        elif gate[0] == "REVIEW" and (decision == "ALLOW" or gate[1] == "POLICY_CHANGED"):
            decision, risk, reasons = "REVIEW", "medium", [gate[1]]
        event = {
            "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
            "session_id": str(body.session_id), "parent_id": str(body.parent_check_id),
            "event_type": "tool_check" if is_tool else "content_check",
            "decision": decision, "risk": risk, "reason_codes": reasons,
            "policy_ids": [], "policy_version": policy.version,
            "threats": [{"category": category, "severity": risk, "source": "llm", "rule_id": None}
                        for category in (result.categories if result else [])],
            "detector": {"status": status, "model": "qwen3.5:4b" if text is not None else None,
                         "digest": getattr(self.detector, "digest", None) if text is not None else None},
            "review": {"approvable": False, "expires_at": None},
            "forwarded": False,
        }
        if is_tool:
            event["tool"] = body.tool if body.tool in ("documents.read", "drafts.update") else "unknown"
        else:
            event["source"] = body.source
        if signal:
            category = {"SYSTEM_EXTRACTION": "system_extraction", "ROLE_SPOOFING": "role_spoofing",
                        "UNTRUSTED_ROLE_CLAIM": "unauthorized_data"}.get(signal, "direct_injection")
            event["threats"].append({"category": category, "severity": risk, "source": "rules", "rule_id": signal})
        return await run_in_threadpool(self.persist, principal, body, expires, event, started)

    def persist(self, principal, body, expires, event, started):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            policy, gate = self.inspect(db, principal, body, expires)
            if gate[0] == "BLOCK":
                event.update(decision="BLOCK", risk="high", reason_codes=[gate[1]])
            elif event["decision"] != "BLOCK" and (gate[1] == "POLICY_CHANGED" or policy.version != event["policy_version"]):
                event.update(decision="REVIEW", risk="unknown", reason_codes=["POLICY_CHANGED"])
            if gate[0] == "BLOCK":
                category = "unauthorized_data" if gate[1] == "RESOURCE_NOT_FOUND_OR_HIDDEN" else "tool_misuse"
                event["threats"] = [{"category": category, "severity": "high", "source": "policy", "rule_id": gate[1]}]
            event["policy_version"] = policy.version
            event["policy_ids"] = [code for code in event["reason_codes"] if code in (
                "POLICY_CHANGED", "TOOL_NOT_ALLOWED", "RESOURCE_NOT_FOUND_OR_HIDDEN", "ACTION_REQUIRES_APPROVAL")]
            event["explanation"] = {
                "ALLOW": "Проверка пройдена. Это оценка, исполнение не выполнялось.",
                "REVIEW": "Передача остановлена: требуется новая проверка или отдельный протокол подтверждения.",
                "BLOCK": "Передача запрещена: обнаружена опасная инструкция или нарушена политика доступа.",
            }[event["decision"]]
            event["timing_ms"] = {"total": (time.monotonic() - started) * 1000}
            self.store.insert(db, principal, body.model_dump_json(), event)
        return event
