import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from pydantic import ValidationError

from .engines import Policy, load_policy


def policy_etag(policy):
    return '"' + hashlib.sha256(policy.model_dump_json().encode()).hexdigest() + '"'


class PolicyService:
    id = "strict-demo-v1"

    def __init__(self, store, seed_path):
        self.store = store
        existing = store.policy_config(self.id, allow_legacy=True)
        seed = Policy.model_validate_json(existing) if existing else load_policy(seed_path)
        store.seed_policy(seed)
        self.snapshot()

    def snapshot(self, db=None):
        raw = self.store.policy_config(self.id, db)
        if raw is None:
            raise HTTPException(503, "POLICY_UNAVAILABLE")
        try:
            return Policy.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(503, "POLICY_UNAVAILABLE") from None

    def replace(self, candidate, expected, principal):
        if principal.role != "policy_admin":
            raise HTTPException(403, "POLICY_ADMIN_REQUIRED")
        if expected is None:
            raise HTTPException(428, "IF_MATCH_REQUIRED")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self.snapshot(db)
            if expected != policy_etag(current) or candidate.version != current.version:
                raise HTTPException(412, "POLICY_VERSION_CONFLICT")
            updated = Policy.model_validate(candidate.model_dump() | {"version": current.version + 1})
            db.execute("INSERT INTO policies VALUES (?,?,?)", (updated.id, updated.version, updated.model_dump_json()))
            db.execute("INSERT INTO policy_metadata VALUES (?,?,?,?,?)", (updated.id, updated.version,
                       datetime.now(timezone.utc).isoformat(), principal.subject_id, policy_etag(updated).strip('"')))
            db.execute("UPDATE active_policies SET version=? WHERE id=?", (updated.version, updated.id))
            self.store.insert(db, principal, updated.model_dump_json(), {
                "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
                "event_type": "policy_update", "decision": "ALLOW", "risk": "low",
                "reason_codes": ["POLICY_UPDATED"], "policy_version": updated.version,
                "previous_version": current.version, "policy_ids": [updated.id],
            })
        return updated
