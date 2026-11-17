from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Principal(StrictModel):
    subject_id: str
    tenant_id: str
    role: Literal["viewer", "operator", "security_reviewer"]


class CheckRequest(StrictModel):
    text: str = Field(min_length=1)
    session_id: UUID = Field(strict=False)
    policy_id: str


class TurnRequest(CheckRequest):
    approval_id: UUID | None = Field(default=None, strict=False)


Category = Literal[
    "direct_injection", "jailbreak", "system_extraction", "role_spoofing",
    "tool_misuse", "unauthorized_data", "privilege_escalation", "multi_turn", "obfuscation",
]
Reason = Literal[
    "BENIGN_REQUEST", "BENIGN_SECURITY_EDUCATION", "ACTIVE_OVERRIDE", "SYSTEM_EXTRACTION",
    "ROLE_SPOOFING", "TOOL_NOT_ALLOWED", "TENANT_BOUNDARY", "RESOURCE_NOT_FOUND_OR_HIDDEN",
    "ACTION_REQUIRES_APPROVAL", "UNTRUSTED_ROLE_CLAIM", "AMBIGUOUS_INTENT", "OBFUSCATION",
    "SESSION_ESCALATION", "CONTEXT_INCOMPLETE", "DETECTOR_UNAVAILABLE", "DETECTOR_TIMEOUT",
    "DETECTOR_INVALID_OUTPUT", "DETECTOR_CONTEXT_OVERFLOW", "JAILBREAK_ATTEMPT", "PRIVILEGE_ESCALATION",
]


class DetectorResult(StrictModel):
    schema_version: Literal["1"]
    intent: Literal["benign", "attack", "ambiguous"]
    categories: list[Category] = Field(max_length=5)
    severity: Literal["none", "low", "medium", "high", "critical"]
    reason_codes: list[Reason] = Field(min_length=1, max_length=5)
