from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Principal(StrictModel):
    subject_id: str
    tenant_id: str
    role: Literal["viewer", "operator", "security_reviewer", "policy_admin"]


class CheckRequest(StrictModel):
    text: str = Field(min_length=1)
    session_id: UUID = Field(strict=False)
    policy_id: str


class TurnRequest(CheckRequest):
    approval_id: UUID | None = Field(default=None, strict=False)


class ReadArguments(StrictModel):
    document_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class WriteArguments(StrictModel):
    draft_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    content: str = Field(min_length=1, max_length=6000)


class ToolCheckRequest(StrictModel):
    session_id: UUID = Field(strict=False)
    parent_check_id: UUID = Field(strict=False)
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict

    @model_validator(mode="after")
    def typed_arguments(self):
        schema = {"documents.read": ReadArguments, "drafts.update": WriteArguments}.get(self.tool)
        if schema:
            self.arguments = schema.model_validate(self.arguments).model_dump()
        return self


class ContentCheckRequest(StrictModel):
    session_id: UUID = Field(strict=False)
    parent_check_id: UUID = Field(strict=False)
    source: Literal["tool_result", "retrieved_document"]
    text: str = Field(min_length=1, max_length=6000)


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
    "POLICY_CHANGED",
]


class DetectorResult(StrictModel):
    schema_version: Literal["1"]
    intent: Literal["benign", "attack", "ambiguous"]
    categories: list[Category] = Field(max_length=5)
    severity: Literal["none", "low", "medium", "high", "critical"]
    reason_codes: list[Reason] = Field(min_length=1, max_length=5)
