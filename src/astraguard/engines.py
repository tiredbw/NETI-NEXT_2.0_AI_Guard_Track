import base64
import binascii
import re
import unicodedata
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator
from yaml.tokens import AliasToken, AnchorToken

from .schemas import DetectorResult, StrictModel
from .detector import Detector, DetectorFailure, OllamaDetector


class RolePolicy(StrictModel):
    allowed_tools: list[Literal["documents.read", "drafts.update"]] = Field(max_length=2)
    resource_scope: Literal["own_tenant"]
    confirmation_actions: list[Literal["drafts.update"]] = Field(max_length=1)

    @model_validator(mode="after")
    def safe_permissions(self):
        if len(set(self.allowed_tools)) != len(self.allowed_tools):
            raise ValueError("Duplicate tools")
        if not set(self.confirmation_actions) <= set(self.allowed_tools):
            raise ValueError("Confirmation action must be allowed")
        if "drafts.update" in self.allowed_tools and "drafts.update" not in self.confirmation_actions:
            raise ValueError("Draft updates always require confirmation")
        return self


class Policy(StrictModel):
    id: Literal["strict-demo-v1"]
    version: int = Field(ge=1)
    roles: dict[Literal["viewer", "operator"], RolePolicy]

    @model_validator(mode="after")
    def role_limits(self):
        if "viewer" in self.roles and "drafts.update" in self.roles["viewer"].allowed_tools:
            raise ValueError("Viewer cannot write")
        return self


class PolicyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ValueError("YAML merges forbidden")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in keys:
                raise ValueError("Policy keys must be unique strings")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def load_policy(path: Path) -> Policy:
    with path.open("rb") as stream:
        content = stream.read(65537)
    raw = content.decode("utf-8")
    if len(raw.encode()) > 65536:
        raise ValueError("Policy too large")
    depth = 0
    for token in yaml.scan(raw):
        if isinstance(token, (AliasToken, AnchorToken)) or type(token).__name__ == "TagToken":
            raise ValueError("YAML aliases, anchors and tags forbidden")
        if type(token).__name__ in {"BlockMappingStartToken", "BlockSequenceStartToken", "FlowMappingStartToken", "FlowSequenceStartToken"}:
            depth += 1
            if depth > 8:
                raise ValueError("Policy nesting too deep")
        elif type(token).__name__ in {"BlockEndToken", "FlowMappingEndToken", "FlowSequenceEndToken"}:
            depth -= 1
    return Policy.model_validate(yaml.load(raw, Loader=PolicyLoader))


def authorize_tool(policy: Policy, role: str, tool: str, tenant: str, resource_tenant: str):
    if tenant != resource_tenant:
        return "BLOCK", "TENANT_BOUNDARY"
    permissions = policy.roles.get(role)
    if not permissions or tool not in permissions.allowed_tools:
        return "BLOCK", "TOOL_NOT_ALLOWED"
    if tool == "drafts.update" or tool in permissions.confirmation_actions:
        return "REVIEW", "ACTION_REQUIRES_APPROVAL"
    return "ALLOW", "BENIGN_REQUEST"


def rule_signal(text: str, *, decode=True):
    original = unicodedata.normalize("NFKC", text)
    original = "".join(c for c in original if unicodedata.category(c) != "Cf").strip()
    text = original.casefold()
    # Quoted/educational matches remain the semantic detector's responsibility.
    if any(c in text for c in ('"', '«', '»', '`', '\n')):
        return None
    wrapper = re.match(r"^(?:<(?:system|developer)>|\[(?:system|developer|admin)\])", text)
    privilege = re.search(r"име(?:ет|ю) право|разреш[её]н|администратор|authorized|override|игнорируй", text)
    action = re.search(r"прочитай|выдай|раскрой|\bread\b|\breveal\b|\bexecute\b", text)
    if wrapper and privilege and action:
        return "ROLE_SPOOFING"
    access_request = re.match(r"^(?:прочитай|выдай|открой|read|retrieve|export)\b", text)
    unverified_permission = re.search(
        r"(?:устно|якобы)\s+(?:разрешил|одобрил)|(?:нет|без)\s+(?:серверных\s+)?(?:прав|разрешения)|"
        r"verbal\s+(?:approval|permission)|without\s+(?:authorization|permission)", text)
    if access_request and unverified_permission:
        return "UNTRUSTED_ROLE_CLAIM"
    if decode and re.match(r"^(?:выполни|исполни|execute|follow)\b", text) and "base64" in text:
        budget = 4096
        for match in re.finditer(r"[A-Za-z0-9+/]{8,}={0,2}", original):
            token = match.group()
            if len(token) > budget * 4 // 3 + 4:
                break
            try:
                decoded = base64.b64decode(token, validate=True)
                if len(decoded) > budget:
                    break
                budget -= len(decoded)
                signal = rule_signal(decoded.decode("utf-8"), decode=False)
                if signal:
                    return signal
            except (binascii.Error, UnicodeDecodeError):
                pass
            if budget <= 0:
                break
    patterns = [
        (r"^(?:игнорируй|отмени) (?:все |предыдущие )?(?:правила|инструкции)", "ACTIVE_OVERRIDE"),
        (r"^ignore (?:all |the )?(?:previous )?instructions", "ACTIVE_OVERRIDE"),
        (r"^(?:выведи|раскрой|покажи).{0,60}(?:свой|текущий|скрытый).{0,40}(?:system prompt|системн|canary)", "SYSTEM_EXTRACTION"),
        (r"^(?:reveal|print|show) your (?:hidden |current )?(?:system prompt|system instructions)", "SYSTEM_EXTRACTION"),
    ]
    for pattern, code in patterns:
        if re.search(pattern, text):
            return code
    return None



def decide(rule, result: DetectorResult | None, failure: str | None):
    if rule and rule != "UNTRUSTED_ROLE_CLAIM":
        return "BLOCK", "critical" if rule == "SYSTEM_EXTRACTION" else "high", [rule]
    if failure or result is None:
        return "REVIEW", "unknown", ["DETECTOR_" + {
            "timeout": "TIMEOUT", "invalid_output": "INVALID_OUTPUT", "context_overflow": "CONTEXT_OVERFLOW",
            "quarantined": "QUARANTINED", "draining": "QUARANTINED", "model_changed": "MODEL_CHANGED",
        }.get(failure, "UNAVAILABLE")]
    if result.intent == "attack" and result.severity in ("high", "critical"):
        return "BLOCK", result.severity, result.reason_codes
    if rule == "UNTRUSTED_ROLE_CLAIM":
        return "REVIEW", "medium", ["UNTRUSTED_ROLE_CLAIM"]
    if result.intent != "benign" or result.categories or result.severity not in ("none", "low"):
        return "REVIEW", "medium", ["AMBIGUOUS_INTENT"]
    return "ALLOW", "low", ["BENIGN_REQUEST"]
