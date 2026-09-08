"""In-process simulation. Production Q, P and reference monitor are separate services."""

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import Field

from ..policies.engine import Action, PolicyEngine
from .validator import Metadata, StrictModel, TypeDirectedValidator


class ToolCall(StrictModel):
    tool: str = Field(pattern=r"^artifact\.inspect$")
    handle: str = Field(pattern=r"^\$VAR_[0-9a-f]{32}$")


class Receipt(StrictModel):
    byte_count: int = Field(ge=0, le=65536)
    accepted: bool


@dataclass(frozen=True)
class Entry:
    value: bytes
    resource: int
    sink: str


class SymbolicMemory:
    def __init__(self):
        self.__entries: dict[str, Entry] = {}

    def put(self, raw: bytes, resource: int) -> str:
        if type(raw) is not bytes or len(raw) > 65536:
            raise ValueError("artifact too large")
        handle = "$VAR_" + secrets.token_hex(16)
        self.__entries[handle] = Entry(raw, resource, "artifact.inspect")
        return handle

    def resolve(self, handle: str, sink: str) -> Entry:
        entry = self.__entries.get(handle)
        if entry is None or entry.sink != sink:
            raise PermissionError("invalid handle")
        return entry

    def clear(self):
        self.__entries.clear()


class DualLLMOrchestrator:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def run(
        self,
        trusted_query: str,
        raw: bytes,
        resource: int,
        q_agent: Callable[[bytes], bytes],
        p_agent: Callable[[str, Metadata, str], ToolCall],
    ) -> Receipt:
        memory = SymbolicMemory()  # isolated per invocation; no cross-run handles
        try:
            handle = memory.put(raw, resource)  # resource assigned by trusted ingestion
            metadata = TypeDirectedValidator.validate(q_agent(raw))
            # A valid integer is not permission to choose another user's resource.
            if metadata.file_index != resource:
                raise PermissionError("resource mismatch")
            call = ToolCall.model_validate(p_agent(trusted_query, metadata, handle))
            entry = memory.resolve(call.handle, call.tool)
            action = Action(tool=call.tool, resource=entry.resource, size=len(entry.value))
            # Final sink consumes bytes as data, never as shell/SQL/template instructions.
            return self.policy.execute(
                action, lambda: Receipt(byte_count=len(entry.value), accepted=True)
            )
        finally:
            memory.clear()  # logical expiry, not guaranteed RAM erasure
