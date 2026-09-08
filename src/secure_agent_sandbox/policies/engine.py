"""Finite tool/resource vocabulary plus bounded integer scopes; no eval or regex DSL."""

import hashlib
import json
from collections.abc import Callable
from threading import RLock
from typing import Literal

import z3
from pydantic import Field

from ..agents.validator import StrictModel

Tool = Literal["artifact.inspect", "artifact.delete"]
TOOL_IDS = {"artifact.inspect": 0, "artifact.delete": 1}


class Rule(StrictModel):
    effect: Literal["allow", "forbid"]
    tool: Tool
    resources: tuple[int, ...] = Field(min_length=1, max_length=256)
    max_bytes: int = Field(ge=0, le=1_048_576)


class Policy(StrictModel):
    rules: tuple[Rule, ...] = Field(max_length=128)

    @classmethod
    def from_json(cls, payload: str):
        if len(payload) > 65536:
            raise ValueError("policy too large")
        from ..agents.validator import reject_duplicates

        data = json.loads(payload, object_pairs_hook=reject_duplicates)
        # JSON arrays have tuple semantics at this transport boundary only.
        if type(data) is not dict or set(data) != {"rules"} or type(data["rules"]) is not list:
            raise ValueError("invalid policy")
        rules = []
        for rule in data["rules"]:
            if type(rule) is not dict or type(rule.get("resources")) is not list:
                raise ValueError("invalid rule")
            rules.append(Rule.model_validate({**rule, "resources": tuple(rule["resources"])}))
        return cls(rules=tuple(rules))

    def digest(self):
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


class Action(StrictModel):
    tool: Tool
    resource: int = Field(ge=0, le=255)
    size: int = Field(ge=0, le=1_048_576)


def expression(policy, tool, resource, size):
    def match(rule):
        return z3.And(
            tool == TOOL_IDS[rule.tool],
            z3.Or(*[resource == r for r in rule.resources]),
            size >= 0,
            size <= rule.max_bytes,
        )

    return z3.And(
        z3.Or(*[match(r) for r in policy.rules if r.effect == "allow"]),
        z3.Not(z3.Or(*[match(r) for r in policy.rules if r.effect == "forbid"])),
    )


class HumanAuthorizationRequired(PermissionError):
    """No boolean approval bypass: external authority must create a new run."""


class PolicyEngine:
    def __init__(self, generic: Policy, task: Policy):
        self.__generic = generic
        self.__task = task
        self.__lock = RLock()

    @property
    def task_digest(self):
        with self.__lock:
            return self.__task.digest()

    def narrow(self, candidate: Policy):
        with self.__lock:
            t, r, n = z3.Ints("tool resource size")
            solver = z3.Solver()
            solver.set(timeout=1000)
            solver.add(t >= 0, t < len(TOOL_IDS), r >= 0, r <= 255, n >= 0, n <= 1_048_576)
            # Check task policy itself, not just its intersection with generic.
            solver.add(expression(candidate, t, r, n), z3.Not(expression(self.__task, t, r, n)))
            verdict = solver.check()
            if verdict != z3.unsat:
                raise HumanAuthorizationRequired("expansion or unproven update; new run required")
            self.__task = candidate

    def execute(self, action: Action, operation: Callable):
        """Authorize and dispatch under one lock: updates cannot race dispatch."""
        with self.__lock:
            allowed = z3.simplify(
                z3.And(
                    expression(self.__generic, TOOL_IDS[action.tool], action.resource, action.size),
                    expression(self.__task, TOOL_IDS[action.tool], action.resource, action.size),
                )
            )
            if not z3.is_true(allowed):
                raise PermissionError("action denied")
            return operation()
