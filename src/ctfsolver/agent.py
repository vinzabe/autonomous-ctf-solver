"""The solver loop with a hard budget.

An `Agent` is a callable given the challenge prompt and toolbox and asked for its
next action, until it submits a flag or the budget runs out. The bundled
`HeuristicAgent` is a small deterministic solver so the harness runs without an LLM;
a real LLM agent implements the same `Agent` protocol.
"""
from __future__ import annotations

import dataclasses
from typing import Protocol

from .challenge import Challenge
from .tools import ToolBox, ToolResult


@dataclasses.dataclass(frozen=True, slots=True)
class Action:
    kind: str                     # a tool name, or "submit"
    arg: str = ""
    arg2: str = ""


class Agent(Protocol):
    name: str
    def act(self, prompt: str, box: ToolBox, history: list[str]) -> Action: ...


@dataclasses.dataclass(frozen=True, slots=True)
class RunResult:
    challenge_id: str
    agent: str
    solved: bool
    steps_used: int
    step_budget: int
    points: int

    @property
    def efficiency(self) -> float:
        """Points per step used — separates 'solved efficiently' from
        'brute-forced at the budget limit'."""
        return self.points / self.steps_used if self.steps_used else 0.0


def _dispatch(box: ToolBox, action: Action) -> ToolResult:
    fn = getattr(box, action.kind, None)
    if fn is None:
        return ToolResult(False, f"no such tool: {action.kind}")
    if action.kind in ("read_file", "rot13", "from_hex", "from_base64"):
        return fn(action.arg)  # type: ignore[no-any-return]
    if action.kind == "grep":
        return fn(action.arg, action.arg2)  # type: ignore[no-any-return]
    return fn()  # type: ignore[no-any-return]


def solve(challenge: Challenge, agent: Agent, *, step_budget: int = 20
          ) -> RunResult:
    box = ToolBox(challenge)
    history: list[str] = []
    steps = 0
    while steps < step_budget:
        action = agent.act(challenge.prompt, box, history)
        steps += 1
        if action.kind == "submit":
            solved = challenge.submit(action.arg)
            if solved:
                # points scale down the longer it took, but never below 1 for a
                # genuine solve within budget
                pts = max(1, round(challenge.max_points * (1 - 0.4 * steps /
                                                           step_budget)))
                return RunResult(challenge.id, agent.name, True, steps,
                                 step_budget, pts)
            history.append(f"submit rejected: {action.arg[:40]}")
            continue
        result = _dispatch(box, action)
        history.append(f"{action.kind}({action.arg[:30]}) -> "
                       f"{result.output[:80]}")
    return RunResult(challenge.id, agent.name, False, steps, step_budget, 0)
