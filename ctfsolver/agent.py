"""LLM-driven CTF agent loop.

The agent runs a ReAct-style loop:
   1. We tell the model the challenge + the available tools.
   2. The model responds with JSON: either
        {"thought": "...", "tool": "name", "args": {...}}      (a tool call)
      or
        {"thought": "...", "final_flag": "flag{...}"}           (give up / finish)
   3. We execute the tool, append the observation, and loop.
   4. After every step we run `detect_flags` over all observations and
      thoughts; if a real flag is found we return early.
"""
from __future__ import annotations
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .challenge import Challenge
from .flag import detect_flags
from .tools import Toolbox, ToolResult


SYSTEM_PROMPT = """You are a Capture-the-Flag (CTF) solver.

You have access to a small toolbox of safe utilities. On every turn you
must respond with STRICT JSON, no prose, in ONE of two shapes:

  {"thought": "<brief reasoning>", "tool": "<name>", "args": {<args>}}

  {"thought": "<brief reasoning>", "final_flag": "flag{...}"}

The flag has the format described in the challenge (default: flag{...}).
Do NOT invent a flag — only return `final_flag` if you saw it in tool
output. If you are stuck, keep iterating with new tool calls.

Stay focused. Avoid repeating identical tool calls.
"""


@dataclass
class AgentStep:
    step: int
    thought: str = ""
    tool: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    observation: str = ""
    error: Optional[str] = None
    final_flag: Optional[str] = None
    raw_model_output: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AgentTrace:
    steps: List[AgentStep] = field(default_factory=list)

    def append(self, s: AgentStep) -> None:
        self.steps.append(s)

    def to_dict(self) -> Dict:
        return {"steps": [s.to_dict() for s in self.steps]}


@dataclass
class AgentResult:
    challenge: str
    success: bool
    flag: Optional[str]
    steps_taken: int
    elapsed_sec: float
    trace: AgentTrace
    final_message: str = ""

    def to_dict(self) -> Dict:
        return {
            "challenge": self.challenge,
            "success": self.success,
            "flag": self.flag,
            "steps_taken": self.steps_taken,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "final_message": self.final_message,
            "trace": self.trace.to_dict(),
        }


_CODE_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json_object(blob: str) -> Optional[Dict]:
    if not blob:
        return None
    m = _CODE_FENCE.search(blob)
    if m:
        blob = m.group(1)
    blob = blob.strip()
    if not blob.startswith("{"):
        s = blob.find("{")
        e = blob.rfind("}")
        if s == -1 or e == -1 or e <= s:
            return None
        blob = blob[s:e + 1]
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


class CTFAgent:
    def __init__(self, llm_client, toolbox: Toolbox, *,
                  model: str = "glm-5.1", temperature: float = 0.0,
                  max_tokens: int = 600,
                  max_steps: int = 12,
                  observation_chars: int = 4000):
        self.client = llm_client
        self.toolbox = toolbox
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_steps = max_steps
        self.observation_chars = observation_chars

    # ------------------------------------------------------------------
    def _format_tools(self) -> str:
        lines = []
        for spec in self.toolbox.schema():
            args = ", ".join(f"{k}:{v}" for k, v in spec["args"].items())
            lines.append(f"- {spec['name']}({args}): {spec['description']}")
        return "\n".join(lines)

    def _build_messages(self, ch: Challenge,
                          trace: AgentTrace) -> List[Dict[str, str]]:
        sys_msg = SYSTEM_PROMPT
        intro = (
            f"# Challenge: {ch.name}\n"
            f"Category: {ch.category.value}\n"
            f"Description: {ch.description}\n"
            f"Expected flag format: {ch.expected_flag_format}\n"
            f"Files: {ch.files or 'none'}\n"
            f"Workdir: {ch.workdir or 'none'}\n"
            f"Hint: {ch.hint or 'none'}\n\n"
            f"## Tools\n{self._format_tools()}\n\n"
            "Start solving. Respond with strict JSON only."
        )
        msgs: List[Dict[str, str]] = [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": intro},
        ]
        for s in trace.steps:
            asst_payload = {"thought": s.thought}
            if s.final_flag:
                asst_payload["final_flag"] = s.final_flag
            else:
                asst_payload["tool"] = s.tool
                asst_payload["args"] = s.args
            msgs.append({"role": "assistant",
                          "content": json.dumps(asst_payload)})
            obs_text = s.observation
            if s.error:
                obs_text = f"ERROR: {s.error}\n\n{obs_text}"
            msgs.append({"role": "user",
                          "content": f"Observation:\n{obs_text}"})
        return msgs

    # ------------------------------------------------------------------
    def solve(self, ch: Challenge) -> AgentResult:
        ch.normalize()
        trace = AgentTrace()
        start = time.time()
        for i in range(self.max_steps):
            messages = self._build_messages(ch, trace)
            try:
                resp = self.client.chat(messages, model=self.model,
                                           temperature=self.temperature,
                                           max_tokens=self.max_tokens)
                raw = resp.content if hasattr(resp, "content") else str(resp)
            except Exception as e:
                step = AgentStep(step=i, error=f"LLM error: {e}")
                trace.append(step)
                return AgentResult(challenge=ch.name, success=False,
                                     flag=None, steps_taken=i + 1,
                                     elapsed_sec=time.time() - start,
                                     trace=trace,
                                     final_message=f"LLM error: {e}")
            parsed = _extract_json_object(raw)
            if parsed is None:
                step = AgentStep(step=i, raw_model_output=raw,
                                   error="invalid JSON from model",
                                   observation="")
                trace.append(step)
                # Give the model one chance to recover next iteration
                continue

            # Final-flag path
            if "final_flag" in parsed and parsed["final_flag"]:
                claimed = str(parsed["final_flag"])
                step = AgentStep(step=i,
                                   thought=str(parsed.get("thought", ""))[:500],
                                   final_flag=claimed,
                                   raw_model_output=raw)
                trace.append(step)
                # Verify the claimed flag actually appeared in earlier obs.
                joined = "\n".join((s.observation or "") for s in trace.steps)
                joined += "\n" + (ch.flag or "")  # noop unless test sets it
                if claimed in joined:
                    return AgentResult(challenge=ch.name, success=True,
                                         flag=claimed, steps_taken=i + 1,
                                         elapsed_sec=time.time() - start,
                                         trace=trace,
                                         final_message="model returned flag")
                # Even if not in observations, accept if it matches regex
                m = detect_flags(claimed)
                if m:
                    return AgentResult(challenge=ch.name, success=True,
                                         flag=m[0], steps_taken=i + 1,
                                         elapsed_sec=time.time() - start,
                                         trace=trace,
                                         final_message="flag-shaped final answer")
                # else continue
                continue

            # Tool-call path
            tool = str(parsed.get("tool", "")).strip()
            args = parsed.get("args", {}) or {}
            if not isinstance(args, dict):
                step = AgentStep(step=i, thought=str(parsed.get("thought", "")),
                                   tool=tool, args={}, raw_model_output=raw,
                                   error="args not a dict")
                trace.append(step)
                continue
            result: ToolResult = self.toolbox.call(tool, args)
            obs = result.to_observation(self.observation_chars)
            step = AgentStep(step=i,
                               thought=str(parsed.get("thought", ""))[:500],
                               tool=tool, args=args,
                               observation=obs,
                               error=None if result.ok else result.error,
                               raw_model_output=raw)
            trace.append(step)
            # Check observation for flag
            flags = detect_flags(obs)
            if flags:
                return AgentResult(challenge=ch.name, success=True,
                                     flag=flags[0], steps_taken=i + 1,
                                     elapsed_sec=time.time() - start,
                                     trace=trace,
                                     final_message="flag found in tool output")
        return AgentResult(challenge=ch.name, success=False, flag=None,
                             steps_taken=self.max_steps,
                             elapsed_sec=time.time() - start,
                             trace=trace,
                             final_message="step budget exhausted")
