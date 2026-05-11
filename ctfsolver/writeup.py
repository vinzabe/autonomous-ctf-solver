"""Writeup generation: render an agent trace as Markdown."""
from __future__ import annotations
from typing import List

from .agent import AgentResult


def generate_writeup(result: AgentResult, *, max_obs_chars: int = 800) -> str:
    lines: List[str] = []
    lines.append(f"# Writeup: {result.challenge}")
    lines.append("")
    lines.append(f"- **Success**: {result.success}")
    lines.append(f"- **Steps taken**: {result.steps_taken}")
    lines.append(f"- **Elapsed**: {result.elapsed_sec:.2f}s")
    if result.flag:
        lines.append(f"- **Flag**: `{result.flag}`")
    lines.append(f"- **Final message**: {result.final_message}")
    lines.append("")
    lines.append("## Agent trace")
    lines.append("")
    for s in result.trace.steps:
        lines.append(f"### Step {s.step + 1}")
        if s.thought:
            lines.append(f"**Thought:** {s.thought}")
        if s.tool:
            args_str = ", ".join(f"{k}={v!r}" for k, v in (s.args or {}).items())
            lines.append(f"**Tool:** `{s.tool}({args_str})`")
        if s.error:
            lines.append(f"**Error:** {s.error}")
        if s.observation:
            obs = s.observation
            if len(obs) > max_obs_chars:
                obs = obs[:max_obs_chars] + f"\n[...truncated {len(s.observation)} chars]"
            lines.append("**Observation:**")
            lines.append("```")
            lines.append(obs)
            lines.append("```")
        if s.final_flag:
            lines.append(f"**Final flag:** `{s.final_flag}`")
        lines.append("")
    return "\n".join(lines)
