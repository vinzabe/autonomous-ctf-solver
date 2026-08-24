"""A small deterministic solver agent, so the harness runs without an LLM.

It reads the files, tries the common encodings (base64/hex/rot13) on any long
token, and submits anything shaped like a flag. Phases are tracked with explicit
flags so the loop always makes forward progress — no re-enumeration. A real LLM
agent implements the same protocol.
"""
from __future__ import annotations

import dataclasses
import re

from .agent import Action
from .tools import ToolBox

_FLAG = re.compile(r"[A-Za-z0-9_]+\{[^}]+\}")
_TOKEN = re.compile(r"[A-Za-z0-9+/=]{8,}")


@dataclasses.dataclass(slots=True)
class HeuristicAgent:
    name: str = "heuristic"
    _enumerated: bool = False
    _to_read: list[str] = dataclasses.field(default_factory=list)
    _decodings: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    _gave_up: bool = False
    _tried: set[str] = dataclasses.field(default_factory=set)

    def act(self, _prompt: str, box: ToolBox,
            history: list[str]) -> Action:
        # 1. a NEW flag-shaped string surfaced in tool output? try it once.
        # Crucially, skip anything already submitted-and-rejected, or the agent
        # loops forever resubmitting flag-shaped CIPHERTEXT (e.g. "synt{...}")
        # that is not the real flag.
        for line in reversed(history):
            if "submit rejected" in line:
                continue
            m = _FLAG.search(line)
            if m and m.group(0) not in self._tried:
                self._tried.add(m.group(0))
                return Action("submit", m.group(0))

        # 2. enumerate the files exactly once.
        if not self._enumerated:
            self._enumerated = True
            res = box.list_files()
            self._to_read = [f for f in res.output.splitlines()
                             if f and f != "(no files)"]
            return Action("list_files")

        # 3. read each file once. QUEUE decodings first (so a flag-shaped but
        # ENCRYPTED string does not cause an early return that skips them), then
        # submit a direct, untried flag-shaped string if present.
        while self._to_read:
            name = self._to_read.pop(0)
            content = box.read_file(name).output
            for token in _TOKEN.findall(content):
                for tool in ("from_base64", "from_hex", "rot13"):
                    self._decodings.append((tool, token))
            # whole-content transforms for Caesar-style challenges
            self._decodings.append(("rot13", content.strip()))
            self._decodings.append(("from_base64", content.strip()))
            m = _FLAG.search(content)
            if m and m.group(0) not in self._tried:
                self._tried.add(m.group(0))
                return Action("submit", m.group(0))
            return Action("read_file", name)

        # 4. work through queued decodings, submitting the first decoded flag.
        while self._decodings:
            tool, token = self._decodings.pop(0)
            res = getattr(box, tool)(token)
            if res.ok:
                m = _FLAG.search(res.output)
                if m and m.group(0) not in self._tried:
                    self._tried.add(m.group(0))
                    return Action("submit", m.group(0))
                return Action(tool, token[:30])

        # 5. nothing worked within our capability — end cleanly.
        self._gave_up = True
        return Action("submit", "no-flag-found")
