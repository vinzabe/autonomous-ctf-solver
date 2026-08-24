"""The agent's tool surface — explicit, scoped, and unable to reach the flag.

Tools operate only on the challenge's declared files and a scoped scratch space.
There is deliberately no tool that reads the challenge object's salt or flag_hash,
and no tool that reaches the host filesystem. Every call is budget-charged.
"""
from __future__ import annotations

import dataclasses
import re

from .challenge import Challenge


@dataclasses.dataclass(frozen=True, slots=True)
class ToolResult:
    ok: bool
    output: str


@dataclasses.dataclass(slots=True)
class ToolBox:
    """Bounds what an agent can do. Files are read-only; there is no path from a
    tool to the scorer's secret."""
    challenge: Challenge

    def _files(self) -> dict[str, str]:
        return dict(self.challenge.files)

    def list_files(self) -> ToolResult:
        return ToolResult(True, "\n".join(sorted(self._files())) or "(no files)")

    def read_file(self, name: str) -> ToolResult:
        files = self._files()
        if name not in files:
            return ToolResult(False, f"no such file: {name}")
        return ToolResult(True, files[name])

    def grep(self, pattern: str, name: str) -> ToolResult:
        files = self._files()
        if name not in files:
            return ToolResult(False, f"no such file: {name}")
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return ToolResult(False, f"bad pattern: {e}")
        hits = [ln for ln in files[name].splitlines() if rx.search(ln)]
        return ToolResult(True, "\n".join(hits) or "(no matches)")

    def rot13(self, text: str) -> ToolResult:
        import codecs
        return ToolResult(True, codecs.encode(text, "rot13"))

    def from_hex(self, text: str) -> ToolResult:
        try:
            return ToolResult(True, bytes.fromhex(text.strip()).decode(
                "utf-8", "replace"))
        except ValueError as e:
            return ToolResult(False, str(e))

    def from_base64(self, text: str) -> ToolResult:
        import base64
        import binascii
        try:
            return ToolResult(True, base64.b64decode(text).decode(
                "utf-8", "replace"))
        except (binascii.Error, ValueError) as e:
            return ToolResult(False, str(e))


# The tool names an agent may call, so a policy can restrict the surface further.
TOOL_NAMES = ("list_files", "read_file", "grep", "rot13", "from_hex",
              "from_base64")
