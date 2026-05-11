"""Toolbox for the CTF agent.

Each tool is a Python function exposed via the `Toolbox` registry. Tools
are defensive by default:

  - `shell_run` only allows a small whitelist of harmless utilities
    (strings/file/xxd/base64/cat/grep/python3/echo/ls/head/tail/wc).
  - `file_read` is sandboxed to the challenge `workdir` (resolved via
    `os.path.realpath` to defeat ../traversal).
  - `http_get` is only enabled when `allow_network=True` AND the host is on
    the explicit whitelist.

This makes it safe to run inside CI / unit tests without external mocks.
"""
from __future__ import annotations
import base64
import dataclasses
import os
import shlex
import subprocess
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass
class ToolResult:
    ok: bool
    output: str
    error: str = ""
    truncated: bool = False

    def to_observation(self, max_chars: int = 4000) -> str:
        body = self.output if self.ok else f"ERROR: {self.error}"
        if len(body) > max_chars:
            return body[:max_chars] + f"\n[...truncated, {len(body)} chars]"
        return body


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
SHELL_WHITELIST = {
    "strings", "file", "xxd", "base64", "cat", "grep", "head", "tail",
    "wc", "ls", "echo", "python3", "od", "tr", "sort", "uniq", "find",
    "stat", "sha1sum", "sha256sum", "md5sum",
}

DEFAULT_HTTP_WHITELIST = {"localhost", "127.0.0.1"}


def _safe_resolve(path: str, sandbox: Optional[str]) -> str:
    """Resolve `path` under `sandbox`. Raises ValueError if outside."""
    abspath = os.path.realpath(path)
    if sandbox is not None:
        sandbox_abs = os.path.realpath(sandbox)
        if not (abspath == sandbox_abs or
                abspath.startswith(sandbox_abs + os.sep)):
            raise ValueError(f"path {path!r} outside sandbox {sandbox!r}")
    return abspath


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def _tool_shell_run(cmd: str, *, sandbox: Optional[str] = None,
                     timeout: float = 8.0) -> ToolResult:
    if not cmd or not cmd.strip():
        return ToolResult(False, "", "empty command")
    try:
        argv = shlex.split(cmd)
    except ValueError as e:
        return ToolResult(False, "", f"parse error: {e}")
    if not argv:
        return ToolResult(False, "", "empty argv")
    prog = os.path.basename(argv[0])
    if prog not in SHELL_WHITELIST:
        return ToolResult(False, "",
                            f"command {prog!r} not allowed; whitelist: "
                            f"{sorted(SHELL_WHITELIST)}")
    try:
        proc = subprocess.run(
            argv, cwd=sandbox, capture_output=True, text=True,
            timeout=timeout, check=False, errors="replace")
    except subprocess.TimeoutExpired:
        return ToolResult(False, "", f"timeout after {timeout}s")
    except FileNotFoundError as e:
        return ToolResult(False, "", str(e))
    out = proc.stdout
    if proc.returncode != 0 and not out:
        return ToolResult(False, "", proc.stderr or f"rc={proc.returncode}")
    return ToolResult(True, out, error=proc.stderr or "")


def _tool_file_read(path: str, *, sandbox: Optional[str] = None,
                      max_bytes: int = 65536) -> ToolResult:
    try:
        resolved = _safe_resolve(path, sandbox)
    except ValueError as e:
        return ToolResult(False, "", str(e))
    if not os.path.isfile(resolved):
        return ToolResult(False, "", f"not a file: {path}")
    try:
        with open(resolved, "rb") as f:
            raw = f.read(max_bytes + 1)
    except OSError as e:
        return ToolResult(False, "", str(e))
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    try:
        text = raw.decode("utf-8")
        return ToolResult(True, text, truncated=truncated)
    except UnicodeDecodeError:
        # Return hex preview for binary files
        return ToolResult(True, raw.hex(), truncated=truncated,
                            error="binary; returned hex")


def _tool_base64_decode(data: str) -> ToolResult:
    try:
        raw = base64.b64decode(data, validate=False)
    except Exception as e:
        return ToolResult(False, "", str(e))
    try:
        return ToolResult(True, raw.decode("utf-8"))
    except UnicodeDecodeError:
        return ToolResult(True, raw.hex(), error="binary; hex returned")


def _tool_base64_encode(data: str) -> ToolResult:
    try:
        return ToolResult(True, base64.b64encode(data.encode("utf-8")).decode())
    except Exception as e:
        return ToolResult(False, "", str(e))


def _tool_hex_decode(data: str) -> ToolResult:
    try:
        raw = bytes.fromhex(data.replace(" ", "").replace("\n", ""))
    except ValueError as e:
        return ToolResult(False, "", str(e))
    try:
        return ToolResult(True, raw.decode("utf-8"))
    except UnicodeDecodeError:
        return ToolResult(True, raw.hex(), error="binary; hex returned")


def _tool_xor_bytes(data_hex: str, key_hex: str) -> ToolResult:
    try:
        data = bytes.fromhex(data_hex.replace(" ", "").replace("\n", ""))
        key = bytes.fromhex(key_hex.replace(" ", ""))
    except ValueError as e:
        return ToolResult(False, "", str(e))
    if not key:
        return ToolResult(False, "", "empty key")
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    try:
        return ToolResult(True, out.decode("utf-8"))
    except UnicodeDecodeError:
        return ToolResult(True, out.hex(), error="binary; hex returned")


def _tool_xor_brute(data_hex: str) -> ToolResult:
    """Brute single-byte XOR; return all candidates that look ASCII printable."""
    try:
        data = bytes.fromhex(data_hex.replace(" ", "").replace("\n", ""))
    except ValueError as e:
        return ToolResult(False, "", str(e))
    candidates: List[str] = []
    for k in range(256):
        out = bytes(b ^ k for b in data)
        printable = sum(1 for b in out if 32 <= b < 127 or b in (9, 10, 13))
        if data and printable / len(data) >= 0.9:
            try:
                candidates.append(f"key=0x{k:02x}: {out.decode('utf-8', errors='replace')}")
            except Exception:
                continue
    if not candidates:
        return ToolResult(True, "(no printable single-byte XOR found)")
    return ToolResult(True, "\n".join(candidates))


def _tool_http_get(url: str, *, allow_network: bool = False,
                     whitelist: Optional[Sequence[str]] = None,
                     timeout: float = 5.0) -> ToolResult:
    if not allow_network:
        return ToolResult(False, "", "network access disabled")
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception as e:
        return ToolResult(False, "", str(e))
    wl = set(whitelist or DEFAULT_HTTP_WHITELIST)
    if host not in wl:
        return ToolResult(False, "", f"host {host!r} not in whitelist {sorted(wl)}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctf-solver/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1_000_000).decode("utf-8", errors="replace")
        return ToolResult(True, body)
    except Exception as e:
        return ToolResult(False, "", str(e))


# ---------------------------------------------------------------------------
# Toolbox registry
# ---------------------------------------------------------------------------
@dataclass
class _ToolSpec:
    name: str
    description: str
    args_schema: Dict[str, str]      # arg_name -> type description
    fn: Callable[..., ToolResult]


class Toolbox:
    """Holds a registry of tools and runs them safely."""

    def __init__(self, *, sandbox: Optional[str] = None,
                  allow_network: bool = False,
                  http_whitelist: Optional[Sequence[str]] = None,
                  shell_timeout: float = 8.0):
        self.sandbox = sandbox
        self.allow_network = allow_network
        self.http_whitelist = list(http_whitelist or DEFAULT_HTTP_WHITELIST)
        self.shell_timeout = shell_timeout
        self._tools: Dict[str, _ToolSpec] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register("shell_run",
            "Run a whitelisted shell command. Args: cmd:str.",
            {"cmd": "string"},
            lambda cmd: _tool_shell_run(cmd, sandbox=self.sandbox,
                                          timeout=self.shell_timeout))
        self.register("file_read",
            "Read a file under the sandbox (returns text or hex if binary). "
            "Args: path:str.",
            {"path": "string"},
            lambda path: _tool_file_read(path, sandbox=self.sandbox))
        self.register("base64_decode",
            "Decode a base64 string. Args: data:str.",
            {"data": "string"},
            lambda data: _tool_base64_decode(data))
        self.register("base64_encode",
            "Encode a string as base64. Args: data:str.",
            {"data": "string"},
            lambda data: _tool_base64_encode(data))
        self.register("hex_decode",
            "Decode hex bytes to text. Args: data:str.",
            {"data": "string"},
            lambda data: _tool_hex_decode(data))
        self.register("xor_bytes",
            "XOR data_hex with key_hex (both as hex strings).",
            {"data_hex": "string", "key_hex": "string"},
            lambda data_hex, key_hex: _tool_xor_bytes(data_hex, key_hex))
        self.register("xor_brute_single_byte",
            "Brute every single-byte XOR key on data_hex; return printable.",
            {"data_hex": "string"},
            lambda data_hex: _tool_xor_brute(data_hex))
        self.register("http_get",
            "HTTP GET (only enabled when network is allowed AND host is "
            "in whitelist). Args: url:str.",
            {"url": "string"},
            lambda url: _tool_http_get(url, allow_network=self.allow_network,
                                          whitelist=self.http_whitelist))

    def register(self, name: str, description: str,
                  args_schema: Dict[str, str],
                  fn: Callable[..., ToolResult]) -> None:
        self._tools[name] = _ToolSpec(name=name, description=description,
                                         args_schema=args_schema, fn=fn)

    def list(self) -> List[str]:
        return sorted(self._tools.keys())

    def schema(self) -> List[Dict]:
        return [{
            "name": t.name,
            "description": t.description,
            "args": t.args_schema,
        } for t in self._tools.values()]

    def call(self, name: str, args: Dict) -> ToolResult:
        spec = self._tools.get(name)
        if spec is None:
            return ToolResult(False, "",
                                f"unknown tool {name!r}; available: {self.list()}")
        try:
            return spec.fn(**(args or {}))
        except TypeError as e:
            return ToolResult(False, "", f"bad arguments for {name}: {e}")
        except Exception as e:
            return ToolResult(False, "", f"{type(e).__name__}: {e}")


SAFE_DEFAULT_TOOLS = ("shell_run", "file_read", "base64_decode",
                       "base64_encode", "hex_decode", "xor_bytes",
                       "xor_brute_single_byte")
