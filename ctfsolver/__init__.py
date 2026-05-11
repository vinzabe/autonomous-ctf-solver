"""Autonomous CTF Solver — LLM agent with tool-calling for CTF challenges."""
__version__ = "0.1.0"

from .challenge import Challenge, ChallengeCategory
from .flag import detect_flags, FLAG_REGEX
from .tools import Toolbox, ToolResult, SAFE_DEFAULT_TOOLS
from .agent import CTFAgent, AgentResult, AgentTrace
from .writeup import generate_writeup
