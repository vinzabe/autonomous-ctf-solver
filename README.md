# Autonomous CTF Solver

ReAct-style autonomous agent that solves CTF challenges by invoking a sandboxed shell toolbox (strings, file, xxd, base64, etc.), reading files within a sandboxed root, and decoding/encrypting candidate flags.

## Features

- **Challenge dataclass**: name, category, files, hints, sandbox_root
- **Toolbox**: whitelisted shell commands (strings, file, xxd, base64, cat, grep, python3, od); file_read with `os.path.realpath` sandbox check; base64/hex encode-decode; xor + single-byte xor brute force; whitelisted+gated `http_get`
- **Flag detection**: regex without `\b` left-anchor (so binary-noise prefixes don't break matching)
- **CTF Agent**: JSON-only ReAct loop; validates `final_flag` against tool observations; configurable `max_steps`
- **Writeup generator**: LLM converts trace -> markdown writeup

## Quick Start

```bash
pip install -r requirements.txt

python -m ctfsolver.cli solve --challenge-dir challenges/strings
```

## Testing

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/test_live_llm.py -v
```

## Architecture

```
ctfsolver/
  challenge.py - Challenge dataclass + loader
  flag.py      - FLAG_REGEX + detect_flags
  tools.py     - Toolbox, ToolResult, SAFE_DEFAULT_TOOLS
  agent.py     - CTFAgent (ReAct loop)
  writeup.py   - LLM writeup generator
  cli.py
challenges/
  strings/, base64/, xor/, reverse_string/ - bundled fixture challenges
```

## License

MIT
