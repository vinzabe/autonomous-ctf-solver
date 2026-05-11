"""CLI: solve a challenge JSON with the LLM agent (LIVE)."""
from __future__ import annotations
import argparse
import json
import os
import sys
from typing import Sequence

from .challenge import Challenge, ChallengeCategory
from .tools import Toolbox
from .agent import CTFAgent
from .writeup import generate_writeup


def _load_challenge(path: str) -> Challenge:
    with open(path) as f:
        data = json.load(f)
    cat = ChallengeCategory(data.get("category", "misc"))
    return Challenge(
        name=data["name"],
        description=data.get("description", ""),
        category=cat,
        files=data.get("files", []),
        workdir=data.get("workdir"),
        target_url=data.get("target_url"),
        expected_flag_format=data.get("expected_flag_format", "flag{...}"),
        hint=data.get("hint"),
    )


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ctfsolver",
                                  description="Autonomous CTF solver")
    p.add_argument("challenge", help="path to challenge JSON")
    p.add_argument("--max-steps", type=int, default=12, dest="max_steps")
    p.add_argument("--model", default="glm-5.1")
    p.add_argument("--allow-network", action="store_true",
                     dest="allow_network")
    p.add_argument("--http-whitelist",
                     help="comma-separated list of allowed hosts")
    p.add_argument("--writeup", help="write Markdown writeup to this path")
    p.add_argument("--timeout", type=float, default=120.0,
                     help="LLM HTTP timeout in seconds")
    ns = p.parse_args(argv)

    sys.path.insert(0,
                      os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from llm_client import LLMClient

    ch = _load_challenge(ns.challenge)
    sandbox = ch.workdir or os.path.dirname(os.path.abspath(ns.challenge))
    whitelist = [h.strip() for h in (ns.http_whitelist or "").split(",")
                  if h.strip()] or None
    tb = Toolbox(sandbox=sandbox, allow_network=ns.allow_network,
                  http_whitelist=whitelist)
    client = LLMClient(timeout=ns.timeout)
    agent = CTFAgent(client, tb, model=ns.model, max_steps=ns.max_steps)
    res = agent.solve(ch)
    print(json.dumps(res.to_dict(), indent=2))
    if ns.writeup:
        with open(ns.writeup, "w") as f:
            f.write(generate_writeup(res))
    return 0 if res.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
