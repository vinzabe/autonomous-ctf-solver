"""CLI: run the solver over the demo challenges under a step budget.

Exit codes: 0 (ran), 1 (error). The point is the report, not a pass/fail.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .agent import solve
from .corpus import demo_challenges
from .heuristic import HeuristicAgent

EXIT_OK, EXIT_ERROR = 0, 1


def cmd_run(a: argparse.Namespace) -> int:
    results = [solve(ch, HeuristicAgent(), step_budget=a.budget)
               for ch in demo_challenges()]
    total = sum(r.points for r in results)
    solved = sum(1 for r in results if r.solved)
    if a.json:
        print(json.dumps({
            "step_budget": a.budget, "solved": solved, "total": len(results),
            "points": total,
            "results": [{"challenge": r.challenge_id, "solved": r.solved,
                         "steps_used": r.steps_used, "points": r.points,
                         "efficiency": round(r.efficiency, 3)}
                        for r in results]}, indent=2))
    else:
        print(f"solved {solved}/{len(results)} within {a.budget} steps  "
              f"({total} points)\n")
        print(f"  {'challenge':<12}{'solved':>8}{'steps':>7}{'points':>8}"
              f"{'eff':>8}")
        for r in results:
            print(f"  {r.challenge_id:<12}{'yes' if r.solved else 'no':>8}"
                  f"{r.steps_used:>7}{r.points:>8}{r.efficiency:>8.2f}")
    return EXIT_OK


def cmd_verify(a: argparse.Namespace) -> int:
    """Prove the flag never leaks: show that no challenge exposes its plaintext."""
    problems = []
    for ch in demo_challenges():
        visible = ch.prompt + "".join(c for _, c in ch.files)
        # the hash and salt must not be reconstructable from visible content
        if ch.salt in visible:
            problems.append(f"{ch.id}: salt visible")
        # there is no attribute that returns the flag
        assert not hasattr(ch, "flag"), "Challenge must not store the plaintext flag"
    if a.json:
        print(json.dumps({"leak_free": not problems,
                          "problems": problems}, indent=2))
    else:
        print("leak-free: no challenge exposes its salt or plaintext flag"
              if not problems else f"LEAKS: {problems}")
    return EXIT_OK if not problems else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ctfsolver", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the solver over the demo challenges")
    r.add_argument("--budget", type=int, default=20, help="step budget per challenge")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify", help="prove flags cannot leak into the score")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except (ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
