# autonomous-ctf-solver

**A bounded CTF-solving agent whose *scoring* you can trust — because the flag never enters a prompt, a tool result, or the transcript.**

Agentic CTF benchmarks are easy to fake, and both failure modes are silent. If the flag appears in the challenge prompt, the agent "solves" it by copying. If the scorer sees the flag in plaintext, a lucky echo scores. Either way the benchmark measures nothing.

This solver is built so the number is honest:

- **Flags are verified by salted hash.** A `Challenge` stores only `HMAC-SHA256(salt, flag)`. There is no method that returns the flag — it cannot leak into a prompt, a log, or the score, by construction.
- **A hard step budget.** The agent runs until it submits a correct flag or the budget is spent, so "solved efficiently" (2 steps) is distinguishable from "brute-forced at the limit."
- **A scoped tool surface.** Tools operate only on the challenge's declared files and pure decoders. No tool reads the salt or hash, and none reaches the host.

```
$ ctfsolver run --budget 20
solved 3/4 within 20 steps  (284 points)

  challenge     solved  steps  points     eff
  warmup           yes      2      96   48.00
  encoding         yes      3      94   31.33
  rot              yes      3      94   31.33
  hard              no     20       0    0.00
```

It solves the three tractable challenges and **honestly fails the hard one** — no cheating, because it structurally cannot cheat.

## Two leak guards, with a real distinction

`make_challenge` refuses to build a leaky challenge:

- **Flag in the PROMPT → always refused.** Telling the agent the answer is not a CTF.
- **Flag in a FILE → refused unless `flag_in_files=True`.** Hiding the flag in a file for the agent to find is a legitimate design, but it must be *declared*, so you cannot leak by accident.

```python
def test_flag_in_prompt_is_refused():
    with pytest.raises(FlagError, match="PROMPT"):
        make_challenge("c", "misc", "the flag is flag{oops}", "flag{oops}")
```

And `verify` proves the whole corpus is leak-free: no challenge exposes its salt, and no `Challenge` object stores the plaintext flag (asserted with `assert not hasattr(ch, "flag")`).

## The scorer can't be gamed by an echo

Because verification is a hash comparison, submitting flag-shaped *ciphertext* fails — which drove a real fix during the build. The heuristic agent kept re-submitting `synt{ebg13_ebpxf}` (a flag-shaped but rot13-encrypted string) because it looked like a flag in the transcript. Now the agent tracks tried candidates and queues decodings *before* any direct submit, so it moves past the ciphertext to `flag{rot13_rocks}`. The scorer never had to know or care — it only ever sees a hash.

## Pluggable agents

An `Agent` is `act(prompt, toolbox, history) -> Action`, called until it submits or the budget runs out. The bundled `HeuristicAgent` is a small deterministic solver (read files, try base64/hex/rot13, submit flag-shaped strings) so the harness runs and tests reproduce without an LLM. A real LLM agent implements the same protocol — and is scored by the same leak-proof rules.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/autonomous-ctf-solver && cd autonomous-ctf-solver
python -m pip install -e ".[dev]"

ctfsolver run --budget 20          # solve the demo challenges, scored
ctfsolver run --budget 20 --json
ctfsolver verify                   # prove flags cannot leak into the score
```

Exit codes: `run` → `0`; `verify` → `0` leak-free, `1` if a leak is found.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=ctfsolver      # 27 tests, ~93% coverage
mypy --strict src/ctfsolver # clean
ruff check src tests        # clean
```

## License

MIT © vinzabe
