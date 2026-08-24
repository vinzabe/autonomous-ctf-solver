# 2. Verify flags by salted hash; the plaintext never leaves the constructor

Date: 2026-08-24
Status: Accepted

## Context
Agentic CTF benchmarks have two silent failure modes: the flag in the prompt (the
agent copies it) and the flag visible to the scorer (a lucky echo scores). Both make
the benchmark measure nothing, and both are easy to introduce by accident.

## Decision
- A `Challenge` stores only `HMAC-SHA256(salt, flag)`. It has no attribute holding
  the plaintext and no method returning it. `submit()` hashes the candidate and
  compares in constant time.
- `make_challenge` takes the plaintext, hashes it immediately, and does not retain
  it. It refuses to build a challenge whose flag appears in the prompt (always) or
  in a file (unless `flag_in_files=True` is explicitly set).
- A structural guard also refuses a challenge whose salt appears in agent-visible
  content, since that would let the flag be recomputed.

## Consequences
- The flag cannot enter a prompt, tool result, transcript, or the score. Enforced by
  tests including `assert not hasattr(ch, "flag")`.
- Submitting flag-shaped ciphertext simply fails the hash check — the scorer needs
  no cleverness to reject it, which is why the whole scoring path is trustworthy.
- Cost: the harness author must supply the plaintext to `make_challenge` once; after
  that it is unrecoverable, so a corpus cannot be "read" to cheat.
