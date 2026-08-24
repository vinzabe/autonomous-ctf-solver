# Threat model & scope

## What this is
A harness for evaluating CTF-solving agents with leak-proof scoring: flags are
verified by hash, the agent runs under a hard budget, and its tools cannot reach the
secret or the host.

## What this is not
- **Not a real exploitation sandbox.** The bundled tools are file reads and pure
  decoders. Categories that require RUNNING untrusted code (pwn, some rev) need real
  isolation — use the companion `agent-sandbox` for that; do not point this harness's
  toolbox at code you are unwilling to execute in-process.
- **Not an LLM agent.** The `HeuristicAgent` is a deterministic stand-in so the
  harness runs and tests reproduce. A real agent implements the `Agent` protocol.

## The scoring guarantees
- **Flags cannot leak into the score.** Stored as a salted hash; no method returns
  the plaintext; the plaintext is not retained after construction.
- **Flags cannot leak into a prompt or file by accident.** The prompt guard is
  absolute; the file guard requires an explicit opt-in.
- **The budget is hard.** An agent that never solves stops exactly at the budget.

## Trust boundaries & limits
- **The harness author is trusted with the plaintext once,** at
  `make_challenge` time. After that it is unrecoverable from the object.
- **The salt must be kept out of agent-visible content** — enforced, but the author
  must not, e.g., pass the salt in as a file.
- **Efficiency is a proxy for skill, not a definition of it.** A crude agent can
  score by exhausting cheap decoders on an easy challenge; the metric is meant to be
  read alongside which challenges were solved, not alone.
- **The demo corpus is small and the heuristic is simple.** Absolute scores measure
  this toolbox and this agent, not real-world CTF capability.

## Non-goals
- Executing untrusted challenge binaries (sandbox separately).
- Being a full CTF platform.
- Certifying agent capability from these synthetic challenges.

## Reporting
Any path by which a flag could reach a prompt, tool output, or the score is a
critical bug — report to **gabejar@usa.com**.
