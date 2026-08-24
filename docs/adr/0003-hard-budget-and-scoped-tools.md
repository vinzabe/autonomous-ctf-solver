# 3. A hard step budget and a tool surface that cannot reach the flag or host

Date: 2026-08-24
Status: Accepted

## Context
"Solved" is meaningless without "at what cost". An agent that eventually brute-forces
a flag at 10,000 steps is not the same as one that solves it in three. And an agent
with an unscoped shell could read the scorer's secret or escape to the host, which
would make the score a lie.

## Decision
- `solve()` enforces a hard `step_budget`; every action (tool call or submit) costs
  a step, and the run ends at the budget. Points decay with steps used, and
  `efficiency` (points per step) is reported, so brute force is visible.
- The `ToolBox` exposes only file reads over the challenge's declared files and pure
  decoders (rot13/hex/base64). No tool reads the salt or hash; none touches the host
  filesystem.

## Consequences
- Efficiency separates a genuine solve from a lucky late one; the demo shows
  2-step and 3-step solves against a 20-step budget.
- The agent structurally cannot reach the scorer's secret, so a "solve" is a real
  solve. A test enumerates the toolbox and asserts no tool references salt/flag/hash.
- Real untrusted-code execution (pwn challenges that run a binary) needs a real
  sandbox — that is out of scope here and is called out in the threat model, with a
  pointer to the companion agent-sandbox project.
