"""ctfsolver — a bounded CTF agent whose SCORING you can trust.

The trap in agentic CTF benchmarks is flag leakage. If the flag appears in the
challenge prompt, the agent 'solves' it by copying; if the scorer sees the flag in
plaintext, a lucky echo scores. Either way the benchmark measures nothing.

This solver is built so the score is honest:

  * The flag is verified by **salted hash**. The plaintext flag never enters a
    prompt, a tool result, or the transcript — only its hash is stored.
  * The agent runs under a **hard step and tool budget**, so 'solved eventually by
    brute force' is distinguishable from 'solved efficiently'.
  * Tools are an explicit, sandboxed surface (read-only challenge files, a scoped
    shell) — the agent cannot reach the scorer's secret or the host.
"""
__version__ = "1.0.0"
