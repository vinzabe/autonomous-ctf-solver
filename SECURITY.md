# Security Policy

## Reporting

Report vulnerabilities responsibly to the repository owner by email to **g@abejar.net** -- do not open public issues.

## Scope

Autonomous agent for **authorized CTF challenges and training**. Do not point it at production systems.

## Considerations

- All shell tools run through a strict allowlist (no `rm`, `mv`, `wget`, `curl`, etc.)
- `file_read` rejects path traversal (`../`) and sandbox escapes (resolves via `os.path.realpath` and verifies prefix)
- `http_get` is gated behind explicit URL whitelisting -- by default no network access
- The agent is constrained to `max_steps` to bound runtime
