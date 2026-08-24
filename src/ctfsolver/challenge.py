"""Challenges and leak-proof flag verification.

A challenge stores the flag ONLY as a salted SHA-256 hash. `submit` checks a
candidate against the hash. There is no method that returns the flag, so it cannot
leak into a prompt, a log, or the score — by construction.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os


class FlagError(ValueError):
    pass


def hash_flag(flag: str, salt: str) -> str:
    if not salt:
        raise FlagError("a salt is required")
    return hmac.new(salt.encode(), flag.encode(), hashlib.sha256).hexdigest()


@dataclasses.dataclass(frozen=True, slots=True)
class Challenge:
    id: str
    category: str                 # "crypto" | "pwn" | "web" | "rev" | ...
    prompt: str                   # shown to the agent — MUST NOT contain the flag
    files: tuple[tuple[str, str], ...]  # (name, content) available to the agent
    flag_hash: str                # salted hash; the plaintext is never stored
    salt: str
    max_points: int = 100

    def __post_init__(self) -> None:
        # A structural guard: the flag hash must not be derivable from anything the
        # agent can see. We cannot check the plaintext (we do not have it), but we
        # CAN ensure the salt is not sitting in the prompt/files.
        visible = self.prompt + "".join(c for _, c in self.files)
        if self.salt and self.salt in visible:
            raise FlagError(
                "salt appears in agent-visible content; the flag would be "
                "recoverable — refusing to construct this challenge")

    def submit(self, candidate: str) -> bool:
        """True iff the candidate matches the flag. Constant-time compare."""
        return hmac.compare_digest(self.flag_hash,
                                   hash_flag(candidate.strip(), self.salt))


def make_challenge(id: str, category: str, prompt: str, flag: str, *,
                   files: tuple[tuple[str, str], ...] = (),
                   max_points: int = 100, salt: str | None = None,
                   flag_in_files: bool = False) -> Challenge:
    """Build a challenge from a plaintext flag, hashing it immediately. The flag is
    NOT retained on the returned object.

    Two leak guards, with a crucial distinction:
      * The flag must NEVER appear in the PROMPT — that tells the agent the answer,
        and no CTF works that way. Always enforced.
      * The flag appearing in a FILE is a legitimate challenge design (the agent has
        to find it), but ONLY when you declare `flag_in_files=True`. Otherwise a
        flag in a file is treated as an accidental leak and refused, so you cannot
        leak by mistake.
    """
    salt = salt or os.urandom(16).hex()
    if flag in prompt:
        raise FlagError(
            "the flag appears in the PROMPT; the agent would be handed the answer. "
            "Remove it before building the challenge.")
    if not flag_in_files and any(flag in c for _, c in files):
        raise FlagError(
            "the flag appears in a file but flag_in_files was not set. If the flag "
            "is meant to be discoverable in the files, pass flag_in_files=True; "
            "otherwise this is an accidental leak.")
    return Challenge(id=id, category=category, prompt=prompt, files=files,
                     flag_hash=hash_flag(flag, salt), salt=salt,
                     max_points=max_points)
