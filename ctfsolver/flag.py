"""Flag detection helpers."""
from __future__ import annotations
import re
from typing import List

# Common CTF flag formats. Permissive: anything {…} after a known prefix.
FLAG_REGEX = re.compile(
    # No word boundary on the left: flags can be embedded in binary noise
    # like `_flag{...}` from `strings`. Right side is bounded by `}`.
    r"(?:flag|FLAG|CTF|picoCTF|HTB|THM|ALLES|hxp|RICTF|FwordCTF)"
    r"\{[!-~]{1,256}?\}",
    re.MULTILINE)


def detect_flags(text: str) -> List[str]:
    """Return all flag-shaped substrings in `text`, deduped, in order."""
    if not text:
        return []
    seen = set()
    out: List[str] = []
    for m in FLAG_REGEX.finditer(text):
        f = m.group(0)
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out
