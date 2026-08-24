"""Demo challenges spanning a few categories, each with the flag hidden behind some
work so a solver must actually do something. Flags are hashed on construction."""
from __future__ import annotations

import base64

from .challenge import Challenge, make_challenge


def demo_challenges() -> list[Challenge]:
    b64 = base64.b64encode(b"flag{base64_was_enough}").decode()
    return [
        make_challenge(
            "warmup", "misc",
            "The flag is hidden in the attached note.",
            flag="flag{read_the_file}",
            files=(("note.txt", "nothing to see... flag{read_the_file} ...here"),),
            flag_in_files=True),
        make_challenge(
            "encoding", "crypto",
            "The attached blob is encoded. Decode it.",
            flag="flag{base64_was_enough}",
            files=(("blob.txt", b64),)),
        make_challenge(
            "rot", "crypto",
            "Caesar would be proud.",
            flag="flag{rot13_rocks}",
            files=(("cipher.txt", "synt{ebg13_ebpxf}"),)),  # rot13 of the flag
        make_challenge(
            "hard", "rev",
            "No hints. The flag is not in the files in any obvious form.",
            flag="flag{deep_dynamic_analysis_required}",
            files=(("binary.txt", "\x7fELF... (opaque)"),)),   # unsolvable by heuristic
    ]
