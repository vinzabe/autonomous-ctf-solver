"""Challenge representation."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ChallengeCategory(str, Enum):
    WEB = "web"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    PWN = "pwn"
    FORENSICS = "forensics"
    MISC = "misc"
    OSINT = "osint"


@dataclass
class Challenge:
    name: str
    description: str
    category: ChallengeCategory = ChallengeCategory.MISC
    files: List[str] = field(default_factory=list)
    workdir: Optional[str] = None
    target_url: Optional[str] = None
    expected_flag_format: str = "flag{...}"
    hint: Optional[str] = None
    flag: Optional[str] = None  # only used in tests for grading

    def normalize(self) -> "Challenge":
        if self.workdir:
            self.workdir = os.path.abspath(self.workdir)
        self.files = [os.path.abspath(f) for f in self.files]
        return self
