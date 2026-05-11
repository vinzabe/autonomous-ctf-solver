"""Live LLM smoke test — solves the strings challenge end-to-end."""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from ctfsolver.agent import CTFAgent
from ctfsolver.challenge import Challenge, ChallengeCategory
from ctfsolver.tools import Toolbox


CHALLENGES = os.path.normpath(os.path.join(_HERE, "..", "challenges"))


@pytest.mark.skipif(not os.environ.get("LLM_LIVE"),
                     reason="set LLM_LIVE=1 for live solve")
def test_live_solve_strings():
    from llm_client import LLMClient
    client = LLMClient(timeout=180.0)
    tb = Toolbox(sandbox=CHALLENGES)
    agent = CTFAgent(client, tb, model="glm-5.1", temperature=0.0,
                       max_steps=6)
    ch = Challenge(
        name="strings",
        description=("There is a CTF flag in the file `strings/binary`. "
                      "The flag has format flag{...}. Use the `strings` "
                      "command to find it."),
        category=ChallengeCategory.MISC,
        files=[os.path.join(CHALLENGES, "strings", "binary")],
        workdir=CHALLENGES,
        expected_flag_format="flag{...}",
    )
    res = agent.solve(ch)
    assert res.success, f"agent failed: {res.final_message}\n{res.trace.to_dict()}"
    assert res.flag == "flag{strings_are_easy_2024}"
