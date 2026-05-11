"""Agent tests with a scripted fake LLM."""
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from ctfsolver.agent import (CTFAgent, AgentResult, AgentTrace, AgentStep,
                                _extract_json_object)
from ctfsolver.challenge import Challenge, ChallengeCategory
from ctfsolver.tools import Toolbox


CHALLENGES = os.path.normpath(os.path.join(_HERE, "..", "challenges"))


# ---------------------------------------------------------------------------
# Fake LLM that returns scripted responses
# ---------------------------------------------------------------------------
class _Resp:
    def __init__(self, content):
        self.content = content


class ScriptedLLM:
    """Returns the next scripted response on each .chat() call."""
    def __init__(self, scripts):
        self.scripts = list(scripts)
        self.calls = 0

    def chat(self, messages, **kw):
        if self.calls >= len(self.scripts):
            raise RuntimeError("no more scripted responses")
        out = self.scripts[self.calls]
        self.calls += 1
        return _Resp(out)


# ---------------------------------------------------------------------------
def _ch_strings():
    return Challenge(
        name="strings",
        description="There's a flag hidden in the binary file. Find it.",
        category=ChallengeCategory.MISC,
        files=[os.path.join(CHALLENGES, "strings", "binary")],
        workdir=CHALLENGES,
    )


def _ch_base64():
    return Challenge(
        name="base64",
        description="Decode the base64-encoded flag in encoded.txt.",
        category=ChallengeCategory.CRYPTO,
        files=[os.path.join(CHALLENGES, "base64", "encoded.txt")],
        workdir=CHALLENGES,
    )


def _ch_xor():
    return Challenge(
        name="xor",
        description="Single-byte XOR cipher. Recover the flag.",
        category=ChallengeCategory.CRYPTO,
        files=[os.path.join(CHALLENGES, "xor", "cipher.hex")],
        workdir=CHALLENGES,
    )


# ---------------------------------------------------------------------------
def test_extract_json_object_handles_codefence():
    p = _extract_json_object('```json\n{"thought": "hi", "tool": "x"}\n```')
    assert p == {"thought": "hi", "tool": "x"}


def test_extract_json_object_handles_prose():
    p = _extract_json_object("Sure!\n{\"final_flag\":\"flag{a}\"}\nBye")
    assert p["final_flag"] == "flag{a}"


def test_extract_json_object_invalid():
    assert _extract_json_object("not json") is None
    assert _extract_json_object("") is None


# ---------------------------------------------------------------------------
def test_agent_solves_strings_via_shell_run():
    binary_path = os.path.join(CHALLENGES, "strings", "binary")
    scripts = [json.dumps({
        "thought": "run strings on the binary",
        "tool": "shell_run",
        "args": {"cmd": f"strings {binary_path}"},
    })]
    llm = ScriptedLLM(scripts)
    tb = Toolbox(sandbox=CHALLENGES)
    agent = CTFAgent(llm, tb, max_steps=3)
    res = agent.solve(_ch_strings())
    assert res.success is True
    assert res.flag == "flag{strings_are_easy_2024}"
    assert res.steps_taken == 1


def test_agent_solves_base64_two_step():
    enc = "ZmxhZ3tiYXNlNjRfZGVjb2RlZF8yMDI0fQ=="
    scripts = [
        json.dumps({"thought": "read the file",
                     "tool": "file_read",
                     "args": {"path": os.path.join(CHALLENGES, "base64",
                                                       "encoded.txt")}}),
        json.dumps({"thought": "decode base64",
                     "tool": "base64_decode",
                     "args": {"data": enc}}),
    ]
    llm = ScriptedLLM(scripts)
    tb = Toolbox(sandbox=CHALLENGES)
    agent = CTFAgent(llm, tb, max_steps=4)
    res = agent.solve(_ch_base64())
    assert res.success is True
    assert res.flag == "flag{base64_decoded_2024}"
    assert res.steps_taken == 2


def test_agent_solves_xor_brute():
    cipher_hex = open(os.path.join(CHALLENGES, "xor",
                                       "cipher.hex")).read().strip()
    scripts = [json.dumps({
        "thought": "brute single-byte XOR",
        "tool": "xor_brute_single_byte",
        "args": {"data_hex": cipher_hex},
    })]
    llm = ScriptedLLM(scripts)
    tb = Toolbox(sandbox=CHALLENGES)
    agent = CTFAgent(llm, tb, max_steps=2)
    res = agent.solve(_ch_xor())
    assert res.success is True
    assert "flag{xor_with_single_byte_42}" in res.flag


def test_agent_step_budget_exhausted():
    scripts = [json.dumps({"thought": "useless",
                              "tool": "base64_decode",
                              "args": {"data": "abc"}})] * 5
    llm = ScriptedLLM(scripts)
    tb = Toolbox()
    agent = CTFAgent(llm, tb, max_steps=3)
    res = agent.solve(_ch_base64())
    assert res.success is False
    assert res.steps_taken == 3
    assert "exhausted" in res.final_message


def test_agent_handles_invalid_json_then_recovers():
    binary_path = os.path.join(CHALLENGES, "strings", "binary")
    scripts = [
        "this is not JSON, sorry",
        json.dumps({"thought": "ok now properly",
                     "tool": "shell_run",
                     "args": {"cmd": f"strings {binary_path}"}}),
    ]
    llm = ScriptedLLM(scripts)
    tb = Toolbox(sandbox=CHALLENGES)
    agent = CTFAgent(llm, tb, max_steps=4)
    res = agent.solve(_ch_strings())
    assert res.success is True
    assert res.flag == "flag{strings_are_easy_2024}"


def test_agent_accepts_final_flag_after_observation():
    enc = "ZmxhZ3tiYXNlNjRfZGVjb2RlZF8yMDI0fQ=="
    flag = "flag{base64_decoded_2024}"
    scripts = [
        json.dumps({"thought": "decode",
                     "tool": "base64_decode",
                     "args": {"data": enc}}),
        json.dumps({"thought": "found it",
                     "final_flag": flag}),
    ]
    llm = ScriptedLLM(scripts)
    tb = Toolbox()
    agent = CTFAgent(llm, tb, max_steps=4)
    res = agent.solve(_ch_base64())
    # Step 1 already finds flag in observation, returns immediately,
    # so steps_taken == 1.
    assert res.success is True
    assert res.flag == flag


def test_agent_rejects_hallucinated_final_flag():
    """Model declares a flag that never appeared and isn't flag-shaped."""
    scripts = [
        json.dumps({"thought": "I just know it",
                     "final_flag": "totally not a flag"}),
        json.dumps({"thought": "trying again",
                     "tool": "base64_decode",
                     "args": {"data": "x"}}),
    ]
    llm = ScriptedLLM(scripts)
    tb = Toolbox()
    agent = CTFAgent(llm, tb, max_steps=2)
    res = agent.solve(_ch_base64())
    assert res.success is False


def test_agent_handles_llm_exception():
    class Boom:
        def chat(self, messages, **kw):
            raise RuntimeError("provider exploded")

    tb = Toolbox()
    agent = CTFAgent(Boom(), tb, max_steps=3)
    res = agent.solve(_ch_base64())
    assert res.success is False
    assert "provider exploded" in res.final_message


def test_agent_writeup_reflects_trace():
    from ctfsolver.writeup import generate_writeup
    binary_path = os.path.join(CHALLENGES, "strings", "binary")
    scripts = [json.dumps({
        "thought": "strings",
        "tool": "shell_run",
        "args": {"cmd": f"strings {binary_path}"},
    })]
    llm = ScriptedLLM(scripts)
    tb = Toolbox(sandbox=CHALLENGES)
    agent = CTFAgent(llm, tb, max_steps=2)
    res = agent.solve(_ch_strings())
    md = generate_writeup(res)
    assert "Writeup: strings" in md
    assert "flag{strings_are_easy_2024}" in md
    assert "shell_run" in md
