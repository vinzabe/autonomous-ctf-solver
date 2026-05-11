import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from ctfsolver.flag import detect_flags, FLAG_REGEX


def test_detects_basic_flag():
    assert detect_flags("here is flag{abc_123}") == ["flag{abc_123}"]


def test_detects_multiple_formats():
    blob = ("intro picoCTF{nice} middle CTF{ok} HTB{also} "
            "and FAKE{nope} and flag{a}")
    found = detect_flags(blob)
    assert "picoCTF{nice}" in found
    assert "CTF{ok}" in found
    assert "HTB{also}" in found
    assert "flag{a}" in found
    assert "FAKE{nope}" not in found


def test_dedupes():
    assert detect_flags("flag{x} ... flag{x}") == ["flag{x}"]


def test_handles_empty_and_none():
    assert detect_flags("") == []
    assert detect_flags(None) == []  # type: ignore


def test_does_not_match_open_brace():
    # Without close-brace it shouldn't match.
    assert detect_flags("flag{stillopen") == []
