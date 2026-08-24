"""Leak-proofing is the whole point: the flag must never be recoverable from what
the agent (or the scorer's transcript) can see."""
import pytest

from ctfsolver.challenge import Challenge, FlagError, hash_flag, make_challenge


def test_flag_is_not_stored_plaintext():
    ch = make_challenge("c", "misc", "find it", "flag{secret}")
    assert not hasattr(ch, "flag")
    # nothing on the object equals the flag
    assert "flag{secret}" not in ch.prompt
    assert "flag{secret}" not in ch.flag_hash


def test_correct_flag_accepted():
    ch = make_challenge("c", "misc", "find it", "flag{correct}")
    assert ch.submit("flag{correct}")
    assert ch.submit("  flag{correct}  ")   # whitespace-tolerant


def test_wrong_flag_rejected():
    ch = make_challenge("c", "misc", "find it", "flag{correct}")
    assert not ch.submit("flag{wrong}")


def test_flag_in_prompt_is_refused():
    with pytest.raises(FlagError, match="PROMPT"):
        make_challenge("c", "misc", "the flag is flag{oops}", "flag{oops}")


def test_flag_in_file_refused_unless_declared():
    with pytest.raises(FlagError, match="accidental leak"):
        make_challenge("c", "misc", "find it", "flag{x}",
                       files=(("f.txt", "flag{x}"),))


def test_flag_in_file_allowed_when_declared():
    ch = make_challenge("c", "misc", "find it", "flag{x}",
                        files=(("f.txt", "flag{x}"),), flag_in_files=True)
    assert ch.submit("flag{x}")


def test_salt_must_not_be_visible():
    with pytest.raises(FlagError, match="salt appears"):
        Challenge("c", "misc", "prompt contains SALT123", (), "hash",
                  salt="SALT123")


def test_hash_requires_salt():
    with pytest.raises(FlagError):
        hash_flag("flag{x}", "")


def test_different_salts_give_different_hashes():
    assert hash_flag("flag{x}", "a") != hash_flag("flag{x}", "b")
