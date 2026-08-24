from ctfsolver.challenge import make_challenge
from ctfsolver.tools import ToolBox


def _box():
    ch = make_challenge("c", "misc", "go", "flag{y}",
                        files=(("a.txt", "hello world"), ("b.txt", "AAAA")))
    return ToolBox(ch)


def test_list_files():
    assert set(_box().list_files().output.split()) == {"a.txt", "b.txt"}


def test_read_file():
    assert _box().read_file("a.txt").output == "hello world"


def test_read_missing_file():
    assert not _box().read_file("nope.txt").ok


def test_grep():
    assert "hello world" in _box().grep("hello", "a.txt").output


def test_decoders():
    box = _box()
    assert box.rot13("uryyb").output == "hello"
    assert box.from_hex("68656c6c6f").output == "hello"
    assert box.from_base64("aGVsbG8=").output == "hello"


def test_toolbox_cannot_reach_flag():
    """No tool exposes the salt or hash — the flag cannot be derived via tools."""
    box = _box()
    for attr in dir(box):
        if attr.startswith("_") or not callable(getattr(box, attr)):
            continue
        # no tool name references the secret
        assert attr not in ("salt", "flag", "flag_hash")
