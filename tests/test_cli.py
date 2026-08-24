import json

import pytest

from ctfsolver.cli import EXIT_OK, main


def test_run_reports_scores(capsys):
    assert main(["run", "--budget", "20"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "solved" in out and "points" in out


def test_run_json(capsys):
    main(["run", "--budget", "20", "--json"])
    d = json.loads(capsys.readouterr().out)
    assert d["solved"] >= 2
    assert all("efficiency" in r for r in d["results"])


def test_verify_confirms_leak_free(capsys):
    assert main(["verify"]) == EXIT_OK
    assert "leak-free" in capsys.readouterr().out


def test_tight_budget_solves_fewer(capsys):
    main(["run", "--budget", "1", "--json"])
    d = json.loads(capsys.readouterr().out)
    # a 1-step budget cannot even enumerate + read + submit
    assert d["solved"] < 3


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
