"""Budget enforcement and honest scoring."""
from ctfsolver.agent import Action, solve
from ctfsolver.challenge import make_challenge
from ctfsolver.corpus import demo_challenges
from ctfsolver.heuristic import HeuristicAgent


def test_budget_is_hard():
    """An agent that never solves must stop exactly at the budget."""
    class Idle:
        name = "idle"
        def act(self, prompt, box, history):
            return Action("list_files")
    ch = make_challenge("c", "misc", "go", "flag{never}")
    res = solve(ch, Idle(), step_budget=7)
    assert not res.solved and res.steps_used == 7


def test_solved_within_budget_scores():
    ch = demo_challenges()[0]   # warmup, solvable
    res = solve(ch, HeuristicAgent(), step_budget=20)
    assert res.solved and res.points > 0


def test_faster_solve_scores_higher():
    ch = demo_challenges()[0]
    fast = solve(ch, HeuristicAgent(), step_budget=20)
    # a tighter budget forces the same solve to be a larger fraction of it -> fewer points
    slow = solve(ch, HeuristicAgent(), step_budget=100)
    assert slow.points >= fast.points   # more headroom -> less decay


def test_efficiency_metric():
    res = solve(demo_challenges()[0], HeuristicAgent(), step_budget=20)
    assert res.efficiency == res.points / res.steps_used


def test_unsolvable_challenge_scores_zero():
    hard = [c for c in demo_challenges() if c.id == "hard"][0]
    res = solve(hard, HeuristicAgent(), step_budget=20)
    assert not res.solved and res.points == 0


def test_heuristic_solves_the_tractable_challenges():
    results = {c.id: solve(c, HeuristicAgent(), step_budget=20).solved
               for c in demo_challenges()}
    assert results["warmup"] and results["encoding"] and results["rot"]
    assert not results["hard"]      # honestly fails the hard one


def test_wrong_submit_does_not_end_run():
    """A rejected flag costs a step but the run continues until solve or budget."""
    ch = demo_challenges()[1]   # encoding, solvable after a decode
    res = solve(ch, HeuristicAgent(), step_budget=20)
    assert res.solved
