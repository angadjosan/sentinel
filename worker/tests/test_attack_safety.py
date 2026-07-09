from __future__ import annotations

from sentinel_worker.attack_safety import (
    AttackBudget,
    AttackSafety,
    AuthRecipe,
    is_destructive_default,
    is_in_scope,
    is_probe_allowed,
    method_allowed,
    parse_attack_safety,
)


def test_scope_allows_in_scope_and_blocks_out_of_scope():
    safety = AttackSafety(scope=("/api/",))
    assert is_in_scope("/api/users", safety) is True
    assert is_in_scope("/admin/panel", safety) is False

    allowed, reason = is_probe_allowed("/api/users", "GET", safety)
    assert allowed is True and reason is None

    allowed, reason = is_probe_allowed("/admin/panel", "GET", safety)
    assert allowed is False and reason == "out_of_scope"


def test_empty_scope_allows_all_except_exclusions():
    safety = AttackSafety()
    assert is_in_scope("/anything", safety) is True
    allowed, reason = is_probe_allowed("/anything", "GET", safety)
    assert allowed is True and reason is None


def test_excluded_path_blocked():
    safety = AttackSafety(exclude_paths=("/api/health",))
    assert is_in_scope("/api/health/live", safety) is False
    allowed, reason = is_probe_allowed("/api/health/live", "GET", safety)
    assert allowed is False and reason == "excluded_path"


def test_destructive_path_blocked():
    safety = AttackSafety()
    assert is_destructive_default("/account/delete", "GET") is True
    assert is_destructive_default("/logout", "GET") is True
    assert is_destructive_default("/api/users", "DELETE") is True
    assert is_destructive_default("/api/users", "GET") is False

    allowed, reason = is_probe_allowed("/account/delete", "GET", safety)
    assert allowed is False and reason == "destructive"

    # DELETE against a benign path is destructive by method.
    allowed, reason = is_probe_allowed("/account/delete", "DELETE", safety)
    assert allowed is False and reason == "destructive"


def test_method_blocked_for_delete():
    safety = AttackSafety()
    assert method_allowed("GET", safety) is True
    assert method_allowed("delete", safety) is False
    # A non-destructive path with a blocked method reports method_blocked.
    allowed, reason = is_probe_allowed("/api/users", "delete", safety)
    # DELETE triggers destructive heuristic first.
    assert allowed is False and reason == "destructive"

    custom = AttackSafety(exclude_methods=("PUT",))
    allowed, reason = is_probe_allowed("/api/users", "PUT", custom)
    assert allowed is False and reason == "method_blocked"


def test_budget_max_duration_exhaustion_with_fake_clock():
    times = iter([100.0, 100.0, 100.0 + 600.0])
    clock = lambda: next(times)  # noqa: E731
    budget = AttackBudget(AttackSafety(max_attack_duration_seconds=600), clock=clock)
    exhausted, reason = budget.exhausted()  # elapsed 0
    assert exhausted is False and reason is None
    exhausted, reason = budget.exhausted()  # elapsed 600 -> exhausted
    assert exhausted is True and reason == "max_duration"


def test_budget_max_requests_exhaustion():
    budget = AttackBudget(AttackSafety(max_requests=3), clock=lambda: 0.0)
    assert budget.remaining_requests() == 3
    for _ in range(3):
        assert budget.exhausted() == (False, None)
        budget.record_request()
    assert budget.remaining_requests() == 0
    assert budget.exhausted() == (True, "max_requests")


def test_budget_elapsed_seconds():
    times = iter([10.0, 25.0])
    budget = AttackBudget(AttackSafety(), clock=lambda: next(times))
    assert budget.elapsed_seconds() == 15.0


def test_parse_defaults():
    safety = parse_attack_safety(None)
    assert safety == AttackSafety()
    assert safety.exclude_methods == ("DELETE",)
    assert safety.max_requests == 500
    assert safety.max_attack_duration_seconds == 600
    assert safety.auth is None

    assert parse_attack_safety({}) == AttackSafety()


def test_parse_with_auth_and_overrides():
    raw = {
        "scope": ["/api/"],
        "exclude_paths": ["/api/health"],
        "exclude_methods": ["DELETE", "PUT"],
        "max_requests": 10,
        "max_attack_duration_seconds": 30,
        "auth": {
            "method": "POST",
            "path": "/session",
            "body": {"user": "admin", "pass": "x"},
            "logged_in_indicator": "Welcome",
        },
    }
    safety = parse_attack_safety(raw)
    assert safety.scope == ("/api/",)
    assert safety.exclude_paths == ("/api/health",)
    assert safety.exclude_methods == ("DELETE", "PUT")
    assert safety.max_requests == 10
    assert safety.max_attack_duration_seconds == 30
    assert safety.auth == AuthRecipe(
        method="POST",
        path="/session",
        body={"user": "admin", "pass": "x"},
        logged_in_indicator="Welcome",
    )
