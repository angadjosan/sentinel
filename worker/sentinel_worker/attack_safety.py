from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field


DESTRUCTIVE_PATH_MARKERS = frozenset(
    {"logout", "signout", "delete", "remove", "destroy", "drop", "reset", "deactivate"}
)


@dataclass(frozen=True)
class AuthRecipe:
    method: str = "POST"
    path: str = "/login"
    body: dict[str, object] = field(default_factory=dict)
    logged_in_indicator: str | None = None


@dataclass(frozen=True)
class AttackSafety:
    scope: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    exclude_methods: tuple[str, ...] = ("DELETE",)
    max_requests: int = 500
    max_attack_duration_seconds: int = 600
    auth: AuthRecipe | None = None


def parse_attack_safety(raw: dict | None) -> AttackSafety:
    if not raw:
        return AttackSafety()
    defaults = AttackSafety()
    auth_raw = raw.get("auth")
    auth: AuthRecipe | None = None
    if isinstance(auth_raw, dict):
        auth = AuthRecipe(
            method=str(auth_raw.get("method", AuthRecipe.method)),
            path=str(auth_raw.get("path", AuthRecipe.path)),
            body=dict(auth_raw.get("body") or {}),
            logged_in_indicator=auth_raw.get("logged_in_indicator"),
        )
    return AttackSafety(
        scope=tuple(raw.get("scope") or ()),
        exclude_paths=tuple(raw.get("exclude_paths") or ()),
        exclude_methods=tuple(raw.get("exclude_methods") or defaults.exclude_methods),
        max_requests=int(raw.get("max_requests", defaults.max_requests)),
        max_attack_duration_seconds=int(
            raw.get("max_attack_duration_seconds", defaults.max_attack_duration_seconds)
        ),
        auth=auth,
    )


def is_destructive_default(path: str, method: str) -> bool:
    if method.upper() == "DELETE":
        return True
    lowered = path.lower()
    return any(marker in lowered for marker in DESTRUCTIVE_PATH_MARKERS)


def is_in_scope(path: str, safety: AttackSafety) -> bool:
    if any(path.startswith(prefix) for prefix in safety.exclude_paths):
        return False
    if is_destructive_default(path, "GET"):
        return False
    if safety.scope:
        return any(path.startswith(prefix) for prefix in safety.scope)
    return True


def method_allowed(method: str, safety: AttackSafety) -> bool:
    blocked = {m.upper() for m in safety.exclude_methods}
    return method.upper() not in blocked


def is_probe_allowed(
    path: str, method: str, safety: AttackSafety
) -> tuple[bool, str | None]:
    if any(path.startswith(prefix) for prefix in safety.exclude_paths):
        return (False, "excluded_path")
    if is_destructive_default(path, method):
        return (False, "destructive")
    if not method_allowed(method, safety):
        return (False, "method_blocked")
    if safety.scope and not any(path.startswith(prefix) for prefix in safety.scope):
        return (False, "out_of_scope")
    return (True, None)


class AttackBudget:
    def __init__(
        self, safety: AttackSafety, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._safety = safety
        self._clock = clock
        self._start = clock()
        self._count = 0

    def record_request(self) -> None:
        self._count += 1

    def exhausted(self) -> tuple[bool, str | None]:
        if self._count >= self._safety.max_requests:
            return (True, "max_requests")
        if self.elapsed_seconds() >= self._safety.max_attack_duration_seconds:
            return (True, "max_duration")
        return (False, None)

    def remaining_requests(self) -> int:
        return max(0, self._safety.max_requests - self._count)

    def elapsed_seconds(self) -> float:
        return self._clock() - self._start
