from __future__ import annotations

from dataclasses import dataclass

from .security import scrub_secrets


SANITIZER_PATTERNS = {
    "heap-buffer-overflow": "ASan heap buffer overflow",
    "use-after-free": "ASan use after free",
    "stack-buffer-overflow": "ASan stack buffer overflow",
    "global-buffer-overflow": "ASan global buffer overflow",
    "ThreadSanitizer: data race": "TSan data race",
    "runtime error:": "UBSan runtime error",
}

BEHAVIORAL_PROOFS = {"data_exfiltrated", "auth_bypassed", "command_executed", "privilege_escalated"}


@dataclass(frozen=True)
class OracleResult:
    confirmed: bool
    kind: str | None
    evidence: str | None


class ConfirmationOracle:
    def evaluate(self, sanitizer_output: str = "", behavioral_proof: str | None = None, proof_detail: str = "") -> OracleResult:
        for needle, label in SANITIZER_PATTERNS.items():
            if needle in sanitizer_output:
                return OracleResult(True, "memory_safety", scrub_secrets(f"{label}\n{sanitizer_output}"))
        if behavioral_proof in BEHAVIORAL_PROOFS:
            return OracleResult(True, "behavioral", scrub_secrets(f"{behavioral_proof}: {proof_detail}"))
        return OracleResult(False, None, None)
