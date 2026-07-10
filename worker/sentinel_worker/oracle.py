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
    def evaluate(
        self,
        sanitizer_output: str = "",
        behavioral_proof: str | None = None,
        proof_detail: str = "",
        *,
        http_evidence: str = "",
    ) -> OracleResult:
        """Confirm a finding only with deterministic runtime proof (AUDIT.md §1 invariant 5).

        A sanitizer crash (ASan/TSan/UBSan) is self-proving. A behavioral proof
        (e.g. `auth_bypassed`) is NOT trusted on the agent's word alone — it must
        be backed by either sanitizer output or an HTTP response captured from the
        target (``http_evidence``). Agent-only self-assertion is rejected.
        """
        for needle, label in SANITIZER_PATTERNS.items():
            if needle in sanitizer_output:
                return OracleResult(True, "memory_safety", scrub_secrets(f"{label}\n{sanitizer_output}"))
        if behavioral_proof in BEHAVIORAL_PROOFS:
            # Require external evidence: an HTTP response from the target or
            # sanitizer output. Free-text proof_detail from the agent is not
            # sufficient by itself.
            if http_evidence.strip():
                return OracleResult(True, "behavioral", scrub_secrets(f"{behavioral_proof}: {proof_detail}\n{http_evidence}".strip()))
            if sanitizer_output.strip():
                return OracleResult(True, "behavioral", scrub_secrets(f"{behavioral_proof}: {proof_detail}\n{sanitizer_output}".strip()))
            return OracleResult(False, None, None)
        return OracleResult(False, None, None)
