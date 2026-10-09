"""Fresh, fail-closed provider account eligibility gate.

A free model and zero token prices do not prove that account-level defaults
cannot add processing charges. No proof is available until an authoritative
account-policy verifier exists, so normal construction is deliberately denied.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Callable

from .policy import PolicyDenied


@dataclass(frozen=True, slots=True)
class EligibilityEvidence:
    account_id: str
    checked_at: float
    expires_at: float
    free_account: bool
    effective_plugins_disabled: bool
    approved_model: str
    evidence_source: str

    @classmethod
    def create(cls, *, account_id: str, checked_at: float, lifetime_seconds: float,
               free_account: bool, effective_plugins_disabled: bool,
               approved_model: str, evidence_source: str) -> "EligibilityEvidence":
        if (not account_id or not evidence_source or not approved_model
                or not math.isfinite(checked_at) or not math.isfinite(lifetime_seconds)
                or not 1 <= lifetime_seconds <= 900):
            raise ValueError("eligibility evidence fields are invalid")
        return cls(account_id, checked_at, checked_at + lifetime_seconds,
                   free_account, effective_plugins_disabled, approved_model,
                   evidence_source)


class AccountEligibilityGate:
    """Require fresh proof of a free account and disabled paid processing."""

    def __init__(self, *, model: str, evidence: EligibilityEvidence | None = None,
                 clock: Callable[[], float] = time.time, max_age_seconds: float = 300.0):
        if not model or not callable(clock):
            raise ValueError("model and clock are required")
        if not math.isfinite(max_age_seconds) or not 1 <= max_age_seconds <= 900:
            raise ValueError("eligibility evidence age must be bounded")
        self._model = model
        self._evidence = evidence
        self._clock = clock
        self._max_age = max_age_seconds

    def require_eligible(self) -> None:
        proof = self._evidence
        if proof is None:
            raise PolicyDenied("account.ineligible",
                "No verified fresh zero-charge account policy is available")
        now = self._clock()
        if (not math.isfinite(now) or not math.isfinite(proof.checked_at)
                or not math.isfinite(proof.expires_at) or proof.checked_at > now
                or proof.expires_at <= now or now - proof.checked_at > self._max_age):
            raise PolicyDenied("account.evidence_expired",
                "Provider account-policy evidence is missing or expired")
        if (not proof.account_id or not proof.evidence_source
                or proof.approved_model != self._model
                or proof.free_account is not True
                or proof.effective_plugins_disabled is not True):
            raise PolicyDenied("account.policy_unverified",
                "Provider account or effective processing policy is not eligible")
