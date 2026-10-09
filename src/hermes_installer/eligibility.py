"""Fresh, fail-closed provider account eligibility gate.

No authoritative proof of effective account-level processing settings is currently
implemented. Production therefore stays ineligible; synthetic observations are
accepted only by explicitly opted-in test fixtures.
"""
from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass
from typing import Callable

from .policy import PolicyDenied


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class EligibilityEvidence:
    account_id: str
    checked_at: float
    expires_at: float
    free_account: bool
    effective_plugins_disabled: bool
    approved_model: str
    credential_ref_sha256: str
    credential_sha256: str
    policy_snapshot_sha256: str
    evidence_source: str

    @classmethod
    def create(cls, *, account_id: str, checked_at: float, lifetime_seconds: float,
               free_account: bool, effective_plugins_disabled: bool,
               approved_model: str, evidence_source: str, credential_ref: str,
               credential: str, policy_snapshot_sha256: str) -> "EligibilityEvidence":
        if (not isinstance(account_id, str) or not account_id or len(account_id) > 256
                or not isinstance(credential_ref, str) or not credential_ref
                or not isinstance(credential, str) or not credential
                or not isinstance(approved_model, str) or not approved_model
                or not isinstance(evidence_source, str) or not evidence_source
                or not math.isfinite(checked_at) or not math.isfinite(lifetime_seconds)
                or not 1 <= lifetime_seconds <= 900
                or not re.fullmatch(r"[0-9a-f]{64}", policy_snapshot_sha256)):
            raise ValueError("eligibility evidence fields are invalid")
        return cls(account_id, checked_at, checked_at + lifetime_seconds,
                   free_account, effective_plugins_disabled, approved_model,
                   _digest(credential_ref), _digest(credential),
                   policy_snapshot_sha256, evidence_source)


class AccountEligibilityGate:
    """Require fresh, identity-bound proof; synthetic proof is fixture-only."""

    def __init__(self, *, model: str, credential_ref: str,
                 evidence: EligibilityEvidence | None = None,
                 clock: Callable[[], float] = time.time, max_age_seconds: float = 300.0,
                 allow_test_evidence: bool = False):
        if not model or not credential_ref or not callable(clock):
            raise ValueError("model, credential reference and clock are required")
        if not math.isfinite(max_age_seconds) or not 1 <= max_age_seconds <= 900:
            raise ValueError("eligibility evidence age must be bounded")
        self._model = model
        self._credential_ref = credential_ref
        self._credential_ref_sha256 = _digest(credential_ref)
        self._evidence = evidence
        self._clock = clock
        self._max_age = max_age_seconds
        self._allow_test_evidence = allow_test_evidence

    def require_eligible(self, *, model: str, credential_ref: str) -> None:
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
        if (model != self._model or model != proof.approved_model
                or _digest(credential_ref) != self._credential_ref_sha256
                or _digest(credential_ref) != proof.credential_ref_sha256):
            raise PolicyDenied("account.identity_mismatch",
                "Provider eligibility evidence does not match the selected account, key reference or model")
        if proof.evidence_source != "synthetic-test-only" or not self._allow_test_evidence:
            raise PolicyDenied("account.policy_unverified",
                "No authoritative effective account-policy verifier is available")
        if (not proof.account_id or proof.free_account is not True
                or proof.effective_plugins_disabled is not True
                or not re.fullmatch(r"[0-9a-f]{64}", proof.policy_snapshot_sha256)):
            raise PolicyDenied("account.policy_unverified",
                "Provider account or effective processing policy is not eligible")

    def verify_credential(self, credential: str) -> None:
        self.require_eligible(model=self._model, credential_ref=self._credential_ref)
        proof = self._evidence
        if (proof is None or not isinstance(credential, str)
                or _digest(credential) != proof.credential_sha256):
            raise PolicyDenied("account.credential_changed",
                "Resolved provider credential does not match the eligibility snapshot")
