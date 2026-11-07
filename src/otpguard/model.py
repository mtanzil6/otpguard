from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {"allow": 0, "challenge": 1, "block": 2}[self.value]


@dataclass
class OtpRequest:
    """One request to send an OTP. Only ``phone`` and ``purpose`` are required."""

    phone: str
    purpose: str
    timestamp: float | None = None      # unix seconds; defaults to now
    is_resend: bool = False
    ip: str | None = None
    session_id: str | None = None
    session_age_ms: int | None = None
    device_id: str | None = None
    attestation: str | None = None       # "passed", "failed" or None
    user_id: str | None = None
    challenge_passed: bool = False
    request_id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def ts(self) -> float:
        return self.timestamp if self.timestamp is not None else time.time()


@dataclass
class Signal:
    """What a detector reports for one request."""

    detector: str
    score: float                         # 0..1
    detail: str
    scope: str = ""                      # e.g. "country:OM" — used to group alerts
    force: Action | None = None          # hard rule: forces at least this action
    retry_after: int | None = None


@dataclass
class Decision:
    request_id: str
    action: Action                       # what the policy decided
    risk: float
    reasons: list[Signal]
    enforced: bool                       # False in shadow mode
    policy_version: str
    retry_after: int | None = None
    phone_hash: str = ""
    country: str = ""

    @property
    def allowed(self) -> bool:
        """True if the caller should go ahead and send the SMS."""
        return (not self.enforced) or self.action is Action.ALLOW

    def to_dict(self, include_reasons: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "request_id": self.request_id,
            "action": self.action.value,
            "allowed": self.allowed,
            "enforced": self.enforced,
            "risk": round(self.risk, 4),
            "retry_after": self.retry_after,
            "policy_version": self.policy_version,
        }
        if include_reasons:
            d["reasons"] = [
                {"detector": s.detector, "score": round(s.score, 3), "detail": s.detail}
                for s in self.reasons
            ]
        return d


def new_request_id() -> str:
    return uuid.uuid4().hex
