from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..enrich import Network, Phone
from ..model import OtpRequest, Signal

if TYPE_CHECKING:
    from ..baselines import Baselines
    from ..policy import Policy
    from ..store.base import Store


@dataclass
class Context:
    req: OtpRequest
    ts: float
    hour_index: int
    phone: Phone
    net: Network | None
    policy: "Policy"
    store: "Store"
    baselines: "Baselines"
    is_new_number: bool = False
    is_new_ip: bool = False
    in_campaign: bool = False
    notes: dict = field(default_factory=dict)

    @property
    def purpose(self) -> str:
        return self.req.purpose

    @property
    def cc(self) -> str:
        return self.phone.region


class Detector:
    id = "D0"
    layer = "L0"
    name = "detector"
    needs_verification = False
    needs_events = False
    needs_ip = False

    def __init__(self, policy: "Policy"):
        self.cfg = policy.det(self.id)

    def active(self, ctx: Context) -> bool:
        p = ctx.policy
        if not p.enabled(self.id):
            return False
        if self.needs_verification and not p.verification_feedback:
            return False
        if self.needs_events and not p.event_feedback:
            return False
        if self.needs_ip and ctx.net is None:
            return False
        return True

    def record(self, ctx: Context) -> None:
        """Update state for this request before any detector evaluates it."""

    def evaluate(self, ctx: Context) -> Signal | None:
        raise NotImplementedError

    def sent(self, ctx: Context) -> None:
        """Called when the OTP is going out (allowed, or shadow mode)."""

    def not_sent(self, ctx: Context) -> None:
        """Called when the OTP is not going out, so reservations can be given back."""

    def signal(self, score: float, detail: str, scope: str = "", **kw) -> Signal:
        return Signal(detector=self.id, score=max(0.0, min(1.0, score)), detail=detail, scope=scope, **kw)


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))
