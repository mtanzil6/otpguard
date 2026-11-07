"""Combine detector signals into one risk value and an action."""
from __future__ import annotations

from .detectors import CLIENT_SIDE
from .model import Action, Signal
from .policy import Policy


def combine(signals: list[Signal], policy: Policy, purpose: str,
            challenge_passed: bool = False) -> tuple[float, Action, list[Signal], int | None]:
    """Weighted noisy-OR: risk = 1 - prod(1 - w_i * s_i).

    Hard rules (signals with ``force``) set a floor on the action. Returns the risk,
    the action, the signals ordered by how much they contributed, and retry_after."""
    keep = 1.0
    contrib: list[tuple[float, Signal]] = []
    forced = Action.ALLOW
    retry = None
    for s in signals:
        if s.force is not None:
            if s.force.rank > forced.rank:
                forced = s.force
            if s.retry_after:
                retry = max(retry or 0, s.retry_after)
            contrib.append((2.0 + s.score, s))      # hard rules always listed first
            continue
        w = policy.weight(s.detector, purpose)
        if challenge_passed and s.detector in CLIENT_SIDE:
            w *= policy.challenge_relief
        part = w * s.score
        keep *= 1.0 - part
        contrib.append((part, s))
    risk = 1.0 - keep
    if forced is not Action.ALLOW:
        risk = max(risk, 1.0 if forced is Action.BLOCK else policy.challenge_threshold)

    if risk >= policy.block_threshold:
        action = Action.BLOCK
    elif risk >= policy.challenge_threshold:
        action = Action.CHALLENGE
    else:
        action = Action.ALLOW
    if forced.rank > action.rank:
        action = forced
    # a solved challenge clears a challenge, but never a block or a hard rule
    if challenge_passed and action is Action.CHALLENGE and forced is not Action.CHALLENGE:
        action = Action.ALLOW
    if action is Action.CHALLENGE and retry is None:
        retry = 60
    contrib.sort(key=lambda x: -x[0])
    return risk, action, [s for _, s in contrib], retry
