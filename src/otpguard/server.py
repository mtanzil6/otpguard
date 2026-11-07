"""HTTP service for apps that aren't written in Python. Needs ``otpguard[server]``.

    OTPGUARD_POLICY=policy.yaml OTPGUARD_REDIS=redis://localhost:6379/0 otpguard serve
"""
from __future__ import annotations

import os
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .model import OtpRequest
from .policy import Policy
from .sentinel import Sentinel


class CheckBody(BaseModel):
    phone: str
    purpose: str
    is_resend: bool = False
    ip: str | None = None
    session_id: str | None = None
    session_age_ms: int | None = None
    device_id: str | None = None
    attestation: str | None = None
    user_id: str | None = None
    challenge_passed: bool = False
    timestamp: float | None = None


class SentBody(BaseModel):
    request_id: str
    cost: float | None = None


class VerifiedBody(BaseModel):
    request_id: str


class EventBody(BaseModel):
    kind: str
    timestamp: float | None = None
    phone: str | None = None


def create_app(sentinel: Sentinel | None = None, show_reasons: bool = False) -> FastAPI:
    if sentinel is None:
        path = os.environ.get("OTPGUARD_POLICY")
        if path:
            sentinel = Sentinel.from_config(path, redis_url=os.environ.get("OTPGUARD_REDIS"),
                                            sql_url=os.environ.get("OTPGUARD_SQL"),
                                            asn_tsv=os.environ.get("OTPGUARD_ASN_TSV"))
        else:
            sentinel = Sentinel(Policy())
    app = FastAPI(title="otpguard", version="0.1.0")
    app.state.sentinel = sentinel

    @app.get("/health")
    def health():
        ok = sentinel.store.ping()
        return {"ok": ok, "policy": sentinel.policy.version, "mode": sentinel.policy.mode}

    @app.post("/v1/check")
    def check(body: CheckBody):
        d = sentinel.check(OtpRequest(**body.model_dump()))
        # reasons go to your logs, not to the client, unless you ask for them
        return d.to_dict(include_reasons=show_reasons)

    @app.post("/v1/sent")
    def sent(body: SentBody):
        sentinel.report_sent(body.request_id, body.cost)
        return {"ok": True}

    @app.post("/v1/verified")
    def verified(body: VerifiedBody):
        if not sentinel.report_verified(body.request_id, time.time()):
            raise HTTPException(404, "unknown or expired request_id")
        return {"ok": True}

    @app.post("/v1/event")
    def event(body: EventBody):
        sentinel.report_event(body.kind, body.timestamp or time.time(), body.phone)
        return {"ok": True}

    return app
