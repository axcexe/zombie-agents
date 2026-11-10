"""Resource server: the API the agents act on (think: CRM, repo, mailbox).

POST /action      perform one action with a Bearer access token
POST /ssf/events  receive CAEP session-revoked SETs (push modes)

It logs every *accepted* action with the full actor chain, so the audit trail can
answer "which human is accountable for this sub-sub-agent's action?"
"""
from __future__ import annotations

import threading
import time

import jwt

from .authz_server import CAEP_SESSION_REVOKED, bit_set, decode_status_list
from .modes import Mode
from .web import Service, call


class ResourceServer:
    def __init__(self, mode: Mode, as_url: str, as_public_key, clock, status_ttl: float):
        self.mode, self.as_url, self.as_key, self.clock = mode, as_url, as_public_key, clock
        self.status_ttl = status_ttl
        self.accepted: list[dict] = []
        self.revoked_grants: set[str] = set()
        self._status: tuple[float, bytes] | None = None
        self.lock = threading.Lock()
        self.svc = Service("rs")
        self.svc.route("POST", "/action")(self.action)
        self.svc.route("POST", "/ssf/events")(self.ssf_event)
        self.url = ""

    def start(self):
        self.url = self.svc.start()
        return self

    def stop(self):
        self.svc.stop()

    def _status_bits(self) -> bytes:
        with self.lock:
            now = time.monotonic()
            if self._status is None or now - self._status[0] >= self.status_ttl:
                _, payload = call("GET", f"{self.as_url}/statuslist")
                self._status = (now, decode_status_list(payload))
            return self._status[1]

    def action(self, body, headers):
        authz = headers.get("Authorization", "")
        if not authz.startswith("Bearer "):
            return 401, {"error": "invalid_token"}
        token = authz[7:]
        try:
            claims = jwt.decode(token, self.as_key, algorithms=["ES256"])
        except jwt.ExpiredSignatureError:
            return 401, {"error": "invalid_token", "reason": "expired"}
        except jwt.PyJWTError:
            return 401, {"error": "invalid_token", "reason": "bad_token"}

        if self.mode.rs_introspect:
            _, r = call("POST", f"{self.as_url}/introspect", {"token": token})
            if not r.get("active"):
                return 401, {"error": "invalid_token", "reason": "revoked"}
        if self.mode.rs_status_list:
            bits = self._status_bits()
            if any(bit_set(bits, d["idx"]) for d in claims.get("dlg", [])):
                return 401, {"error": "invalid_token", "reason": "revoked"}
        if self.mode.rs_push:
            with self.lock:
                if any(d["gid"] in self.revoked_grants for d in claims.get("dlg", [])):
                    return 401, {"error": "invalid_token", "reason": "revoked"}

        chain, a = [], claims.get("act")
        while a:
            chain.append(a["sub"])
            a = a.get("act")
        entry = {"t": self.clock(), "client": claims["client_id"], "depth": claims["depth"],
                 "on_behalf_of": claims["sub"], "actor_chain": chain, "op": body.get("op")}
        with self.lock:
            self.accepted.append(entry)
        return 200, {"ok": True}

    def ssf_event(self, body, _h):
        try:
            set_claims = jwt.decode(body["set"], self.as_key, algorithms=["ES256"])
        except jwt.PyJWTError:
            return 400, {"error": "invalid SET"}
        ev = set_claims.get("events", {}).get(CAEP_SESSION_REVOKED)
        if ev:
            with self.lock:
                self.revoked_grants.add(ev["subject"]["id"])
        return 202, {}
