"""OAuth 2.0 authorization server for agent delegation.

Endpoints
  POST /consent      the human authorises a top-level agent (stands in for the authorization-code flow)
  POST /token        grant_type=refresh_token | urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693)
  POST /revoke       RFC 7009 token revocation
  POST /introspect   RFC 7662 token introspection
  GET  /statuslist   Token Status List (modelled on draft-ietf-oauth-status-list)
  POST /ssf/register register a push receiver for CAEP session-revoked events (OpenID SSF / RFC 8417 SETs)

Every token exchange creates a new *grant* with its own refresh token. The access token
says who the human is (sub) and who is acting (nested `act`, RFC 8693). In lineage modes
it also carries `dlg`: the ordered list of grant ids from the human's consent down to this agent.
"""
from __future__ import annotations

import base64
import secrets
import threading
import time
import uuid
import zlib
from collections import Counter

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .modes import Mode
from .web import Service, call

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
ISSUER = "https://as.lab.example"
STATUS_LIST_SIZE = 4096


class AuthorizationServer:
    def __init__(self, mode: Mode, access_ttl: float):
        self.mode, self.access_ttl = mode, access_ttl
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.key.public_key()
        self.grants: dict[str, dict] = {}
        self.refresh_tokens: dict[str, str] = {}
        self.bits = bytearray(STATUS_LIST_SIZE // 8)
        self.receivers: list[str] = []
        self.calls = Counter()
        self.lock = threading.RLock()
        self.svc = Service("as")
        self.url = ""
        for (m, p, fn) in [("POST", "/consent", self.consent), ("POST", "/token", self.token),
                           ("POST", "/revoke", self.revoke), ("POST", "/introspect", self.introspect),
                           ("GET", "/statuslist", self.status_list), ("POST", "/ssf/register", self.register)]:
            self.svc.route(m, p)(fn)

    def start(self):
        self.url = self.svc.start()
        return self

    def stop(self):
        self.svc.stop()

    # ------------------------------------------------------------ grants --
    def _new_grant(self, user: str, client: str, scope: list[str], parent: str | None) -> str:
        gid = uuid.uuid4().hex[:12]
        self.grants[gid] = {"user": user, "client": client, "scope": scope, "parent": parent,
                            "revoked": False, "idx": len(self.grants),
                            "children": [], "created": time.time()}
        if parent:
            self.grants[parent]["children"].append(gid)
        return gid

    def lineage(self, gid: str) -> list[str]:
        chain = []
        while gid:
            chain.append(gid)
            gid = self.grants[gid]["parent"]
        return list(reversed(chain))  # root (human consent) first

    def _alive(self, gid: str) -> bool:
        if self.mode.ancestor_check:
            return not any(self.grants[g]["revoked"] for g in self.lineage(gid))
        return not self.grants[gid]["revoked"]

    def _issue(self, gid: str) -> dict:
        g = self.grants[gid]
        chain = self.lineage(gid)
        act = None  # RFC 8693 nested actor chain: current actor outermost
        for anc in chain:
            act = {"sub": self.grants[anc]["client"], **({"act": act} if act else {})}
        now = time.time()
        claims = {"iss": ISSUER, "sub": g["user"], "client_id": g["client"], "scope": " ".join(g["scope"]),
                  "act": act, "gid": gid, "depth": len(chain) - 1,
                  "iat": int(now), "exp": now + self.access_ttl, "jti": uuid.uuid4().hex}
        if self.mode.lineage:
            claims["dlg"] = [{"gid": a, "idx": self.grants[a]["idx"]} for a in chain]
            claims["status"] = {"status_list": {"idx": g["idx"], "uri": f"{self.url}/statuslist"}}
        rt = secrets.token_urlsafe(24)
        self.refresh_tokens[rt] = gid
        return {"access_token": jwt.encode(claims, self.key, algorithm="ES256"), "token_type": "Bearer",
                "expires_in": self.access_ttl, "refresh_token": rt, "grant_id": gid}

    def _decode(self, token: str, verify_exp=True) -> dict:
        return jwt.decode(token, self.public_key, algorithms=["ES256"], options={"verify_exp": verify_exp})

    # ---------------------------------------------------------- endpoints --
    def consent(self, body, _h):
        with self.lock:
            gid = self._new_grant(body["user"], body["client"], body["scope"].split(), None)
            return 200, self._issue(gid)

    def token(self, body, _h):
        with self.lock:
            gt = body.get("grant_type")
            if gt == "refresh_token":
                gid = self.refresh_tokens.get(body.get("refresh_token", ""))
                if not gid or not self._alive(gid):
                    return 400, {"error": "invalid_grant"}
                return 200, self._issue(gid)
            if gt == TOKEN_EXCHANGE:
                try:
                    parent = self._decode(body["subject_token"])
                except jwt.PyJWTError as e:
                    return 400, {"error": "invalid_grant", "detail": str(e)}
                pgid = parent["gid"]
                if not self._alive(pgid):
                    return 400, {"error": "invalid_grant", "detail": "parent grant revoked"}
                want = body.get("scope", parent["scope"]).split()
                if not set(want) <= set(parent["scope"].split()):
                    return 400, {"error": "invalid_scope"}
                gid = self._new_grant(parent["sub"], body["client"], want, pgid)
                return 200, self._issue(gid)
            return 400, {"error": "unsupported_grant_type"}

    def revoke(self, body, _h):
        tok = body.get("token", "")
        with self.lock:
            gid = self.refresh_tokens.get(tok)
            if gid is None:
                try:
                    gid = self._decode(tok, verify_exp=False)["gid"]
                except jwt.PyJWTError:
                    return 200, {}  # RFC 7009: invalid tokens do not cause an error
            targets = [gid]
            if self.mode.as_cascade:
                stack = list(self.grants[gid]["children"])
                while stack:
                    child = stack.pop()
                    targets.append(child)
                    stack.extend(self.grants[child]["children"])
            for g in targets:
                self.grants[g]["revoked"] = True
                idx = self.grants[g]["idx"]
                self.bits[idx // 8] |= 1 << (idx % 8)
        if self.mode.push:
            self._push(gid)
        return 200, {"revoked_grants": len(targets)}

    def introspect(self, body, _h):
        self.calls["introspect"] += 1
        try:
            claims = self._decode(body.get("token", ""))
        except jwt.PyJWTError:
            return 200, {"active": False}
        with self.lock:
            active = not self.grants[claims["gid"]]["revoked"]  # RFC 7662: status of *this* token
        return 200, {"active": active, **({"sub": claims["sub"], "client_id": claims["client_id"]} if active else {})}

    def status_list(self, _b, _h):
        self.calls["statuslist"] += 1
        with self.lock:
            lst = base64.urlsafe_b64encode(zlib.compress(bytes(self.bits))).rstrip(b"=").decode()
        return 200, {"status_list": {"bits": 1, "lst": lst}, "ttl": None}

    def register(self, body, _h):
        self.receivers.append(body["endpoint"])
        return 200, {}

    def _push(self, gid: str):
        set_token = jwt.encode({"iss": ISSUER, "jti": uuid.uuid4().hex, "iat": int(time.time()),
                                "events": {CAEP_SESSION_REVOKED: {
                                    "subject": {"format": "opaque", "id": gid},
                                    "event_timestamp": int(time.time())}}},
                               self.key, algorithm="ES256", headers={"typ": "secevent+jwt"})
        for r in list(self.receivers):
            self.calls["push"] += 1
            call("POST", r, {"set": set_token})


def decode_status_list(payload: dict) -> bytes:
    lst = payload["status_list"]["lst"]
    return zlib.decompress(base64.urlsafe_b64decode(lst + "=" * (-len(lst) % 4)))


def bit_set(bits: bytes, idx: int) -> bool:
    return bool(bits[idx // 8] >> (idx % 8) & 1)
