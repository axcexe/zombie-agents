"""An autonomous agent: works in a loop and keeps itself authorised for as long as the AS lets it.

That last part is the important behaviour. A well-built agent framework refreshes expired
tokens automatically, because long-running tasks have to survive token expiry.
That same resilience is what lets a sub-agent outlive the human's revocation.
"""
from __future__ import annotations

import threading
import time

from .authz_server import TOKEN_EXCHANGE
from .web import call


class Agent(threading.Thread):
    def __init__(self, name: str, depth: int, as_url: str, rs_url: str, clock, interval: float):
        super().__init__(daemon=True, name=name)
        self.agent_name, self.depth = name, depth
        self.as_url, self.rs_url, self.clock, self.interval = as_url, rs_url, clock, interval
        self.access = self.refresh = None
        self.stop_flag = threading.Event()
        self.stopped_at: float | None = None
        self.stop_reason = "still running"
        self.refreshes = 0

    # credentials ------------------------------------------------------------
    def authorise_by_human(self, user: str, scope: str):
        _, tok = call("POST", f"{self.as_url}/consent", {"user": user, "client": self.agent_name, "scope": scope})
        self.access, self.refresh = tok["access_token"], tok["refresh_token"]
        return tok

    def delegate_to(self, child: "Agent", scope: str):
        """RFC 8693 token exchange: the child gets its own grant derived from this agent's token."""
        status, tok = call("POST", f"{self.as_url}/token", {"grant_type": TOKEN_EXCHANGE,
                                                             "subject_token": self.access,
                                                             "client": child.agent_name, "scope": scope})
        if status != 200:
            raise RuntimeError(f"delegation failed: {tok}")
        child.access, child.refresh = tok["access_token"], tok["refresh_token"]

    def _refresh(self) -> bool:
        status, tok = call("POST", f"{self.as_url}/token", {"grant_type": "refresh_token",
                                                             "refresh_token": self.refresh})
        if status == 200:
            self.access, self.refreshes = tok["access_token"], self.refreshes + 1
            return True
        return False

    # work loop ----------------------------------------------------------------
    def run(self):
        while not self.stop_flag.is_set():
            status, body = call("POST", f"{self.rs_url}/action", {"op": f"{self.agent_name}-step"}, bearer=self.access)
            if status == 401:
                if not self._refresh():
                    self.stopped_at = self.clock()
                    self.stop_reason = f"refresh refused after RS said '{body.get('reason')}'"
                    return
            time.sleep(self.interval)
