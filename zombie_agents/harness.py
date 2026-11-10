"""Runs one scenario per revocation mode and measures what happens after the human revokes.

Scenario
  t=0       alice consents: `orchestrator` may act for her.
            orchestrator delegates (RFC 8693 token exchange) to `researcher` and `coder`;
            researcher delegates to `scraper`; scraper delegates to `browser`.
            Every agent then works in a loop, refreshing tokens when they expire.
  t=REVOKE  alice revokes orchestrator's grant (RFC 7009). That's the "kill switch" every
            consent screen and incident runbook relies on.
  t=END     stop and measure every action the resource server ACCEPTED after the revocation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .agent import Agent
from .authz_server import AuthorizationServer
from .modes import Mode
from .resource_server import ResourceServer
from .web import call

TREE = [  # (agent, parent, scope)
    ("orchestrator", None, "crm:read crm:write repo:write"),
    ("researcher", "orchestrator", "crm:read"),
    ("coder", "orchestrator", "repo:write"),
    ("scraper", "researcher", "crm:read"),
    ("browser", "scraper", "crm:read"),
]


@dataclass
class Timing:
    access_ttl: float = 3.0     # access-token lifetime (production values are typically 5-60 min)
    status_ttl: float = 2.0     # how long the RS caches the status list
    revoke_at: float = 4.0
    end_at: float = 16.0
    interval: float = 0.1       # each agent acts 10x per second


@dataclass
class AgentResult:
    name: str
    depth: int
    actions_before: int
    zombie_actions: int
    last_action_after_revoke: float | None
    stopped: bool
    stop_reason: str
    refreshes: int
    timeline: list[float] = field(default_factory=list)


@dataclass
class ModeResult:
    mode: Mode
    agents: list[AgentResult]
    as_calls: dict
    accepted_total: int
    audit_example: dict | None

    @property
    def zombie_total(self):
        return sum(a.zombie_actions for a in self.agents)

    @property
    def still_running(self):
        return [a for a in self.agents if not a.stopped]

    @property
    def worst_lag(self):
        if self.still_running:
            return None
        return max((a.last_action_after_revoke or 0.0) for a in self.agents)

    @property
    def as_calls_per_action(self):
        return (self.as_calls.get("introspect", 0) + self.as_calls.get("statuslist", 0)) / max(self.accepted_total, 1)


def run_mode(mode: Mode, t: Timing, user: str = "alice") -> ModeResult:
    start = time.monotonic()
    clock = lambda: time.monotonic() - start  # noqa: E731

    authz = AuthorizationServer(mode, t.access_ttl).start()
    rs = ResourceServer(mode, authz.url, authz.public_key, clock, t.status_ttl).start()
    if mode.push:
        call("POST", f"{authz.url}/ssf/register", {"endpoint": f"{rs.url}/ssf/events"})

    agents: dict[str, Agent] = {}
    depth: dict[str, int] = {}
    root_refresh = None
    for name, parent, scope in TREE:
        depth[name] = 0 if parent is None else depth[parent] + 1
        a = Agent(name, depth[name], authz.url, rs.url, clock, t.interval)
        if parent is None:
            root_refresh = a.authorise_by_human(user, scope)["refresh_token"]
        else:
            agents[parent].delegate_to(a, scope)
        agents[name] = a
    for a in agents.values():
        a.start()

    time.sleep(max(0.0, t.revoke_at - clock()))
    revoke_time = clock()
    call("POST", f"{authz.url}/revoke", {"token": root_refresh, "token_type_hint": "refresh_token"})

    time.sleep(max(0.0, t.end_at - clock()))
    for a in agents.values():
        a.stop_flag.set()
    for a in agents.values():
        a.join(timeout=2)
    rs.stop()
    authz.stop()

    results = []
    for name, a in agents.items():
        times = [e["t"] for e in rs.accepted if e["client"] == name]
        after = [x for x in times if x > revoke_time]
        results.append(AgentResult(
            name=name, depth=a.depth,
            actions_before=len(times) - len(after), zombie_actions=len(after),
            last_action_after_revoke=(max(after) - revoke_time) if after else None,
            stopped=a.stopped_at is not None, stop_reason=a.stop_reason, refreshes=a.refreshes,
            timeline=times))
    deepest = [e for e in rs.accepted if e["t"] <= revoke_time]
    deepest.sort(key=lambda e: (e["depth"], e["t"]))
    return ModeResult(mode, results, dict(authz.calls), len(rs.accepted), deepest[-1] if deepest else None)
