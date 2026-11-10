"""Terminal + Markdown + JSON reporting."""
from __future__ import annotations

import json
import os

from .harness import ModeResult, Timing

BUCKET = 0.5


def timeline_row(times: list[float], t: Timing) -> str:
    n = int(t.end_at / BUCKET)
    revoke_col = int(t.revoke_at / BUCKET)
    busy = {int(x / BUCKET) for x in times}
    cells = ["█" if i in busy else "·" for i in range(n)]
    cells.insert(revoke_col, "│")
    return "".join(cells)


def fmt_lag(r: ModeResult) -> str:
    if r.still_running:
        return f"never ({len(r.still_running)} agent(s) still running)"
    return f"{r.worst_lag:.2f}s"


def render_mode(r: ModeResult, t: Timing) -> str:
    out = [f"\n■ {r.mode.name}: {r.mode.summary}",
           f"  {'agent':<13}{'depth':>5}  timeline (0→{t.end_at:.0f}s, │ = revoke at {t.revoke_at:.0f}s){'':4}after revoke"]
    for a in r.agents:
        status = (f"{a.zombie_actions:>4} actions, " +
                  ("STILL RUNNING" if not a.stopped else f"stopped (+{(a.last_action_after_revoke or 0):.2f}s)"))
        out.append(f"  {a.name:<13}{a.depth:>5}  {timeline_row(a.timeline, t)}  {status}")
    out.append(f"  → zombie actions: {r.zombie_total} | worst time-to-stop: {fmt_lag(r)} | "
               f"AS round-trips per action: {r.as_calls_per_action:.2f} | push events: {r.as_calls.get('push', 0)}")
    return "\n".join(out)


def scorecard_md(results: list[ModeResult], t: Timing) -> str:
    lines = ["| Mode | Agents still running after revoke | Actions accepted after revoke | Worst time-to-stop | AS round-trips per action |",
             "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| `{r.mode.name}` | {len(r.still_running)} / {len(r.agents)} | {r.zombie_total} | "
                     f"{fmt_lag(r)} | {r.as_calls_per_action:.2f} |")
    lines.append("")
    lines.append(f"_access-token TTL {t.access_ttl}s, status-list cache {t.status_ttl}s, revoke at t={t.revoke_at}s, "
                 f"observed until t={t.end_at}s, each agent acts every {t.interval}s._")
    return "\n".join(lines)


def write(results: list[ModeResult], t: Timing, out_dir: str, timelines: str):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.md"), "w", encoding="utf-8") as f:
        f.write("# Results\n\n" + scorecard_md(results, t) + "\n\n```text" + timelines + "\n```\n")
    data = [{"mode": r.mode.name, "summary": r.mode.summary, "zombie_actions": r.zombie_total,
             "agents_still_running": [a.name for a in r.still_running],
             "worst_time_to_stop_s": r.worst_lag, "as_calls": r.as_calls,
             "as_calls_per_action": round(r.as_calls_per_action, 3),
             "agents": [{k: v for k, v in a.__dict__.items() if k != "timeline"} for a in r.agents]}
            for r in results]
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"timing": t.__dict__, "results": data}, f, indent=2)
