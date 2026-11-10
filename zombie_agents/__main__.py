"""python -m zombie_agents [--mode NAME ...] [--check] [--out results]"""
from __future__ import annotations

import argparse
import sys

from . import report
from .harness import Timing, run_mode
from .modes import BY_NAME, MODES


def check(results, t: Timing) -> list[str]:
    """The claims the README makes. Each one must hold on every run."""
    r = {x.mode.name: x for x in results}
    fails = []

    def expect(cond, msg):
        if not cond:
            fails.append(msg)

    for name in ("naive-jwt", "introspection"):
        if name in r:
            expect(len(r[name].still_running) > 0, f"{name}: expected sub-agents to survive revocation")
            expect(any(a.name == "orchestrator" and a.stopped for a in r[name].agents),
                   f"{name}: the directly revoked agent should stop")
    if "as-cascade" in r:
        expect(not r["as-cascade"].still_running and r["as-cascade"].worst_lag <= 0.5,
               "as-cascade: every agent should stop within 0.5s")
    if "status-list" in r:
        expect(not r["status-list"].still_running and r["status-list"].worst_lag <= t.status_ttl + 0.5,
               f"status-list: every agent should stop within the cache TTL ({t.status_ttl}s) + 0.5s")
        expect(r["status-list"].as_calls_per_action < 0.1, "status-list: AS load should be far below 1 call/action")
    if "ssf-push" in r:
        expect(not r["ssf-push"].still_running and r["ssf-push"].worst_lag <= 0.5,
               "ssf-push: every agent should stop within 0.5s")
        expect(r["ssf-push"].as_calls_per_action == 0, "ssf-push: no per-request AS calls expected")
    return fails


def main():
    ap = argparse.ArgumentParser(description="Does revoking an AI agent stop its sub-agents?")
    ap.add_argument("--mode", action="append", choices=list(BY_NAME), help="run only these modes")
    ap.add_argument("--check", action="store_true", help="exit non-zero if a documented claim does not hold")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()

    t = Timing()
    modes = [BY_NAME[m] for m in a.mode] if a.mode else MODES
    print(f"Delegation tree: alice → orchestrator → {{researcher → scraper → browser, coder}}\n"
          f"alice revokes orchestrator at t={t.revoke_at:.0f}s. Who keeps working?")
    results, blocks = [], []
    for m in modes:
        res = run_mode(m, t)
        block = report.render_mode(res, t)
        print(block, flush=True)
        results.append(res)
        blocks.append(block)

    print("\n" + report.scorecard_md(results, t))
    ex = next((r.audit_example for r in results if r.audit_example), None)
    if ex:
        print(f"\nAudit sample (deepest agent): action '{ex['op']}' on behalf of {ex['on_behalf_of']} via "
              + " → ".join(reversed(ex["actor_chain"])))
    report.write(results, t, a.out, "\n".join(blocks))
    if a.check:
        fails = check(results, t)
        print("\nCHECK:", "all claims hold" if not fails else "FAILED")
        for f in fails:
            print("  ✗", f)
        sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
