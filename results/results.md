# Results

| Mode | Agents still running after revoke | Actions accepted after revoke | Worst time-to-stop | AS round-trips per action |
|---|---|---|---|---|
| `naive-jwt` | 4 / 5 | 461 | never (4 agent(s) still running) | 0.00 |
| `introspection` | 4 / 5 | 443 | never (4 agent(s) still running) | 1.00 |
| `as-cascade` | 0 / 5 | 0 | 0.00s | 1.03 |
| `status-list` | 0 / 5 | 3 | 0.06s | 0.02 |
| `ssf-push` | 0 / 5 | 0 | 0.00s | 0.00 |

_access-token TTL 3.0s, status-list cache 2.0s, revoke at t=4.0s, observed until t=16.0s, each agent acts every 0.1s._

```text
■ naive-jwt: Today's default: RS validates JWTs locally; RFC 7009 revocation hits only the grant revoked.
  agent        depth  timeline (0→16s, │ = revoke at 4s)    after revoke
  orchestrator     0  ████████│███·····················    13 actions, stopped (+1.31s)
  researcher       1  ████████│████████████████████████   112 actions, STILL RUNNING
  coder            1  ████████│████████████████████████   112 actions, STILL RUNNING
  scraper          2  ████████│████████████████████████   112 actions, STILL RUNNING
  browser          3  ████████│████████████████████████   112 actions, STILL RUNNING
  → zombie actions: 461 | worst time-to-stop: never (4 agent(s) still running) | AS round-trips per action: 0.00 | push events: 0

■ introspection: RS introspects every call (RFC 7662), but the AS keeps no parent links between grants.
  agent        depth  timeline (0→16s, │ = revoke at 4s)    after revoke
  orchestrator     0  ████████│························     0 actions, stopped (+0.00s)
  researcher       1  ████████│████████████████████████   111 actions, STILL RUNNING
  coder            1  ████████│████████████████████████   110 actions, STILL RUNNING
  scraper          2  ████████│████████████████████████   111 actions, STILL RUNNING
  browser          3  ████████│████████████████████████   111 actions, STILL RUNNING
  → zombie actions: 443 | worst time-to-stop: never (4 agent(s) still running) | AS round-trips per action: 1.00 | push events: 0

■ as-cascade: AS links each exchanged grant to its parent and revokes the subtree; RS introspects every call.
  agent        depth  timeline (0→16s, │ = revoke at 4s)    after revoke
  orchestrator     0  ████████│························     0 actions, stopped (+0.00s)
  researcher       1  ████████│························     0 actions, stopped (+0.00s)
  coder            1  ████████│························     0 actions, stopped (+0.00s)
  scraper          2  ████████│························     0 actions, stopped (+0.00s)
  browser          3  ████████│························     0 actions, stopped (+0.00s)
  → zombie actions: 0 | worst time-to-stop: 0.00s | AS round-trips per action: 1.03 | push events: 0

■ status-list: Tokens carry their delegation lineage; RS checks every ancestor in a cached Token Status List.
  agent        depth  timeline (0→16s, │ = revoke at 4s)    after revoke
  orchestrator     0  ████████│█·······················     1 actions, stopped (+0.06s)
  researcher       1  ████████│························     0 actions, stopped (+0.00s)
  coder            1  ████████│························     0 actions, stopped (+0.00s)
  scraper          2  ████████│█·······················     1 actions, stopped (+0.03s)
  browser          3  ████████│█·······················     1 actions, stopped (+0.06s)
  → zombie actions: 3 | worst time-to-stop: 0.06s | AS round-trips per action: 0.02 | push events: 0

■ ssf-push: Tokens carry lineage; AS pushes a CAEP session-revoked event; RS rejects any token descended from it.
  agent        depth  timeline (0→16s, │ = revoke at 4s)    after revoke
  orchestrator     0  ████████│························     0 actions, stopped (+0.00s)
  researcher       1  ████████│························     0 actions, stopped (+0.00s)
  coder            1  ████████│························     0 actions, stopped (+0.00s)
  scraper          2  ████████│························     0 actions, stopped (+0.00s)
  browser          3  ████████│························     0 actions, stopped (+0.00s)
  → zombie actions: 0 | worst time-to-stop: 0.00s | AS round-trips per action: 0.00 | push events: 1
```
