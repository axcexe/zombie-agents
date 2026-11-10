# zombie-agents

**You revoke the AI agent. Do its sub-agents stop?**

Agents delegate. An orchestrator hands work to a researcher, which spins up a scraper, which
drives a browser. Each hop is typically an OAuth 2.0 token exchange
([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) that mints a *new* grant for the child.
When the human clicks "revoke" ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)), revocation lands on
**one** grant. Nothing in standard OAuth says it has to travel down the tree.

This repo is a runnable lab that measures what actually happens. It runs a real authorization server,
a resource server, and five autonomous agents across four levels of delegation. Then it compares five
revocation strategies, from today's default to two built on emerging IETF and OpenID standards.

```text
alice ──consent──▶ orchestrator ──exchange──▶ researcher ──exchange──▶ scraper ──exchange──▶ browser
                        └──────────exchange──▶ coder
                 ▲
       t=4s: alice revokes orchestrator
```

## Result

| Mode | Agents still running after revoke | Actions accepted after revoke | Worst time-to-stop | AS round-trips per action |
|---|---|---|---|---|
| `naive-jwt` | **4 / 5** | **461** | **never** | 0.00 |
| `introspection` | **4 / 5** | **443** | **never** | 1.00 |
| `as-cascade` | 0 / 5 | 0 | 0.00s | 1.03 |
| `status-list` | 0 / 5 | 3 | 0.06s *(bounded by cache TTL, 2s)* | 0.02 |
| `ssf-push` | 0 / 5 | 0 | 0.00s | 0.00 |

```text
■ naive-jwt: Today's default: RS validates JWTs locally; RFC 7009 revocation hits only the grant revoked.
  agent        depth  timeline (0→16s, │ = revoke at 4s)    after revoke
  orchestrator     0  ████████│███·····················    13 actions, stopped (+1.31s)
  researcher       1  ████████│████████████████████████   112 actions, STILL RUNNING
  coder            1  ████████│████████████████████████   112 actions, STILL RUNNING
  scraper          2  ████████│████████████████████████   112 actions, STILL RUNNING
  browser          3  ████████│████████████████████████   112 actions, STILL RUNNING

■ introspection: RS introspects every call (RFC 7662), but the AS keeps no parent links between grants.
  orchestrator     0  ████████│························     0 actions, stopped (+0.00s)
  researcher       1  ████████│████████████████████████   111 actions, STILL RUNNING
  ...
```

**The headline finding:** "strict" validation doesn't help. Introspecting every single request
(`introspection`) stops the agent you revoked *instantly*, and every sub-agent keeps going forever.
The resource server asks the right question about the wrong token. The problem isn't how fresh the
revocation check is. It's that **revocation is a tree operation, and OAuth tokens are leaves that
don't know their ancestors.**

In this lab the sub-agents survive indefinitely because each one holds its own refresh token. They
are long-running agents, so they're built to recover from expiry. Even an AS that issues *no* refresh
tokens on exchange leaves children alive until their access tokens expire, which in production
is commonly 5 to 60 minutes of agent activity after the human said stop.

## The five strategies

| Mode | What the RS checks | What the AS knows | How revocation travels |
|---|---|---|---|
| `naive-jwt` | signature + `exp`, locally | nothing about parents | it doesn't |
| `introspection` | RFC 7662 call per request | nothing about parents | only to the token revoked |
| `as-cascade` | RFC 7662 call per request | parent→child links | AS revokes the whole subtree |
| `status-list` | every ancestor in the token's `dlg` lineage, against a cached [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) | parent→child links | RS pulls a compressed bitstring every *TTL* seconds |
| `ssf-push` | every ancestor in `dlg`, against a pushed revocation set | parent→child links | AS pushes a [CAEP](https://openid.net/specs/openid-caep-1_0.html) `session-revoked` SET ([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)) |

### Trade-offs

* **`as-cascade` works, at a price.** One AS round-trip on *every* API call, and it only works when every
  grant in the chain was issued by the **same** AS. The moment an agent exchanges a token at a different
  organisation's AS, the chain is broken.
* **`status-list` scales.** RS load is one small fetch per cache period (0.02 calls per action here), and
  it works across issuers, because each lineage entry can point at its own issuer's status list. The cost is a
  revocation delay bounded by the cache TTL.
* **`ssf-push` is the fastest and cheapest**, but needs a push channel to every relying party (OpenID Shared
  Signals Framework). It also needs a pull-based fallback (`status-list`) for receivers that were offline when the event fired.
* **Production answer: lineage + push + status-list fallback.** The lineage claim is what makes the other two possible.

## The missing piece: delegation lineage in the token

The two modes that work across issuers rely on one addition to the access token: an ordered list of every grant
the token descends from, each with a pointer to where its revocation status lives.

```json
{
  "sub": "alice",
  "client_id": "browser",
  "act": { "sub": "browser", "act": { "sub": "scraper", "act": { "sub": "researcher", "act": { "sub": "orchestrator" }}}},
  "dlg": [
    { "gid": "9f1c…", "idx": 0 },
    { "gid": "a71e…", "idx": 1 },
    { "gid": "c03b…", "idx": 3 },
    { "gid": "e55d…", "idx": 4 }
  ],
  "status": { "status_list": { "idx": 4, "uri": "https://as.example/statuslist" } }
}
```

`act` (RFC 8693) says *who* acted. It doesn't give the RS anything it can check for revocation.
`dlg` closes that gap. See [docs/delegation-lineage-profile.md](docs/delegation-lineage-profile.md)
for the proposed claim profile, the AS rules, and the RS rules.

A side effect is accountability (problem #4 on most agent-security lists). Every accepted action carries the full chain, so a
fourth-level sub-agent's action is still attributable to a human:

```text
Audit sample: action 'browser-step' on behalf of alice via orchestrator → researcher → scraper → browser
```

## Run it

Docker:

```bash
docker build -t zombie-agents .
docker run --rm zombie-agents
```

Or with Python 3.10+:

```bash
pip install -r requirements.txt
python -m zombie_agents --check
```

* `--mode naive-jwt --mode ssf-push` runs a subset.
* `--check` exits non-zero if any claim in this README stops holding (CI runs it on every push).
* Results are written to `results/results.md` and `results/results.json`.
* Timing knobs (`access_ttl`, `status_ttl`, `revoke_at`, `end_at`) are in `zombie_agents/harness.py`.

A full run takes about 80 seconds: 16 seconds of real time per mode. Nothing is simulated with sleeps or
fake clocks. Every action is a real HTTP request with a real ES256-signed JWT.

## Code map

```text
zombie_agents/
  modes.py            the five strategies as feature flags
  authz_server.py     OAuth AS: consent, refresh, RFC 8693 exchange, RFC 7009 revoke,
                      RFC 7662 introspect, status list, SSF/CAEP push
  resource_server.py  API under protection; validation per mode; audit log with actor chain
  agent.py            autonomous agent loop that auto-refreshes (that's what makes zombies)
  harness.py          builds the delegation tree, revokes at t=4s, measures
  report.py           timelines, scorecard, JSON
docs/delegation-lineage-profile.md   proposed token profile
```

## Limitations and honest caveats

* **"Naive" models a common pattern, not a named product.** Some authorization servers may already link
  exchanged grants to their parents. If yours does, `as-cascade` is your baseline. Please open an issue with specifics.
* The status list is served as plain JSON with the draft's `{bits, lst}` encoding (zlib + base64url). The draft
  wraps it in a signed JWT or CWT. Signing it adds no new behaviour to measure here.
* One AS and one RS. The cross-issuer argument for lineage is reasoned, not yet demonstrated. A two-AS federation
  scenario is the obvious next experiment.
* `dlg` grows with delegation depth. A real profile should cap depth (which is a useful policy in its own right) or
  use a hash chain.

## Related open problems

This lab targets *revocation doesn't reach the end of a delegation chain*. The same lineage claim is a
building block for neighbouring problems that remain open:
* one accountable owner for thousands of short-lived sub-agents
* agent tasks that outlast tokens and consent
* trust between agents from different organisations (federated status lists)

## License

MIT
