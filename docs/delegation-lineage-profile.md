# Delegation Lineage Profile (draft, for discussion)

**Status:** an experimental proposal, implemented in this repo. It is not a standard.

## Problem

RFC 8693 token exchange lets an agent obtain a token for a sub-agent. The `act` claim records
*who* acted, but a resource server (RS) can't use it to decide whether any *ancestor* grant has been
revoked. Revocation (RFC 7009) and introspection (RFC 7662) both operate on a single token. So revoking the
root of a delegation tree leaves every descendant valid.

## The `dlg` claim

An access token issued through delegation MUST include `dlg`: a JSON array ordered from the
root (the human's consent) to the grant this token belongs to.

```json
"dlg": [
  { "gid": "<root grant id>",  "idx": 0,  "uri": "https://as-a.example/statuslist" },
  { "gid": "<child grant id>", "idx": 17, "uri": "https://as-b.example/statuslist" }
]
```

| member | meaning |
|---|---|
| `gid` | opaque, issuer-unique grant identifier; used for push-based revocation events |
| `idx` | index of that grant in its issuer's Token Status List |
| `uri` | status list location. MAY be omitted when equal to this token's own `status.status_list.uri` |

The last entry describes the token's own grant. Because each entry carries its own `uri`, the lineage
can span authorization servers.

## Authorization server rules

1. **Exchange.** When minting a token by token exchange, the AS MUST copy the subject token's
   `dlg` and append an entry for the new grant. It MUST refuse the exchange if any entry in the
   subject token's lineage is revoked.
2. **Refresh.** The AS MUST refuse to refresh a grant if any ancestor is revoked.
3. **Revoke.** Revoking a grant MUST set that grant's status bit. It SHOULD emit a CAEP
   `session-revoked` event whose subject is the grant id, to every registered receiver.
4. **Depth.** The AS SHOULD enforce a maximum lineage length, and SHOULD narrow scope at each hop.

## Resource server rules

1. Reject the token if **any** `dlg` entry is revoked, according to:
   * the pushed revocation set (received CAEP events), and
   * the status list at each entry's `uri`, cached no longer than the RS's revocation-latency budget.
2. Record the full `act` chain and `sub` in the audit log for every accepted request.

## Measured effect (this repo)

| | actions accepted after the human revoked | agents still running |
|---|---|---|
| without lineage, introspecting every call | 443 | 4 of 5 |
| with lineage + status list (2s cache) | 3 | 0 |
| with lineage + CAEP push | 0 | 0 |

## Open questions

* Privacy: `dlg` reveals the shape of the delegation tree to every RS. Pairwise or opaque grant ids
  could limit correlation.
* Size: deep chains grow the token. Options are a hash chain with server-side resolution, or a hard depth cap.
* Cross-organisation: the receiving organisation must fetch, and trust, another issuer's status list.
