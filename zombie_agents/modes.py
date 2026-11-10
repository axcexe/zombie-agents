"""The five revocation strategies under test.

Each mode is a combination of three choices:
  * what the resource server (RS) checks on every call,
  * whether the authorization server (AS) knows which grant a child grant was derived from,
  * how the news of a revocation reaches the RS.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mode:
    name: str
    summary: str
    # Resource-server validation
    rs_introspect: bool = False      # RFC 7662 call to the AS on every request
    rs_status_list: bool = False     # check every ancestor's bit in a cached Token Status List
    rs_push: bool = False            # reject tokens whose lineage contains a pushed-revoked grant
    # Authorization-server behaviour
    as_cascade: bool = False         # revoking a grant also revokes its whole subtree
    lineage: bool = False            # tokens carry the delegation lineage (`dlg` claim)
    ancestor_check: bool = False     # refresh / token exchange refused if ANY ancestor is revoked
    push: bool = False               # AS pushes a CAEP session-revoked SET to receivers


MODES = [
    Mode("naive-jwt",
         "Today's default: RS validates JWTs locally; RFC 7009 revocation hits only the grant revoked."),
    Mode("introspection",
         "RS introspects every call (RFC 7662), but the AS keeps no parent links between grants.",
         rs_introspect=True),
    Mode("as-cascade",
         "AS links each exchanged grant to its parent and revokes the subtree; RS introspects every call.",
         rs_introspect=True, as_cascade=True),
    Mode("status-list",
         "Tokens carry their delegation lineage; RS checks every ancestor in a cached Token Status List.",
         rs_status_list=True, lineage=True, ancestor_check=True),
    Mode("ssf-push",
         "Tokens carry lineage; AS pushes a CAEP session-revoked event; RS rejects any token descended from it.",
         rs_push=True, lineage=True, ancestor_check=True, push=True),
]

BY_NAME = {m.name: m for m in MODES}
