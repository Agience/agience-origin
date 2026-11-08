"""A root that lost a part opens for its own principal alone, for good (reviews 29 and 30).

Revision ID: 0029_root_part_removed
Revises: 0028_share_stored_by

Additive. `authority_nodes.part_removed_seq` is the entry that last removed a node under a root,
and `confirmed_empty_seq` the operator's confirmation (`root.confirm_empty`) that nothing is left
under the root's master key. The upgrade fills `part_removed_seq` from the ledger's own past
removals: each creation edge an `edge.remove` entry took away, or an `edge.add` demoted to
secondary containment (review 30), is charged to the root its source sat under at that entry, the
ledger walked in order exactly as `authority_ledger.replay` walks it (review 31), so a removal made
before this migration refuses as one made after it and `verify_chain` agrees with the tables. A
withdrawal (a compensating entry) charges nothing. A charged root stays charged;
`confirmed_empty_seq` is kept only for an older Origin's `root.confirm_empty`, which opens nothing.
"""
import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0029_root_part_removed"
down_revision: Union[str, None] = "0028_share_stored_by"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("authority_nodes") as batch:
        batch.add_column(sa.Column("part_removed_seq", sa.Integer, nullable=True))
        batch.add_column(sa.Column("confirmed_empty_seq", sa.Integer, nullable=True))
    conn = op.get_bind()
    for root, seq in charges(conn.execute(sa.text(
            "SELECT seq, body, bootstrap, compensates FROM authority_ledger "
            "ORDER BY seq")).fetchall()).items():
        conn.execute(sa.text("UPDATE authority_nodes SET part_removed_seq = :s "
                             "WHERE node_id = :n"), {"s": seq, "n": root})


def charges(rows) -> dict:
    """`{root: seq}` as `authority_ledger.replay` charges them (review 31): the ledger walked in
    order, each removal (or demotion) of a creation edge charged to the root its source sat under
    at that entry, a withdrawal (a compensating entry) charging nothing, and a node charged only
    while the replay holds it. Self-contained, so the fill does not move with the app's code."""
    edges: dict = {}                 # (src, dst) -> origin
    nodes: set = set()
    charged: dict = {}

    def root_of(node):
        seen = {node}
        while True:
            parents = sorted(s for (s, d), origin in edges.items() if d == node and origin)
            if not parents or not parents[0] or parents[0] in seen:
                return node
            node = parents[0]
            seen.add(node)

    def charge(src, seq):
        root = root_of(src)
        if root in nodes:
            charged[root] = int(seq)

    for seq, body, bootstrap, compensates in rows:
        b = json.loads(body)
        kind = b.get("kind")
        if kind == "grant":
            if bootstrap:
                nodes.add(b.get("resource_id"))
        elif kind == "edge.add":
            key = (b.get("src"), b.get("dst"))
            if edges.get(key) and not b.get("origin") and compensates is None:
                # A creation edge demoted to secondary containment deleted its member just as a
                # removal does (review 30, F1): charged the same way.
                charge(key[0], seq)
            edges[key] = bool(b.get("origin"))
            if bootstrap:
                nodes.update(key)
            elif b.get("origin"):
                nodes.add(key[1])
        elif kind == "edge.remove":
            key = (b.get("src"), b.get("dst"))
            if key in edges:
                was = edges.pop(key)
                if was and compensates is None:
                    charge(key[0], seq)
        elif kind in ("root.confirm_empty", "drop_key", "job_grant"):
            continue
        elif kind == "root.retire":
            nodes.discard(b.get("principal_id"))
            charged.pop(b.get("principal_id"), None)
        else:
            nodes.add(b.get("principal_id"))
    return {r: s for r, s in charged.items() if r in nodes}


def downgrade() -> None:
    with op.batch_alter_table("authority_nodes") as batch:
        batch.drop_column("confirmed_empty_seq")
        batch.drop_column("part_removed_seq")
