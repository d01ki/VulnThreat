"""Claim views, effective review state and the explicit citation graph (DESIGN §9.2, §9.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

CITATION_KINDS = ("cites", "duplicates")
TRUSTED_VERIFICATION = ("explicit", "reviewer_confirmed")
KNOWN_ROOT_ORIGINS = ("primary", "vendor", "kev")


@dataclass
class ClaimView:
    id: str
    key: str
    subject_id: str
    predicate: str
    value: dict[str, Any]
    origin: str
    initial_state: str
    effective_state: str
    revision_id: str
    revision_is_latest: bool
    source_name: str
    source_kind: str
    published_at: datetime | None
    fetched_at: datetime
    quote: str | None = None
    locator: str | None = None
    superseded_by: list[str] = field(default_factory=list)
    inactive_reason: str | None = None

    @property
    def positive(self) -> bool:
        return self.predicate == "exploited_in_wild" and self.value.get("value") is True

    @property
    def negative(self) -> bool:
        return self.predicate == "exploited_in_wild" and self.value.get("value") is False

    @property
    def evidence_time(self) -> datetime:
        return self.published_at or self.fetched_at


@dataclass(frozen=True)
class RelationView:
    from_id: str
    to_id: str
    kind: str
    verification: str


def mark_inactive(claims: list[ClaimView], relations: list[RelationView]) -> None:
    """Set inactive_reason for retracted, rejected, candidate, superseded or outdated claims."""
    by_id = {c.id: c for c in claims}
    for r in relations:
        if r.kind == "supersedes" and r.verification in TRUSTED_VERIFICATION and r.to_id in by_id:
            by_id[r.to_id].superseded_by.append(r.from_id)
    for c in claims:
        if c.effective_state == "retracted":
            c.inactive_reason = "retracted"
        elif c.effective_state == "rejected":
            c.inactive_reason = "rejected by reviewer"
        elif c.effective_state == "candidate":
            c.inactive_reason = "unreviewed candidate"
        elif c.superseded_by:
            c.inactive_reason = "superseded"
        elif not c.revision_is_latest:
            c.inactive_reason = "older revision of the document"


def _scc(nodes: list[str], edges: dict[str, set[str]]) -> dict[str, int]:
    """Tarjan's strongly connected components (iterative). Returns node -> component id."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    comp: dict[str, int] = {}
    counter = 0
    next_comp = 0
    for root in nodes:
        if root in index:
            continue
        work: list[tuple[str, list[str]]] = [(root, sorted(edges.get(root, ())))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, children = work[-1]
            if children:
                child = children.pop()
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, sorted(edges.get(child, ()))))
                elif child in on_stack:
                    low[node] = min(low[node], index[child])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp[w] = next_comp
                    if w == node:
                        break
                next_comp += 1
    return comp


@dataclass
class Independence:
    report_count: int
    confirmed_root_count: int
    unresolved_source_count: int
    root_groups: list[list[str]]
    derived_from_inactive: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_count": self.report_count,
            "confirmed_root_count": self.confirmed_root_count,
            "unresolved_source_count": self.unresolved_source_count,
            "root_groups": self.root_groups,
            "derived_from_inactive": self.derived_from_inactive,
        }


def independence(claims: list[ClaimView], relations: list[RelationView]) -> Independence:
    """Group positive reports by their citation roots.

    Only explicit or reviewer-confirmed cites/duplicates edges are used. Citation cycles are
    collapsed into one strongly connected component so they cannot inflate the root count.
    A root whose origin is unknown (e.g. a secondary article that cites nothing) is reported
    as unresolved and never counted as an independent confirmation.
    Active reports whose every citation path ends at inactive (retracted/rejected) roots are
    returned in ``derived_from_inactive``.
    """
    claims = [c for c in claims if c.predicate == "exploited_in_wild"]
    by_id = {c.id: c for c in claims}
    latest_by_key = {c.key: c.id for c in claims if c.revision_is_latest}

    def redirect(target: str) -> str:
        # A citation of an older document revision or a superseded claim follows the replacement.
        seen = set()
        while target in by_id and target not in seen:
            seen.add(target)
            t = by_id[target]
            if t.inactive_reason == "older revision of the document" and t.key in latest_by_key:
                target = latest_by_key[t.key]
            elif t.inactive_reason == "superseded" and t.superseded_by:
                target = sorted(t.superseded_by)[0]
            else:
                break
        return target

    edges: dict[str, set[str]] = {}
    for r in relations:
        if r.kind in CITATION_KINDS and r.verification in TRUSTED_VERIFICATION:
            to = redirect(r.to_id)
            if r.from_id in by_id and to in by_id and to != r.from_id:
                edges.setdefault(r.from_id, set()).add(to)
    nodes = sorted(by_id)
    comp = _scc(nodes, edges)
    comp_edges: dict[int, set[int]] = {}
    members: dict[int, list[str]] = {}
    for n in nodes:
        members.setdefault(comp[n], []).append(n)
        for m in edges.get(n, ()):
            if comp[m] != comp[n]:
                comp_edges.setdefault(comp[n], set()).add(comp[m])

    def sinks(start: int) -> set[int]:
        seen, out, todo = {start}, set(), [start]
        while todo:
            c = todo.pop()
            nxt = comp_edges.get(c, set())
            if not nxt:
                out.add(c)
            for x in nxt:
                if x not in seen:
                    seen.add(x)
                    todo.append(x)
        return out

    positives = [c for c in claims if c.positive and c.inactive_reason is None]
    derived_inactive: list[str] = []
    root_comps: set[int] = set()
    for c in positives:
        roots = sinks(comp[c.id])
        live_roots = {
            r for r in roots if any(by_id[m].inactive_reason is None and by_id[m].positive for m in members[r])
        }
        if edges.get(c.id) and not live_roots:
            derived_inactive.append(c.id)
            continue
        root_comps.update(live_roots)
    confirmed = 0
    unresolved = 0
    groups: list[list[str]] = []
    for rc in sorted(root_comps):
        live_members = [m for m in members[rc] if by_id[m].inactive_reason is None]
        groups.append(sorted(live_members))
        if any(by_id[m].origin in KNOWN_ROOT_ORIGINS for m in live_members):
            confirmed += 1
        else:
            unresolved += 1
    return Independence(
        report_count=len(positives) - len(derived_inactive),
        confirmed_root_count=confirmed,
        unresolved_source_count=unresolved,
        root_groups=groups,
        derived_from_inactive=sorted(derived_inactive),
    )
