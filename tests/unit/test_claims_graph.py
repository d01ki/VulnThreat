"""Citation graph: reposts, cycles and unknown roots must not inflate independence (DESIGN §9.2)."""

from datetime import datetime, timezone

from tiw.domain.claims import ClaimView, RelationView, independence, mark_inactive

T = datetime(2026, 10, 1, tzinfo=timezone.utc)


def c(cid, origin="secondary", state="unreviewed", value=True, latest=True, key=None):
    return ClaimView(cid, key or cid, "DEMO-VULN-001", "exploited_in_wild", {"value": value}, origin, state, state,
                     "rev-" + cid, latest, "src", "advisory", T, T)


def cites(a, b, verification="explicit"):
    return RelationView(a, b, "cites", verification)


def run(claims, rels):
    mark_inactive(claims, rels)
    return independence(claims, rels)


def test_ten_reposts_of_one_article_are_one_root():
    claims = [c("root")] + [c(f"r{i}") for i in range(10)]
    ind = run(claims, [cites(f"r{i}", "root") for i in range(10)])
    assert ind.report_count == 11
    assert ind.confirmed_root_count == 0
    assert ind.unresolved_source_count == 1


def test_citation_cycle_collapses_to_one_root():
    claims = [c("a"), c("b"), c("x")]
    ind = run(claims, [cites("a", "b"), cites("b", "a"), cites("x", "a")])
    assert ind.unresolved_source_count == 1 and ind.confirmed_root_count == 0
    assert len(ind.root_groups) == 1 and set(ind.root_groups[0]) == {"a", "b"}


def test_known_primary_root_counts_once():
    claims = [c("p", origin="primary"), c("s1"), c("s2")]
    ind = run(claims, [cites("s1", "p"), cites("s2", "p")])
    assert ind.confirmed_root_count == 1 and ind.unresolved_source_count == 0


def test_candidate_relations_are_ignored():
    claims = [c("p", origin="primary"), c("s1")]
    ind = run(claims, [cites("s1", "p", verification="candidate")])
    assert ind.confirmed_root_count == 1 and ind.unresolved_source_count == 1


def test_reposts_of_retracted_report_are_discounted():
    claims = [c("p", origin="primary", state="retracted"), c("s1"), c("s2")]
    ind = run(claims, [cites("s1", "p"), cites("s2", "p")])
    assert ind.report_count == 0
    assert set(ind.derived_from_inactive) == {"s1", "s2"}


def test_citation_of_old_revision_follows_new_revision():
    old = c("old", origin="primary", latest=False, key="k")
    new = c("new", origin="primary", latest=True, key="k")
    ind = run([old, new, c("s")], [cites("s", "old")])
    assert ind.confirmed_root_count == 1 and ind.report_count == 2 and not ind.derived_from_inactive


def test_inactive_reasons():
    claims = [c("a", state="retracted"), c("b", state="rejected"), c("m", origin="model", state="candidate"), c("o", latest=False)]
    mark_inactive(claims, [])
    assert [x.inactive_reason for x in claims] == ["retracted", "rejected by reviewer", "unreviewed candidate", "older revision of the document"]
