"""Benchmark the v2 attack-graph engine (pure domain, no database).

Usage:  uv run python scripts/benchmark_v2.py [--repeats 20] [--seed 1]

Cases
  small    the synthetic attack-path demo (exact optimiser), loaded from the fixtures via a temp workspace
  medium   seeded random graph: 100 assets, 500 findings, 4 objectives, 40 candidate actions (greedy optimiser)
  limit    dense graph that must hit the path/expansion limits (truncation must be reported)

Reports p50/p95 wall time and peak Python heap (tracemalloc) per stage. Numbers depend on the
machine; the script prints platform information next to the results. Nothing is invented: if a
stage fails, the error is printed instead of a number.
"""

from __future__ import annotations

import argparse
import platform
import random
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from tiw.domain.attack_graph import (
    Edge,
    EvidenceItem,
    Exploit,
    Fact,
    GraphModel,
    Limits,
    Node,
    Objective,
    enumerate_paths,
)
from tiw.domain.remediation import Action, Constraints, Evaluator, optimize


def _fact(fid: str, rng: random.Random) -> Fact:
    r = rng.random()
    declared = "unknown" if r < 0.1 else "satisfied"
    ev = () if declared == "unknown" else (EvidenceItem(f"rec:{fid}", "topology", "supports", r > 0.15),)
    return Fact(fid, "reachability", fid, declared, ev)


def synthetic(seed: int, n_assets: int, n_findings: int, out_degree: float, limits: Limits) -> tuple[GraphModel, list[Action]]:
    rng = random.Random(seed)
    nodes = {f"a{i:03d}": Node(f"a{i:03d}", "asset", f"a{i:03d}") for i in range(n_assets)}
    nodes["internet"] = Node("internet", "entry_point", "Internet")
    ports = ["tcp/443", "tcp/22", "tcp/8443", "tcp/5432"]
    layers = [list(range(i, n_assets, 5)) for i in range(5)]  # 5 zones, mostly forward edges
    edges: list[Edge] = []
    for i in layers[0]:
        edges.append(Edge(f"ei{i}", "internet", f"a{i:03d}", "network", (rng.choice(ports),), _fact(f"edge:ei{i}", rng)))
    for z in range(4):
        for i in layers[z]:
            for j in rng.sample(layers[z + 1], k=min(len(layers[z + 1]), max(1, int(rng.expovariate(1 / out_degree))))):
                eid = f"e{i}-{j}"
                edges.append(Edge(eid, f"a{i:03d}", f"a{j:03d}", "network", tuple(sorted(rng.sample(ports, 2))), _fact(f"edge:{eid}", rng)))
    exploits = []
    for k in range(n_findings):
        a = rng.randrange(n_assets)
        fid = f"f{k}"
        app = Fact(f"applicability:{fid}", "applicability", fid, "satisfied", (EvidenceItem(f"app:{fid}", "applicability", "supports", True),))
        exploits.append(Exploit(fid, f"a{a:03d}", f"DEMO-VULN-{100 + k}", (rng.choice(ports),), "network_access",
                                rng.choice(["code_execution", "code_execution", "data_access"]), app))
    objectives = [Objective(f"OBJ-{j}", f"a{j:03d}", f"obj{j}", rng.randint(1, 3)) for j in layers[4][:4]]
    actions = [Action(f"A-{x.finding_id}", "patch_finding", x.finding_id, rng.randint(1, 3), finding_id=x.finding_id)
               for x in rng.sample(exploits, 30)]
    actions += [Action(f"R-{e.id}", "restrict_edge", e.id, rng.randint(1, 2), edge_id=e.id) for e in rng.sample(edges, 10)]
    return GraphModel(nodes, edges, exploits, objectives, limits), actions


def timed(fn, repeats: int):
    times = []
    out = None
    tracemalloc.start()
    for _ in range(repeats):
        t0 = time.perf_counter()
        out = fn()
        times.append((time.perf_counter() - t0) * 1000)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    times.sort()
    p95 = times[min(len(times) - 1, int(round(0.95 * (len(times) - 1))))]
    return out, statistics.median(times), p95, peak / 1e6


def demo_model():
    from tiw.services import demo, graph
    from tiw.storage import db

    tmp = Path(tempfile.mkdtemp(prefix="tiw-bench-"))
    ws = db.resolve_workspace(tmp / "ap")
    demo.seed(ws, "attack-path")
    with db.session_scope(ws) as s:
        w = graph.load(s)
    db.dispose_engine(ws)
    return w.model, w.actions, w.now


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    print(f"platform: {platform.platform()} | python {platform.python_version()} | cpu: {platform.processor() or 'n/a'}")
    print(f"repeats={a.repeats} seed={a.seed}\n")
    rows = []

    model, actions, now = demo_model()
    enum, p50, p95, mem = timed(lambda: enumerate_paths(model, at=now), a.repeats)
    rows.append(("small (demo)", "enumerate", len(model.nodes), len(model.exploits), len(enum.paths), enum.truncated, p50, p95, mem))
    res, p50, p95, mem = timed(lambda: optimize(model, enum, actions, Constraints(budget=2)), a.repeats)
    rows.append(("small (demo)", f"optimize {res.method} ({res.evaluated} subsets)", "", "", res.best.weighted_paths, "", p50, p95, mem))

    lim = Limits(max_hops=6, max_paths=2000, max_expansions=200_000)
    m, acts = synthetic(a.seed, 100, 500, 2.0, lim)
    enum, p50, p95, mem = timed(lambda: enumerate_paths(m, at=None), max(3, a.repeats // 4))
    rows.append(("medium", "enumerate", len(m.nodes), len(m.exploits), len(enum.paths), enum.truncated, p50, p95, mem))
    res, p50, p95, mem = timed(lambda: optimize(m, enum, acts, Constraints(budget=10)), max(3, a.repeats // 4))
    before = Evaluator(m, enum, acts, "as_recorded").evaluate(()).weighted_paths
    rows.append(("medium", f"optimize {res.method} ({len(acts)} actions)", "", "", f"{before}->{res.best.weighted_paths}", "", p50, p95, mem))

    m2, _ = synthetic(a.seed + 1, 100, 500, 6.0, Limits(max_hops=8, max_paths=500, max_expansions=50_000))
    enum, p50, p95, mem = timed(lambda: enumerate_paths(m2, at=None), 3)
    rows.append(("limit", "enumerate", len(m2.nodes), len(m2.exploits), len(enum.paths), f"{enum.truncated}: {'; '.join(enum.truncation_reasons)}", p50, p95, mem))

    print(f"{'case':<14} {'stage':<38} {'nodes':>5} {'finds':>5} {'paths/obj':>10} {'truncated':<40} {'p50 ms':>8} {'p95 ms':>8} {'peak MB':>8}")
    for r in rows:
        print(f"{r[0]:<14} {r[1]:<38} {r[2]!s:>5} {r[3]!s:>5} {r[4]!s:>10} {r[5]!s:<40} {r[6]:>8.1f} {r[7]:>8.1f} {r[8]:>8.2f}")


if __name__ == "__main__":
    main()
