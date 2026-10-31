"""Server-side SVG geometry for the thin-line activity chart and the evidence donut.

Lines are straight segments between observed buckets (no smoothing that would invent peaks).
Gap buckets break the line instead of drawing zero.
"""

from __future__ import annotations

import math
from typing import Any

W, H = 720, 240
PAD_L, PAD_R, PAD_T, PAD_B = 40, 12, 12, 28


def _nice_max(v: int) -> int:
    if v <= 4:
        return 4
    mag = 10 ** int(math.floor(math.log10(v)))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return int(math.ceil(m * mag))
    return v


def line_chart(series: dict[str, Any]) -> dict[str, Any]:
    pts = series["points"]
    n = len(pts)
    ymax = _nice_max(series["max"])
    iw, ih = W - PAD_L - PAD_R, H - PAD_T - PAD_B

    def x(i: int) -> float:
        return PAD_L + (iw * (i + 0.5) / n if n else 0)

    def y(v: float) -> float:
        return PAD_T + ih - ih * (v / ymax)

    def paths(key: str) -> list[str]:
        segs: list[list[tuple[float, float]]] = []
        cur: list[tuple[float, float]] = []
        for i, p in enumerate(pts):
            v = p[key]
            if v is None:
                if cur:
                    segs.append(cur)
                cur = []
                continue
            cur.append((round(x(i), 1), round(y(v), 1)))
        if cur:
            segs.append(cur)
        out = []
        for seg in segs:
            if len(seg) == 1:
                (a, b) = seg[0]
                out.append(f"M{a - 2},{b} L{a + 2},{b}")
            else:
                out.append("M" + " L".join(f"{a},{b}" for a, b in seg))
        return out

    grid = [{"y": round(y(v), 1), "label": v} for v in range(0, ymax + 1, max(1, ymax // 4))]
    every = max(1, math.ceil(n / 8))
    xlabels = [{"x": round(x(i), 1), "label": p["label"]} for i, p in enumerate(pts) if i % every == 0]
    gaps = []
    for i, p in enumerate(pts):
        if p["gap"]:
            gaps.append({"x": round(PAD_L + iw * i / n, 1), "w": round(iw / n, 1)})
    markers = {
        key: [
            {"x": round(x(i), 1), "y": round(y(p[key]), 1), "v": p[key], "label": p["label"]}
            for i, p in enumerate(pts)
            if p[key]
        ]
        for key in ("public", "local")
    }
    return {
        "w": W, "h": H, "left": PAD_L, "right": W - PAD_R, "top": PAD_T, "bottom": H - PAD_B,
        "public": paths("public"), "local": paths("local"), "grid": grid, "xlabels": xlabels, "gaps": gaps, "markers": markers,
    }


def donut(items: list[dict[str, Any]], r: int = 54, stroke: int = 14) -> dict[str, Any]:
    total = sum(i["count"] for i in items)
    c = 2 * math.pi * r
    segs = []
    offset = 0.0
    for it in items:
        if not it["count"]:
            continue
        length = c * it["count"] / total
        gap = 2 if len([i for i in items if i["count"]]) > 1 else 0
        segs.append({"status": it["status"], "dash": f"{max(length - gap, 0.5):.2f} {c:.2f}", "offset": f"{-offset:.2f}", "count": it["count"]})
        offset += length
    return {"r": r, "stroke": stroke, "size": 2 * (r + stroke), "c": round(c, 2), "segments": segs, "total": total}
