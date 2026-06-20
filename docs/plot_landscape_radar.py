#!/usr/bin/env python3
"""Render docs/img/landscape-radar.png — a qualitative positioning radar.

Axes are the three the 2025 survey uses (Lee, Park, Lee & Choi, FSI:DI 55, 2025,
Fig. 8): **Throughput**, **Coverage**, **Anti-Forensic resilience**. The survey
plots the three *technique families* (metadata-based, carving-based, WAL-based);
this chart overlays **sqlite4n6**, which spans all three families plus the
rollback journal.

HONESTY: the per-technique values are QUALITATIVE positioning after the survey's
heuristic Fig. 8 (the paper itself states those values are "not empirically
measured ... heuristically assigned"), NOT measured metrics. The one
*measured*-anchored point is sqlite4n6's Throughput: medium, ~15.3 s to carve a
100 MB database (slower than a metadata-only scan, comparable to the carving
tools) — see the Throughput section of competitive-landscape.md. Coverage and
Anti-Forensic are "high" because sqlite4n6 reads metadata + carves + applies the
WAL overlay + recovers the rollback journal, and recovers post-secure_delete via
WAL/journal. Re-run this script to refresh the PNG.
"""

import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
PNG_PATH = HERE / "img" / "landscape-radar.png"

AXES = ["Throughput", "Coverage", "Anti-Forensic\nresilience"]

# (label, colour, [throughput, coverage, anti-forensic]) on a 0..1 qualitative scale.
SERIES = [
    ("Metadata-based", "#7570b3", [0.90, 0.85, 0.20]),
    ("Carving-based", "#d62728", [0.45, 0.90, 0.50]),
    ("WAL-based", "#e6840f", [0.35, 0.40, 0.90]),
    ("sqlite4n6 (all + journal)", "#1b9e8a", [0.50, 0.95, 0.90]),
]


def main() -> None:
    n = len(AXES)
    # Close the polygon by repeating the first angle/value.
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6.4, 6.0), subplot_kw={"polar": True})
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(AXES, fontsize=11)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["", "", "", ""])
    ax.set_rlabel_position(0)
    ax.grid(True, alpha=0.35)

    for label, colour, vals in SERIES:
        v = vals + vals[:1]
        emphasis = label.startswith("sqlite4n6")
        ax.plot(
            angles,
            v,
            color=colour,
            linewidth=2.6 if emphasis else 1.6,
            label=label,
            zorder=5 if emphasis else 3,
        )
        ax.fill(angles, v, color=colour, alpha=0.18 if emphasis else 0.06, zorder=2)

    fig.suptitle(
        "SQLite recovery technique positioning\n(qualitative, after survey Fig. 8)",
        fontsize=11,
        x=0.42,
        y=1.04,
    )
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.10), fontsize=9, frameon=False)
    fig.tight_layout()
    PNG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(PNG_PATH, dpi=150, bbox_inches="tight")
    print(f"wrote {PNG_PATH}")


if __name__ == "__main__":
    main()
