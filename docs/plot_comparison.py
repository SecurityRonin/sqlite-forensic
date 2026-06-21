#!/usr/bin/env python3
"""Render docs/img/recovery-comparison.png from docs/img/comparison_metrics.csv.

The CSV is emitted by ``forensic/tests/nemetz_tool_comparison.rs`` (the
``emit_three_tool_comparison`` test, run with the undark/fqlite oracles set), so
every number plotted here is the harness's computed value — never hand-typed.
Re-run that test to refresh the CSV, then re-run this script to refresh the PNG.

Three panels:
  1. Precision-Recall plane with constant-F1 iso-contours and an ideal star.
  2. F1 grouped bars (category x 3 tools).
  3. F0.5 grouped bars (precision-weighted forensic beta).
"""

import csv
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
CSV_PATH = HERE / "img" / "comparison_metrics.csv"
PNG_PATH = HERE / "img" / "recovery-comparison.png"

# Tool -> colour (ours teal, fqlite orange, undark red); category -> marker.
TOOL_COLOR = {"ours": "#1b9e8a", "fqlite": "#e6840f", "undark": "#d62728"}
TOOL_ORDER = ["ours", "fqlite", "undark"]
CAT_MARKER = {"0C": "o", "0D": "s", "0E": "^"}
CAT_ORDER = ["0C", "0D", "0E"]


def load(path):
    """Return rows[(cat, tool)] -> {recall, precision, f1, f0_5}."""
    rows = {}
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            rows[(r["category"], r["tool"])] = {
                "recall": float(r["recall_substrate"]),
                "precision": float(r["precision"]),
                "f1": float(r["f1"]),
                "f0_5": float(r["f0_5"]),
            }
    return rows


def panel_pr(ax, rows):
    """Precision-recall plane with constant-F1 iso-contours."""
    ax.set_title("Precision-Recall (substrate recall)", fontsize=11)
    ax.set_xlabel("recall (substrate)")
    ax.set_ylabel("precision")
    ax.set_xlim(0, 1.02)
    ax.set_ylim(0, 1.02)
    ax.set_aspect("equal")

    # Constant-F1 iso-contours: F1 = 2PR/(P+R) -> P = F*R / (2R - F).
    recall_grid = np.linspace(0.001, 1.0, 400)
    for f in (0.2, 0.4, 0.6, 0.8):
        denom = 2 * recall_grid - f
        precision_iso = np.where(denom > 0, f * recall_grid / denom, np.nan)
        precision_iso = np.where(
            (precision_iso >= 0) & (precision_iso <= 1.0), precision_iso, np.nan
        )
        ax.plot(recall_grid, precision_iso, ls=":", lw=0.8, color="#9e9e9e", zorder=1)
        # Label each iso-contour near the top of the plane.
        valid = np.where(~np.isnan(precision_iso))[0]
        if len(valid):
            idx = valid[np.argmin(np.abs(precision_iso[valid] - 0.97))]
            ax.annotate(
                f"F1={f:g}",
                (recall_grid[idx], precision_iso[idx]),
                fontsize=7,
                color="#7a7a7a",
                ha="left",
                va="bottom",
            )

    # Ideal corner.
    ax.scatter(
        [1.0], [1.0], marker="*", s=220, color="#444444", zorder=4, label="ideal (1,1)"
    )

    for (cat, tool), m in rows.items():
        if tool not in TOOL_COLOR:  # headline P/R chart plots the 3 full-recall tools
            continue
        ax.scatter(
            m["recall"],
            m["precision"],
            marker=CAT_MARKER[cat],
            s=90,
            color=TOOL_COLOR[tool],
            edgecolors="white",
            linewidths=0.6,
            zorder=3,
        )

    # Two legends: tool (colour) and category (marker).
    tool_handles = [
        plt.Line2D(
            [], [], marker="o", ls="", color=TOOL_COLOR[t], markersize=9, label=t
        )
        for t in TOOL_ORDER
    ]
    cat_handles = [
        plt.Line2D(
            [],
            [],
            marker=CAT_MARKER[c],
            ls="",
            color="#444444",
            markersize=9,
            label=c,
        )
        for c in CAT_ORDER
    ]
    ideal_handle = plt.Line2D(
        [], [], marker="*", ls="", color="#444444", markersize=13, label="ideal (1,1)"
    )
    leg1 = ax.legend(
        handles=tool_handles, title="tool", loc="lower left", fontsize=8, title_fontsize=8
    )
    ax.add_artist(leg1)
    ax.legend(
        handles=cat_handles + [ideal_handle],
        title="category",
        loc="lower right",
        fontsize=8,
        title_fontsize=8,
    )


def grouped_bars(ax, rows, metric, title):
    """Grouped bars: category on x, one bar per tool, with value labels."""
    ax.set_title(title, fontsize=11)
    ax.set_ylabel(metric.upper().replace("_", "."))
    # Headroom above 1.0 so full-height (1.000) bars and their value labels never
    # collide with the top spine.
    ax.set_ylim(0, 1.12)
    x = np.arange(len(CAT_ORDER))
    width = 0.26
    for i, tool in enumerate(TOOL_ORDER):
        vals = [rows[(cat, tool)][metric] for cat in CAT_ORDER]
        bars = ax.bar(
            x + (i - 1) * width,
            vals,
            width,
            color=TOOL_COLOR[tool],
            label=tool,
            edgecolor="white",
            linewidth=0.5,
        )
        for b, v in zip(bars, vals):
            ax.annotate(
                f"{v:.3f}",
                (b.get_x() + b.get_width() / 2, v),
                xytext=(0, 2),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=6.5,
            )
    ax.set_xticks(x)
    ax.set_xticklabels(CAT_ORDER)
    ax.set_xlabel("category")
    # Legend BELOW the axis (horizontal): the upper area is full of 1.000 bars
    # (ours/fqlite on 0D, ours on 0E), so an in-plot legend would overlap them.
    ax.legend(
        fontsize=8,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.13),
        ncol=len(TOOL_ORDER),
        frameon=False,
    )


def main():
    rows = load(CSV_PATH)
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.8))
    panel_pr(axes[0], rows)
    grouped_bars(axes[1], rows, "f1", "F1 (balanced)")
    grouped_bars(axes[2], rows, "f0_5", "F0.5 (precision-weighted)")
    fig.suptitle(
        "Deleted-record recovery on the Nemetz corpus — ours vs undark vs fqlite "
        "(0C/0D/0E, harness-computed)",
        fontsize=12,
    )
    fig.tight_layout(rect=(0, 0.07, 1, 0.96))
    fig.savefig(PNG_PATH, dpi=130)
    print(f"wrote {PNG_PATH}")


if __name__ == "__main__":
    main()
