"""Figures and displayed equations for the formal-track report.

Every figure is drawn from a generated artifact; the ones that are schematic
(address map, handler timeline) are drawn from constants of the machine model
and say so in their captions.  Equations are typeset with matplotlib's
mathtext, so no LaTeX installation is needed.
"""
from __future__ import annotations

import hashlib
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt                       # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build")
DPI = 300

STATUS_COLOUR = {
    "proved": "#2e7d32",
    "conditional": "#9ccc65",
    "bounded": "#c0ca33",
    "observed": "#90a4ae",
    "unknown": "#bdbdbd",
    "timeout": "#8d6e63",
    "abstract_counterexample": "#ffb300",
    "refuted": "#c62828",
}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 7, "axes.linewidth": 0.6,
    "mathtext.fontset": "cm", "axes.spines.top": False,
    "axes.spines.right": False,
})


def _save(fig, name):
    os.makedirs(BUILD, exist_ok=True)
    path = os.path.join(BUILD, name + ".png")
    fig.savefig(path, dpi=DPI, bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)
    return path


def equation(tex: str, size: float = 10.5) -> tuple[str, float, float]:
    """Render one mathtext line; returns `(path, width_in, height_in)`."""
    os.makedirs(BUILD, exist_ok=True)
    name = "eq_" + hashlib.sha1(f"{tex}|{size}".encode()).hexdigest()[:12]
    path = os.path.join(BUILD, name + ".png")
    fig = plt.figure(figsize=(0.01, 0.01))
    text = fig.text(0, 0, f"${tex}$", fontsize=size)
    fig.canvas.draw()
    box = text.get_window_extent()
    width, height = box.width / fig.dpi, box.height / fig.dpi
    fig.set_size_inches(width + 0.04, height + 0.06)
    text.set_position((0.02 / (width + 0.04), 0.03 / (height + 0.06)))
    fig.savefig(path, dpi=DPI, transparent=True)
    plt.close(fig)
    return path, width + 0.04, height + 0.06


# ---------------------------------------------------------------- figures

def address_map(instruction_starts: int):
    """The CPU address space as the model sees it (schematic, not to scale)."""
    fig, ax = plt.subplots(figsize=(3.35, 1.35))
    regions = [
        (0.0, 1.1, "RAM\n2 KiB", "#90caf9", "$0000"),
        (1.1, 2.3, "RAM\nmirrors", "#e3f2fd", "$0800"),
        (2.3, 3.6, "PPU\nregisters", "#ffe0b2", "$2000"),
        (3.6, 4.6, "APU,\npads", "#ffcc80", "$4000"),
        (4.6, 6.0, "unmapped\n(open bus)", "#eeeeee", "$4020"),
        (6.0, 10.0, "PRG ROM\n32 KiB, immutable", "#a5d6a7", "$8000"),
    ]
    for low, high, label, colour, _tick in regions:
        ax.add_patch(Rectangle((low, 0), high - low, 1, facecolor=colour,
                               edgecolor="black", linewidth=0.5))
        ax.text((low + high) / 2, 0.5, label, ha="center", va="center",
                fontsize=4.8)
    ax.annotate("", xy=(6.0, -0.55), xytext=(10.0, -0.55),
                arrowprops=dict(arrowstyle="<->", lw=0.7, color="#2e7d32"))
    ax.text(8.0, -0.85, f"P1: every opcode fetch here\n"
            f"|N| = {instruction_starts:,} instruction starts",
            ha="center", va="center", fontsize=5.6, color="#2e7d32")
    ax.annotate("", xy=(0.0, -0.55), xytext=(6.0, -0.55),
                arrowprops=dict(arrowstyle="<->", lw=0.7, color="#c62828"))
    ax.text(3.0, -0.85, "a fetch here violates P1", ha="center",
            va="center", fontsize=5.6, color="#c62828")
    ax.set_xlim(0, 10)
    ax.set_ylim(-1.15, 1.02)
    ax.set_xticks([r[0] for r in regions] + [10.0])
    ax.set_xticklabels([r[4] for r in regions] + ["$FFFF"], fontsize=5.2)
    ax.xaxis.set_ticks_position("top")
    ax.set_yticks([])
    for side in ("left", "bottom", "top"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=2, pad=1)
    return _save(fig, "address_map")


def ledger(counts: dict):
    order = [k for k in STATUS_COLOUR if counts.get(k)]
    fig, ax = plt.subplots(figsize=(3.35, 0.22 * len(order) + 0.45))
    values = [counts[k] for k in order]
    ax.barh(range(len(order)), values,
            color=[STATUS_COLOUR[k] for k in order], edgecolor="black",
            linewidth=0.4)
    for row, value in enumerate(values):
        ax.text(value + max(values) * 0.015, row, str(value), va="center",
                fontsize=6.5)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels([k.replace("_", " ") for k in order])
    ax.invert_yaxis()
    ax.set_xlabel("obligations in the ledger")
    ax.set_xlim(0, max(values) * 1.12)
    return _save(fig, "ledger")


def decomposition(statuses: dict, extra: dict):
    """The dependency structure of P1 with each node's settled status."""
    fig, ax = plt.subplots(figsize=(3.35, 2.9))
    nodes = {
        "P1": (0.5, 0.93, "P1\nevery fetch in ROM"),
        "LOC-DIRECT": (0.10, 0.68, "LOC-DIRECT\nstatic\nsuccessors"),
        "LOC-ASYNC": (0.30, 0.68, "LOC-ASYNC\nvectors"),
        "LOC-DISPATCH": (0.50, 0.68, "LOC-DISPATCH\nJMP ($0006)"),
        "LOC-RETURN": (0.70, 0.68, "LOC-RETURN\nRTS / RTI"),
        "J-ASYNC": (0.90, 0.68, "J-ASYNC\ninterrupts"),
        "LOC-ENGINE": (0.30, 0.41, "LOC-ENGINE\ndispatcher\ncode"),
        "CONTRACTS": (0.50, 0.41, extra["contracts_label"]),
        "INDICES": (0.50, 0.14, extra["indices_label"]),
        "STACK-PAGE-STORES": (0.70, 0.41, "STACK-PAGE-\nSTORES"),
        "J-IRQ": (0.90, 0.41, "J-IRQ\nI flag set"),
    }
    status = dict(statuses)
    status["CONTRACTS"] = extra["contracts_status"]
    status["INDICES"] = extra["indices_status"]
    half_w, half_h = 0.088, 0.075
    edges = [("P1", k) for k in ("LOC-DIRECT", "LOC-ASYNC", "LOC-DISPATCH",
                                 "LOC-RETURN", "J-ASYNC")]
    edges += [("LOC-DISPATCH", "LOC-ENGINE"), ("LOC-DISPATCH", "CONTRACTS"),
              ("CONTRACTS", "INDICES"), ("LOC-RETURN", "STACK-PAGE-STORES"),
              ("J-ASYNC", "J-IRQ")]
    for parent, child in edges:
        x0, y0, _ = nodes[parent]
        x1, y1, _ = nodes[child]
        ax.annotate("", xy=(x1, y1 + half_h + 0.008),
                    xytext=(x0, y0 - half_h - 0.008),
                    arrowprops=dict(arrowstyle="-|>", lw=0.5,
                                    color="#555555", shrinkA=0, shrinkB=0))
    # J-IRQ depends on LOC-RETURN: drawn sideways so it crosses nothing
    ax.annotate("", xy=(0.70 + half_w + 0.006, 0.66),
                xytext=(0.90 - half_w - 0.006, 0.43),
                arrowprops=dict(arrowstyle="-|>", lw=0.5, color="#555555",
                                linestyle="--", shrinkA=0, shrinkB=0))
    for key, (x, y, label) in nodes.items():
        colour = STATUS_COLOUR.get(status.get(key, "unknown"), "#bdbdbd")
        ax.add_patch(FancyBboxPatch((x - half_w, y - half_h), 2 * half_w,
                                    2 * half_h, boxstyle="round,pad=0.004",
                                    facecolor=colour, edgecolor="black",
                                    linewidth=0.5))
        ax.text(x, y, label, ha="center", va="center", fontsize=4.3,
                color="white" if status.get(key) in ("proved", "refuted")
                else "black")
    used = [s for s in STATUS_COLOUR
            if s in {status.get(k, "unknown") for k in nodes}]
    for i, name in enumerate(used):
        ax.add_patch(Rectangle((0.0, 0.20 - i * 0.055), 0.03, 0.035,
                               facecolor=STATUS_COLOUR[name],
                               edgecolor="black", linewidth=0.4))
        ax.text(0.04, 0.217 - i * 0.055, name.replace("_", " "),
                fontsize=4.8, va="center")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(0.0, 1.03)
    ax.axis("off")
    return _save(fig, "decomposition")


def stack_wrap(storm: dict):
    """Stack pointer at each forced NMI entry: 3 bytes per entry, mod 256."""
    fig, ax = plt.subplots(figsize=(3.35, 1.55))
    k = list(range(0, 257))
    predicted = [(0xFF - 3 * i) % 256 for i in k]
    ax.plot(k, predicted, lw=0.6, color="#1565c0",
            label=r"$S_k=(\mathtt{FF}_{16}-3k)\ \mathrm{mod}\ 256$")
    variant = next(v for v in storm["variants"] if v["entries_forced"] == 256)
    pointer = variant["stack_pointer"]
    first = pointer["at_each_entry_first_eight"]
    last = pointer["at_each_entry_last_eight"]
    # entry j (1-based) is taken with the pointer left by j-1 earlier entries
    # the first recorded value is the pointer before the storm; entry j is
    # then taken after j-1 earlier forced entries
    ax.scatter(range(0, len(first) - 1), first[1:], s=5, color="#c62828",
               zorder=3, label="recorded in the trace")
    ax.scatter(range(256 - len(last), 256), last, s=5, color="#c62828",
               zorder=3)
    for wrap in (86, 171):
        ax.axvline(wrap - 0.5, lw=0.4, ls=":", color="#555555")
    ax.text(90, 238, "wrap", fontsize=5.5, ha="left")
    ax.text(175, 238, "wrap", fontsize=5.5, ha="left")
    ax.set_xlabel("NMI entries taken before this one, $k$")
    ax.set_ylabel("stack pointer $S$")
    ax.set_xlim(0, 256)
    ax.set_ylim(0, 262)
    ax.set_yticks([0, 64, 128, 192, 255])
    ax.set_yticklabels(["$00", "$40", "$80", "$C0", "$FF"])
    ax.set_xticks([0, 64, 86, 128, 171, 256])
    ax.legend(fontsize=5.3, frameon=False, loc="lower center", ncol=2,
              bbox_to_anchor=(0.5, 1.02), handlelength=1.2)
    return _save(fig, "stack_wrap")


def storm_outcomes(storm: dict):
    """Outcome of each forced-re-entry variant (entries x warm-up)."""
    entries = sorted({v["entries_forced"] for v in storm["variants"]})
    warmups = sorted({v["warmup_frames"] for v in storm["variants"]})
    colour = {"fetch outside PRG": "#c62828",
              "fetch off the graph inside PRG": "#ef6c00",
              "instruction budget exhausted": "#cfd8dc"}
    fig, ax = plt.subplots(figsize=(3.35, 1.05))
    seen = {}
    for v in storm["variants"]:
        stop = v["outcome"]["stopped"]
        key = stop if stop in colour else (
            "fetch off the graph inside PRG" if "PRG" in stop or "graph" in stop
            else stop)
        seen[key] = colour.get(key, "#7e57c2")
        ax.add_patch(Rectangle((entries.index(v["entries_forced"]),
                                warmups.index(v["warmup_frames"])), 0.92,
                               0.86, facecolor=seen[key], edgecolor="black",
                               linewidth=0.4))
    ax.set_xlim(0, len(entries))
    ax.set_ylim(0, len(warmups))
    ax.set_xticks([i + 0.46 for i in range(len(entries))])
    ax.set_xticklabels(entries, fontsize=5.4)
    ax.set_yticks([i + 0.43 for i in range(len(warmups))])
    ax.set_yticklabels(warmups, fontsize=5.4)
    ax.set_xlabel("forced consecutive NMI entries")
    ax.set_ylabel("warm-up\nframes", fontsize=6)
    ax.tick_params(length=0)
    for side in ("left", "bottom"):
        ax.spines[side].set_visible(False)
    handles = [Rectangle((0, 0), 1, 1, facecolor=c, edgecolor="black",
                         linewidth=0.4) for c in seen.values()]
    labels = [{"instruction budget exhausted":
               "stayed on the graph (200,000 instructions)"}.get(k, k)
              for k in seen]
    ax.legend(handles, labels, fontsize=5.2, frameon=False, ncol=1,
              loc="lower left", bbox_to_anchor=(0.0, 1.0))
    return _save(fig, "storm_outcomes")


def handler_timeline():
    """The NMI handler and the two assumed windows (schematic)."""
    fig, ax = plt.subplots(figsize=(3.35, 1.75))
    segments = [
        (0.0, 1.0, "idle", "#eeeeee"),
        (1.0, 2.2, "prologue", "#ffcc80"),
        (2.2, 7.4, "handler body and game logic", "#e3f2fd"),
        (7.4, 8.6, "exit", "#ffcc80"),
        (8.6, 9.6, "idle", "#eeeeee"),
    ]
    for low, high, label, colour in segments:
        ax.add_patch(Rectangle((low, 0.9), high - low, 0.34, facecolor=colour,
                               edgecolor="black", linewidth=0.5))
        ax.text((low + high) / 2, 1.07, label, ha="center", va="center",
                fontsize=5.2)
    for x, label in ((1.6, "$8082-\n$808C"), (4.8, "includes JSR $8212"),
                     (8.0, "$817E STA\n$8181 RTI")):
        ax.text(x, 0.78, label, ha="center", va="top", fontsize=4.6,
                family="DejaVu Sans Mono")
    ax.plot([0, 2.2, 2.2, 8.0, 8.0, 9.6], [0.32, 0.32, 0.08, 0.08, 0.32,
                                           0.32], lw=0.9, color="#1565c0")
    ax.text(-0.12, 0.32, "1", fontsize=5.5, ha="right", va="center")
    ax.text(-0.12, 0.08, "0", fontsize=5.5, ha="right", va="center")
    ax.text(5.1, 0.19, "ghost NMI-enable bit  $e$", fontsize=5.5,
            ha="center", color="#1565c0")
    ax.annotate("NMI taken", xy=(1.0, 1.24), xytext=(0.55, 1.95), fontsize=5.5,
                ha="center", arrowprops=dict(arrowstyle="-|>", lw=0.6))
    ax.annotate("", xy=(1.0, 1.38), xytext=(2.2, 1.38),
                arrowprops=dict(arrowstyle="<->", lw=0.6, color="#c62828"))
    ax.text(1.25, 1.6, "MA-NMI-EDGE:\nno second NMI", fontsize=5.0,
            va="center", color="#c62828")
    ax.annotate("", xy=(8.0, 1.38), xytext=(8.6, 1.38),
                arrowprops=dict(arrowstyle="<->", lw=0.6, color="#c62828"))
    ax.text(8.7, 1.6, "MA-NMI-LATENCY:\nnone before RTI completes",
            fontsize=5.0, va="center", ha="right", color="#c62828")
    ax.set_xlim(-0.3, 9.7)
    ax.set_ylim(0, 2.05)
    ax.axis("off")
    return _save(fig, "handler_timeline")


def dispatch_sites(observed: dict):
    """Largest index observed at each dispatch site against its table."""
    sites = observed["dispatch_sites"]
    fig, ax = plt.subplots(figsize=(3.35, 1.7))
    xs = range(len(sites))
    ax.bar(xs, [s["table_entries"] for s in sites], color="#e0e0e0",
           edgecolor="black", linewidth=0.4, label="table entries")
    reached = [(i, s) for i, s in enumerate(sites) if s["fetches"]]
    ax.bar([i for i, _ in reached],
           [s["index_max"] + 1 for _, s in reached], color="#1565c0",
           width=0.5, label="largest index observed + 1")
    for i, s in enumerate(sites):
        if not s["fetches"]:
            ax.text(i, s["table_entries"] + 1.5, "never reached",
                    fontsize=4.4, ha="center", va="bottom", rotation=90,
                    color="#c62828")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([s["site"].replace("0x", "$") for s in sites],
                       rotation=90, fontsize=5)
    ax.set_ylabel("entries")
    ax.legend(fontsize=5.3, frameon=False, loc="upper left")
    return _save(fig, "dispatch_sites")


def coverage(tracer: dict, native: dict, total: int):
    fig, ax = plt.subplots(figsize=(3.35, 0.8))
    rows = [("tracer", tracer), ("nes-py", native)]
    for row, (label, data) in enumerate(rows):
        executed = data["graph_nodes_executed"]
        ax.barh(row, executed, color="#1565c0", edgecolor="black",
                linewidth=0.4)
        ax.barh(row, total - executed, left=executed, color="#eeeeee",
                edgecolor="black", linewidth=0.4)
        ax.text(executed / 2, row, f"{executed:,} executed", ha="center",
                va="center", fontsize=5.5, color="white")
        ax.text(executed + (total - executed) / 2, row,
                f"{total - executed:,} never executed", ha="center",
                va="center", fontsize=5.5)
    ax.set_yticks([0, 1])
    ax.set_yticklabels([r[0] for r in rows])
    ax.set_xlim(0, total)
    ax.set_xlabel(f"instruction starts in the recovered graph (|N| = {total:,})")
    return _save(fig, "coverage")
