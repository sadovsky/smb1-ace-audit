"""What the observation runs did not execute, broken down by routine.

Graph coverage on its own ("59% of 10,708 instruction starts") says nothing
about *what* is unobserved, and the honest answer to "is the rest dead code?"
is that this module cannot tell you: everything here is an **observation** over
the inputs that were run, and a node that was never executed is simply
unobserved.  What it can do is attribute the unexecuted nodes to the routine
they belong to and say how that routine is entered, which turns one percentage
into a list a reader can check against the game.

Routines.  A routine entry is an instruction start with an incoming `call`,
`dispatch` or `interrupt` edge, plus the three hardware vectors and the
JumpEngine itself.  Every other node is attributed to the nearest entry by a
multi-source breadth-first search over the edges that stay inside a routine
(`fallthrough`, `branch`, `jump`, `return_point`); `call` and `dispatch` edges
are not followed, so a callee's nodes are not attributed to its caller.  A node
no entry reaches that way is reported as unattributed rather than guessed at.

Reasons.  Each unexecuted routine is given a reason, and **every reason is an
interpretation, not a measurement**; the JSON marks them as such.  They are
derived from the graph and the coverage set alone:

``entry-not-executed``        the entry was never fetched, so nothing in the
                              routine was: the feature it implements was not
                              triggered by these inputs.
``dispatch-only``             every incoming edge is a `dispatch` edge from a
                              site that was never fetched.
``brk-only``                  every incoming edge comes from the IRQ/BRK
                              vector; the image executes no `BRK` in normal
                              play.
``partially-executed``        the entry ran and some nodes did not: a branch,
                              an area type, an enemy identifier or an error
                              path inside a routine that did run.
``overlapping-start``         the address is an interior byte of another
                              instruction that *was* executed, i.e. the
                              graph's data-as-code decoding, not a routine the
                              processor can enter by itself.
``unattributed``              no entry reaches it over intra-routine edges.

    python3 -m formal.dyn.coverage_gaps \\
        --coverage formal/results/reports/dyn_coverage_extended.json \\
                   formal/results/reports/dyn_coverage_extended_nespy.json \\
        --out formal/results/reports/dyn_coverage_gaps.json
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os

DISPATCH = 0x8E04
BODY_EDGES = frozenset({"fallthrough", "branch", "jump", "return_point"})
ENTRY_EDGES = frozenset({"call", "dispatch", "interrupt"})


def expand(runs: list) -> set[int]:
    """Undo `formal.dyn.observe.ranges`."""
    out: set[int] = set()
    for item in runs:
        if isinstance(item, list):
            out.update(range(item[0], item[1] + 1))
        else:
            out.add(int(item))
    return out


def load_coverage(paths: list[str]) -> tuple[dict, set[int]]:
    per_file = {}
    union: set[int] = set()
    for path in paths:
        with open(path) as handle:
            payload = json.load(handle)
        executed = expand(payload["executed_instruction_starts"])
        per_file[os.path.basename(path)] = {
            "engine": payload["manifest"].get("engine"),
            "frames_total": payload["manifest"].get("frames_total"),
            "instructions_total": payload["manifest"].get(
                "instructions_total"),
            "graph_nodes_executed": len(executed),
            "executed_not_an_instruction_start": payload.get(
                "executed_not_an_instruction_start", []),
            "input_models": payload["manifest"].get("input_models"),
        }
        union |= executed
    return per_file, union


def routines(cfg) -> tuple[dict[int, int], list[int]]:
    """Attribute every instruction start to the nearest routine entry."""
    incoming: dict[int, set[str]] = collections.defaultdict(set)
    for node in cfg.nodes.values():
        for source, kind in node.predecessors:
            incoming[node.address].add(kind)
    entries = {address for address, kinds in incoming.items()
               if kinds & ENTRY_EDGES}
    entries.add(DISPATCH)
    for vector in (0xFFFA, 0xFFFC, 0xFFFE):
        target = cfg.read_byte(vector) | cfg.read_byte(vector + 1) << 8
        if target in cfg.nodes:
            entries.add(target)
    owner: dict[int, int] = {}
    queue = collections.deque()
    for entry in sorted(entries):
        owner[entry] = entry
        queue.append(entry)
    while queue:
        address = queue.popleft()
        for target, kind in cfg.nodes[address].successors:
            if kind in BODY_EDGES and target in cfg.nodes \
                    and target not in owner:
                owner[target] = owner[address]
                queue.append(target)
    return owner, sorted(entries)


def classify(cfg, owner, entries, executed) -> dict:
    incoming: dict[int, list[tuple[int, str]]] = {
        address: list(node.predecessors)
        for address, node in cfg.nodes.items()}
    overlapping = cfg.overlapping_starts()
    members: dict[int, list[int]] = collections.defaultdict(list)
    for address, entry in owner.items():
        members[entry].append(address)
    unattributed = sorted(set(cfg.nodes) - set(owner))

    fetched_dispatch_sites = {site for site in cfg.dispatches
                              if site in executed}
    rows = []
    for entry in entries:
        body = sorted(members.get(entry, []))
        missing = [address for address in body if address not in executed]
        if not missing:
            continue
        kinds = {kind for _, kind in incoming.get(entry, [])}
        sources = sorted({source for source, _ in incoming.get(entry, [])})
        if entry in executed:
            reason = "partially-executed"
        elif kinds and kinds <= {"dispatch"}:
            unfetched = sorted(site for site in sources
                               if site not in fetched_dispatch_sites)
            reason = "dispatch-only" if unfetched else "entry-not-executed"
        elif kinds and kinds <= {"interrupt"}:
            reason = "brk-only"
        else:
            reason = "entry-not-executed"
        rows.append({
            "routine_entry": f"0x{entry:04X}",
            "nodes": len(body),
            "nodes_executed": len(body) - len(missing),
            "nodes_not_executed": len(missing),
            "entry_executed": entry in executed,
            "entered_by": sorted(kinds),
            "callers": [f"0x{source:04X}" for source in sources[:8]],
            "callers_truncated": len(sources) > 8,
            "reason_interpretation": reason,
        })
    rows.sort(key=lambda row: (-row["nodes_not_executed"],
                               row["routine_entry"]))

    overlap_only = sorted(
        address for address in cfg.nodes
        if address not in executed and address in overlapping
        and any(container in executed for container in overlapping[address]))

    by_reason = collections.Counter()
    for row in rows:
        by_reason[row["reason_interpretation"]] += row["nodes_not_executed"]
    return {
        "routines_with_unexecuted_nodes": rows,
        "unexecuted_nodes_by_reason_interpretation": dict(by_reason),
        "unattributed_nodes": [f"0x{a:04X}" for a in unattributed],
        "unexecuted_overlapping_starts_inside_executed_instructions": [
            f"0x{a:04X}" for a in overlap_only],
        "unexecuted_overlapping_starts_count": len(overlap_only),
    }


def dispatch_report(cfg, executed) -> dict:
    sites = []
    for site, info in sorted(cfg.dispatches.items()):
        sites.append({
            "site": f"0x{site:04X}",
            "site_fetched": site in executed,
            "table_entries": len(info.entries),
            "distinct_entry_addresses": len(set(info.entries)),
            "entry_addresses_executed": len(
                {entry for entry in info.entries if entry in executed}),
            "entry_addresses_never_executed": [
                f"0x{entry:04X}" for entry in sorted(set(info.entries))
                if entry not in executed],
        })
    return {
        "sites": sites,
        "sites_fetched": sum(1 for row in sites if row["site_fetched"]),
        "sites_never_fetched": [row["site"] for row in sites
                                if not row["site_fetched"]],
    }


def replay_manifests(directory: str) -> list[dict]:
    out = []
    for path in sorted(glob.glob(os.path.join(directory, "play_*.json"))):
        try:
            with open(path) as handle:
                manifest = json.load(handle)["manifest"]
        except (OSError, ValueError, KeyError):
            continue
        manifest.pop("events", None)
        manifest.pop("stages", None)
        manifest["file"] = os.path.basename(path)
        out.append(manifest)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage", nargs="+", required=True)
    parser.add_argument("--out", default=None)
    parser.add_argument("--replays", default=os.path.expanduser(
        "~/big/smb1-formal/replays"))
    parser.add_argument("--baseline", default=None,
                        help="an earlier observation report, for before/after")
    args = parser.parse_args(argv)

    from analysis.cfg import build_from_vectors
    from rom import b, image

    from .crossvalidate import git_commit

    cfg = build_from_vectors(b)
    starts = cfg.instruction_starts
    per_file, executed = load_coverage(args.coverage)
    executed &= starts
    owner, entries = routines(cfg)

    baseline = None
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline) as handle:
            older = json.load(handle)
        baseline = older.get("fetched_program_counters", {})

    report = {
        "experiment": "formal.dyn.coverage_gaps",
        "status": "observed",
        "manifest": {
            "rom_sha1": image().sha1,
            "repository_commit": git_commit(),
            "coverage_inputs": per_file,
            "replays": replay_manifests(args.replays),
        },
        "coverage": {
            "graph_instruction_starts": len(starts),
            "graph_nodes_executed": len(executed),
            "graph_nodes_not_executed": len(starts) - len(executed),
            "graph_coverage": round(len(executed) / len(starts), 6),
            "routine_entries": len(entries),
            "routine_entries_executed": sum(1 for entry in entries
                                            if entry in executed),
            "baseline_for_comparison": ({
                "graph_nodes_executed": baseline.get("graph_nodes_executed"),
                "graph_coverage": baseline.get("graph_coverage"),
            } if baseline else None),
        },
        "dispatch_sites": dispatch_report(cfg, executed),
        **classify(cfg, owner, entries, executed),
        "limitations": [
            "observed over the inputs that were run; no bound follows from "
            "any of it, and a node that was not executed is unobserved, not "
            "unreachable",
            "every value of reason_interpretation is this module's reading of "
            "the graph and the coverage set, not a measurement",
            "routine attribution is a nearest-entry breadth-first search over "
            "intra-routine edges; a routine with several entry points is "
            "reported as several routines",
        ],
    }
    print(json.dumps(report["coverage"], indent=2))
    print(json.dumps(report["unexecuted_nodes_by_reason_interpretation"],
                     indent=2))
    print("dispatch sites never fetched: "
          + (", ".join(report["dispatch_sites"]["sites_never_fetched"])
             or "none"))
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
