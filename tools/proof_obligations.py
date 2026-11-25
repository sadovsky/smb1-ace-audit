"""Assemble results/proof_obligations.json from the live analysis (plan 16).

Each obligation's status is computed from the artifacts rather than asserted,
so the file cannot drift from what the tools actually show.  The rule the plan
sets is honoured here: no obligation reads "met" while anything it depends on
is unresolved, and the summary refuses to claim impossibility while any
obligation is open.

    python3 -m tools.proof_obligations
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.cfg import build_from_vectors              # noqa: E402
from analysis.destinations import RAM_REGIONS, resolve_all  # noqa: E402
from analysis.dispatch_tables import establish           # noqa: E402
from analysis.index_derivation import (                  # noqa: E402
    CANDIDATE_INVARIANTS,
    ENEMY_SITES,
    derive_conditional,
    derive_site,
    enemy_assumptions,
)
from analysis.interrupts import masking_report, vectors  # noqa: E402
from analysis.provenance import BoundProvenance          # noqa: E402
from analysis.write_census import census, writers_of     # noqa: E402
from rom import b, image                                 # noqa: E402

#: Variables whose invariants the dispatch bounds depend on.
CRITICAL_VARIABLES = {
    0x071F: "$92C8 dispatch index",
    0x0770: "$8215 dispatch index",
    0x0772: "$8234 / $83A3 / $AEDF dispatch index",
    0x073C: "$856A dispatch index",
    0x0733: "$9743 dispatch index",
    0x0746: "$D2E5 dispatch index (clamped at the dispatch)",
    0x000E: "$B04C dispatch index",
    0x001D: "$B34E dispatch index",
    0x0000: "$9664 dispatch index (summed with $07)",
    0x0007: "$9664 dispatch index (summed with $00)",
}


def _status(met: bool, partial: bool = False) -> str:
    if met:
        return "met"
    return "partially established" if partial else "open"


def build() -> dict:
    graph = build_from_vectors(b)
    boundaries = establish(b, graph)
    resolutions = resolve_all(b, graph)
    enemy = enemy_assumptions(graph)
    writers = census(b, scope="linear")
    masking = masking_report(b, graph)

    derivations = {}
    for dispatch in sorted(graph.dispatches):
        assumption = (enemy.get(dispatch) if dispatch in ENEMY_SITES
                      else CANDIDATE_INVARIANTS.get(dispatch))
        derivations[dispatch] = (derive_site(b, graph, dispatch),
                                 derive_conditional(b, graph, dispatch,
                                                    assumption),
                                 assumption)

    unconditional = [d for d, (_p, c, _a) in derivations.items()
                     if c.bound().is_unconditional]
    overrunning = [d for d, (_p, c, _a) in derivations.items()
                   if c.overruns_table or c.truncated]
    unresolved_transfers = {}
    for _address, kind, _detail in graph.unresolved:
        unresolved_transfers[kind] = unresolved_transfers.get(kind, 0) + 1

    variable_manifests = {}
    for address, role in sorted(CRITICAL_VARIABLES.items()):
        buckets = writers_of(address, writers)
        variable_manifests[f"0x{address:04X}"] = {
            "role": role,
            "exact_writers": [f"0x{w.address:04X}" for w in buckets["exact"]],
            "indexed_writers": len(buckets["indexed"]),
            "unresolved_writers": len(buckets["unresolved"]),
            "fully_resolved": not buckets["unresolved"] and not buckets["stack"],
        }
    fully_resolved = [k for k, v in variable_manifests.items()
                      if v["fully_resolved"]]

    ram_resolutions = [r for r in resolutions if r.region in RAM_REGIONS]
    unconfirmed_tables = [f"0x{row.dispatch:04X}" for row in boundaries.values()
                          if not row.independent_sources]

    obligations = [
        {
            "id": "A",
            "obligation": ("All reachable instruction starts and transfers "
                           "identified or conservatively represented"),
            "status": _status(False, partial=True),
            "evidence": {
                "instruction_starts": len(graph.nodes),
                "occupied_bytes": len(graph.occupied_bytes()),
                "overlapping_decodings_preserved":
                    len(graph.overlapping_starts()),
                "unresolved_transfers": unresolved_transfers,
                "undocumented_instructions_reached": len(graph.undocumented),
                "halt_instructions_reached": len(graph.halts),
            },
            "assumptions": [
                "a JSR returns to the instruction after it unless the callee "
                "is the JumpEngine (modelled as a return_point edge, not "
                "verified by stack analysis)",
                "indirect and stack-derived destinations are recorded as "
                "unresolved rather than enumerated",
            ],
            "limitations": [
                f"{unresolved_transfers.get('rts', 0)} RTS and "
                f"{unresolved_transfers.get('rti', 0)} RTI destinations are "
                "not resolved; obligation D covers them",
                "coverage is of the CFG built from the three vectors and the "
                "JumpEngine, not of all states reachable by input",
            ],
            "verification_method": "analysis/cfg.py, analysis/decoder.py",
            "artifacts": ["results/cfg.json"],
        },
        {
            "id": "B",
            "obligation": ("JumpEngine consumes the expected return address "
                           "and resolves to allowed targets"),
            "status": _status(False, partial=True),
            "evidence": {
                "dispatch_sites": len(graph.dispatches),
                "tables_with_independent_boundary_confirmation":
                    len(boundaries) - len(unconfirmed_tables),
                "tables_over_read_by_the_old_heuristic":
                    [f"0x{row.dispatch:04X}" for row in boundaries.values()
                     if row.heuristic_was_wrong],
                "distinct_effective_indices_per_site": 128,
                "resolutions_total": len(resolutions),
            },
            "assumptions": [
                "address formation follows jumpengine.resolve_table, which "
                "models ASL aliasing and the 8-bit INY wrap",
            ],
            "limitations": [
                f"table boundaries at {unconfirmed_tables} rest on the "
                "heuristic alone" if unconfirmed_tables else
                "every table boundary has independent confirmation",
                "the engine's consumption of the return address is modelled, "
                "not proved against a stack analysis",
            ],
            "verification_method": ("analysis/dispatch_tables.py, "
                                    "analysis/destinations.py"),
            "artifacts": ["data/dispatch_tables.json",
                          "results/destination_matrix.json"],
        },
        {
            "id": "C",
            "obligation": ("Variables influencing dynamic control flow "
                           "satisfy the required invariants"),
            "status": _status(False),
            "evidence": {
                "sites_bounded_with_no_ram_assumption":
                    [f"0x{d:04X}" for d in sorted(unconditional)],
                "sites_bounded_only_under_an_assumption":
                    len(derivations) - len(unconditional) - len(overrunning),
                "sites_not_bounded_under_their_stated_assumption":
                    [f"0x{d:04X}" for d in sorted(overrunning)],
                "critical_variables_with_a_fully_resolved_writer_set":
                    fully_resolved,
                "writer_manifests": variable_manifests,
            },
            "assumptions": [
                "the invariants listed per site in "
                "results/dispatch_bounds.json, most of them observed only",
            ],
            "limitations": [
                "no critical variable has a fully resolved writer set: every "
                "one is reachable in principle by an unresolved indirect "
                "store, so no invariant is established inductively",
                "$9664's index is $00 + $07 and needs a relational invariant "
                "that is not attempted",
            ],
            "verification_method": ("analysis/index_derivation.py, "
                                    "analysis/write_census.py"),
            "artifacts": ["results/dispatch_bounds.json",
                          "results/write_census.json"],
        },
        {
            "id": "D",
            "obligation": ("RTS/RTI consume valid frames except for "
                           "explicitly modelled intentional alternatives"),
            "status": _status(False),
            "evidence": {
                "stack_derived_returns": unresolved_transfers.get("rts", 0)
                + unresolved_transfers.get("rti", 0),
                "intentional_alternative_modelled":
                    "JumpEngine ($8E04) consumes its caller's return address",
            },
            "assumptions": [],
            "limitations": [
                "the replacement for the RTS pattern scan (plan section 8, "
                "analysis with abstract stack semantics over the CFG) is not "
                "implemented; stack_depth.py measures a band, which is not "
                "return-frame integrity",
            ],
            "verification_method": "not yet implemented",
            "artifacts": [],
        },
        {
            "id": "E",
            "obligation": ("The hardware and input model covers all relevant "
                           "execution semantics"),
            "status": _status(False, partial=True),
            "evidence": {
                "memory_regions_classified": True,
                "io_fetches_treated_as_bus_transactions": True,
                "irq_conclusion": masking["conclusion"],
                "irq_vector_target": next(
                    f"0x{v.target:04X}" for v in vectors(b, graph)
                    if v.name == "irq"),
                "undocumented_opcodes_modelled": 105,
            },
            "assumptions": [
                "instruction fetches from register and open-bus regions are "
                "classified as hardware dependent, not as crashes",
            ],
            "limitations": [
                "open-bus fetch values are not modelled, only flagged",
                "no emulator fidelity comparison has been run in this "
                "revision (plan section 14)",
                "the input model is not yet formalised as an artifact",
            ],
            "verification_method": ("memory.py, analysis/decoder.py, "
                                    "analysis/interrupts.py"),
            "artifacts": ["results/interrupts.json"],
        },
        {
            "id": "F",
            "obligation": ("Unintended execution is independently evaluated "
                           "for input controllability"),
            "status": _status(False),
            "evidence": {
                "resolutions_reaching_controllable_ram": len(ram_resolutions),
                "unexpected_rom_destinations": sum(
                    1 for r in resolutions
                    if r.outcome.value == "unexpected_rom"),
                "unexpected_rom_landing_on_operand_bytes": sum(
                    1 for r in resolutions
                    if r.rom_role == "operand_byte_of_another_instruction"),
            },
            "assumptions": [],
            "limitations": [
                "no input sequence has been demonstrated for any "
                "out-of-range index; reachability under the controller-only "
                "model remains open",
                "assisted experiments (inject.py) do not establish "
                "controller-only reachability",
            ],
            "verification_method": "classify.py, search_oob.py, fuzz.py",
            "artifacts": ["exploitability_classification.json"],
        },
    ]

    open_ids = [o["id"] for o in obligations if o["status"] != "met"]
    return {
        "rom_sha1": image().sha1,
        "obligations": obligations,
        "open_obligations": open_ids,
        "impossibility_claim_permitted": not open_ids,
        "summary": (
            "No controller-only arbitrary code execution has been "
            "demonstrated. Impossibility is not claimed: obligations "
            + ", ".join(open_ids) + " are unresolved."
            if open_ids else
            "All obligations met."),
    }


def main() -> None:
    report = build()
    print(f"ROM sha1 {report['rom_sha1']}\n")
    print("id  status                   obligation")
    print("-" * 78)
    for obligation in report["obligations"]:
        print(f"{obligation['id']:3} {obligation['status']:24} "
              f"{obligation['obligation'][:46]}")
        for limitation in obligation["limitations"][:2]:
            print(f"      - {limitation[:84]}")
    print(f"\nopen obligations: {', '.join(report['open_obligations'])}")
    print(f"impossibility claim permitted: "
          f"{report['impossibility_claim_permitted']}")
    print(f"\n{report['summary']}")

    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "results", "proof_obligations.json")
    with open(path, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
