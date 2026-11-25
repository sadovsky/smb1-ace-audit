"""Conservative census of every instruction that can write RAM (plan section 10).

An invariant such as `RAM[$071F] <= 8` is only as good as the list of
instructions that can modify it.  This module enumerates the writers of any
address by decoding the PRG and classifying each store's effective-address set
with `effective_address`, keeping three categories apart:

  exact        the address is the operand; the writer definitely can hit it
  indexed      `base,X`/`base,Y` whose range covers the address; needs the
               index range to be bounded before it can be dismissed
  unresolved   `(zp),Y`/`(zp,X)`/stack writes whose target is not yet
               constrained; these are *reported*, never silently dropped

`writers_of()` therefore returns an over-approximation.  A variable whose
manifest contains unresolved writers cannot carry a PROVEN bound, which is why
`$071F` is STRUCTURAL_CONDITIONAL in `analysis.dispatch_index`.

Scope: by default the census decodes the instruction starts discovered by
`trace.py`.  Instruction starts missed by the tracer would be missed here too,
so `scope="linear"` additionally decodes every byte offset in PRG as a
potential instruction start.  That is a much coarser over-approximation and is
the honest default when asking "could anything anywhere write this?".
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from d65 import LEN, M

from . import effective_address as ea
from .effective_address import AddressKnowledge, AddressSet

#: Instructions that write memory (plus the register that supplies the value).
STORE_VALUE_SOURCE = {"STA": "A", "STX": "X", "STY": "Y"}

#: Read-modify-write instructions: they both read and write the location.
RMW = {"INC", "DEC", "ASL", "LSR", "ROL", "ROR"}

#: Stack pushes write page one.
PUSH = {"PHA": "A", "PHP": "P"}


@dataclass(frozen=True)
class Writer:
    """One instruction that can modify memory."""

    address: int                 # CPU address of the instruction
    opcode: int
    mnemonic: str
    mode: str
    targets: AddressSet
    value_source: str            # "A"/"X"/"Y"/"P"/"memory" (for RMW)
    reached_by_tracer: bool

    @property
    def is_read_modify_write(self) -> bool:
        return self.mnemonic in RMW

    def category(self) -> str:
        if self.targets.knowledge is AddressKnowledge.UNRESOLVED:
            return "unresolved"
        if self.targets.knowledge is AddressKnowledge.STACK_PAGE:
            return "stack"
        if self.targets.size == 1:
            return "exact"
        return "indexed"

    def to_json(self) -> dict:
        return {
            "address": f"0x{self.address:04X}",
            "opcode": f"0x{self.opcode:02X}",
            "mnemonic": self.mnemonic,
            "mode": self.mode,
            "category": self.category(),
            "value_source": self.value_source,
            "read_modify_write": self.is_read_modify_write,
            "reached_by_tracer": self.reached_by_tracer,
            "targets": self.targets.to_json(),
        }


def _targets_for(mode: str, mnemonic: str, operand_lo: int,
                 operand_hi: int) -> AddressSet | None:
    if mode == "abs":
        return ea.exact(operand_lo | operand_hi << 8)
    if mode in ("abx", "aby"):
        return ea.indexed_absolute(operand_lo | operand_hi << 8)
    if mode == "zp":
        return ea.exact(operand_lo)
    if mode in ("zpx", "zpy"):
        return ea.indexed_page_zero(operand_lo)
    if mode == "izy":
        return ea.unresolved_pointer(operand_lo, "(zp),Y")
    if mode == "izx":
        return ea.unresolved_pointer(operand_lo, "(zp,X)")
    if mode == "imp" and mnemonic in PUSH:
        return ea.stack_page()
    return None


def decode_writer(read_byte: Callable[[int], int], pc: int,
                  *, reached: bool) -> Writer | None:
    """Decode the instruction at `pc`; return a Writer if it modifies memory."""
    opcode = read_byte(pc)
    if opcode not in M:
        return None
    mnemonic, mode = M[opcode]
    if mnemonic not in STORE_VALUE_SOURCE and mnemonic not in RMW \
            and mnemonic not in PUSH:
        return None
    length = LEN[mode]
    if mnemonic in RMW and mode == "acc":
        return None                      # ASL A and friends touch no memory
    operand_lo = read_byte(pc + 1) if length > 1 else 0
    operand_hi = read_byte(pc + 2) if length > 2 else 0
    targets = _targets_for(mode, mnemonic, operand_lo, operand_hi)
    if targets is None:
        return None
    value_source = (STORE_VALUE_SOURCE.get(mnemonic)
                    or PUSH.get(mnemonic)
                    or "memory")
    return Writer(pc, opcode, mnemonic, mode, targets, value_source, reached)


def _tracer_starts(trace_path: str) -> set[int]:
    if not os.path.exists(trace_path):
        return set()
    with open(trace_path) as handle:
        return set(json.load(handle)["instruction_starts"])


def census(read_byte: Callable[[int], int], *, scope: str = "linear",
           trace_path: str = "trace.json",
           prg_range: tuple[int, int] = (0x8000, 0x10000)) -> list[Writer]:
    """Enumerate memory writers in PRG.

    scope="traced"  only instruction starts found by trace.py
    scope="linear"  every byte offset as a candidate instruction start
                    (over-approximates, catches starts the tracer missed)
    """
    reached = _tracer_starts(trace_path)
    if scope == "traced":
        candidates: Iterable[int] = sorted(reached)
    elif scope == "linear":
        candidates = range(*prg_range)
    else:
        raise ValueError(f"unknown scope {scope!r}")

    writers = []
    for pc in candidates:
        writer = decode_writer(read_byte, pc, reached=pc in reached)
        if writer is not None:
            writers.append(writer)
    return writers


def writers_of(address: int, writers: Sequence[Writer]) -> dict[str, list[Writer]]:
    """Partition the writers that could modify `address` by how well resolved."""
    buckets: dict[str, list[Writer]] = {"exact": [], "indexed": [],
                                        "stack": [], "unresolved": []}
    for writer in writers:
        if address in writer.targets:
            buckets[writer.category()].append(writer)
    return buckets


def manifest(address: int, writers: Sequence[Writer], *,
             name: str = "") -> dict:
    """A writer manifest for one variable, suitable for results/*.json."""
    buckets = writers_of(address, writers)
    resolved_only = not buckets["unresolved"] and not buckets["stack"]
    return {
        "address": f"0x{address:04X}",
        "name": name,
        "counts": {k: len(v) for k, v in buckets.items()},
        "fully_resolved": resolved_only,
        "status": ("every writer resolved" if resolved_only
                   else "contains writers whose target is not constrained"),
        "writers": {k: [w.to_json() for w in v] for k, v in buckets.items()},
    }


#: Variables that feed a dynamic control transfer, so whose invariants the
#: dispatch bounds depend on.  Keys are CPU addresses; values describe the role.
CRITICAL_VARIABLES = {
    0x0000: "$9664 index, summed with $07",
    0x0007: "$9664 index, summed with $00 (also JumpEngine pointer high byte)",
    0x000E: "$B04C index",
    0x0016: "enemy slot 0 identifier",
    0x0017: "enemy slot 1 identifier",
    0x0018: "enemy slot 2 identifier",
    0x0019: "enemy slot 3 identifier",
    0x001A: "enemy slot 4 identifier",
    0x001D: "$B34E index",
    0x071F: "$92C8 index",
    0x0733: "$9743 index",
    0x073C: "$856A index",
    0x0746: "$D2E5 index (clamped at the dispatch)",
    0x0770: "$8215 index",
    0x0772: "$8234 / $83A3 / $AEDF index",
}


def main() -> None:  # pragma: no cover - CLI
    import json

    from rom import b, image

    writers = census(b, scope="linear")
    traced = census(b, scope="traced")
    print(f"ROM sha1 {image().sha1}")
    print(f"memory writers decoded: {len(writers)} linearly, "
          f"{len(traced)} at traced instruction starts\n")
    print("Counts are given for both scopes. 'traced' decodes only the "
          "instruction starts the")
    print("CFG reaches; 'linear' decodes every byte offset as a candidate "
          "start, which is a much")
    print("coarser over-approximation and is the honest answer to 'could "
          "anything reach this?'.\n")
    header = ("address  traced: exact/idx/unres   linear: exact/idx/unres  "
              "resolved?  role")
    print(header)
    print("-" * len(header))
    manifests = {}
    for address, role in sorted(CRITICAL_VARIABLES.items()):
        record = manifest(address, writers, name=role)
        traced_record = manifest(address, traced, name=role)
        record["traced_counts"] = traced_record["counts"]
        record["traced_exact_writers"] = traced_record["writers"]["exact"]
        manifests[f"0x{address:04X}"] = record
        counts, tcounts = record["counts"], traced_record["counts"]
        print(f"${address:04X}  "
              f"{tcounts['exact']:7}/{tcounts['indexed']:3}/"
              f"{tcounts['unresolved']:<10} "
              f"{counts['exact']:7}/{counts['indexed']:3}/"
              f"{counts['unresolved']:<10} "
              f"{'yes' if record['fully_resolved'] else 'NO':>9}  {role}")

    resolved = [k for k, v in manifests.items() if v["fully_resolved"]]
    print(f"\nvariables whose writer set is fully resolved: "
          f"{len(resolved)} of {len(manifests)}")
    print("Every unresolved entry is an indirect store whose pointer this "
          "analysis does not constrain.")
    print("No inductive state invariant can be established while any remains, "
          "so obligation C stays open.")

    exact = manifests["0x071F"]["traced_exact_writers"]
    print(f"\n$071F, the $92C8 index, has {len(exact)} exact writer(s) among "
          "reached instructions: "
          + ", ".join(w["address"] + " " + w["mnemonic"] for w in exact))
    print("Both are in the dispatch's own routine, which is why RAM[$071F] "
          "<= 8 is supportable")
    print("but not proved: the indexed and indirect stores above are not "
          "ruled out.")

    with open("results/write_census.json", "w") as handle:
        json.dump({"rom_sha1": image().sha1,
                   "writers_decoded_linear": len(writers),
                   "writers_decoded_traced": len(traced),
                   "manifests": manifests}, handle, indent=2, sort_keys=True)
    print("\nwrote results/write_census.json")


if __name__ == "__main__":  # pragma: no cover
    main()
