"""Control-flow graph with typed edges and overlapping decodings (plan section 5).

`trace.py` guards its walk with `if pc in code: return`, where `code` holds
every *byte* already decoded.  That makes the tracer refuse to decode an
instruction whose start address happens to be an operand byte of an
already-decoded instruction, so an overlapping instruction stream -- the normal
consequence of entering a routine one byte off, and a standard ingredient of
control-flow corruption -- is discarded silently.  It also stops a trace dead
at the first undocumented opcode, mis-aligning nothing but reporting nothing
either.

This module keys its visited set on **instruction start addresses**, so two
decodings that overlap in memory both survive and both carry their discovery
provenance.  Edges are typed:

    fallthrough      next instruction
    branch           taken side of a conditional branch
    jump             JMP abs
    call             JSR target
    return_point     the address a JSR is expected to return to
    dispatch         a JumpEngine table entry (JSR $8E04)
    interrupt        reset / NMI / IRQ-BRK vector entry
    unresolved       a transfer whose destination is data-derived

Unresolved transfers (`JMP ($0006)`, every `RTS`/`RTI`) are recorded as nodes
with an `unresolved` outgoing edge rather than quietly terminating a walk, so
"we do not know where this goes" is a reportable result.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable

from .decoder import Flow, Instruction, decode

JUMPENGINE = 0x8E04

#: Edge kinds that represent a transfer whose target is not statically known.
UNRESOLVED_KINDS = frozenset({"unresolved"})


@dataclass
class Node:
    instruction: Instruction
    #: how this instruction start was first discovered
    discovery: str
    successors: list[tuple[int, str]] = field(default_factory=list)
    predecessors: list[tuple[int, str]] = field(default_factory=list)

    @property
    def address(self) -> int:
        return self.instruction.address


@dataclass
class DispatchSite:
    """A `JSR $8E04` and the table immediately following it."""

    dispatch: int
    table: int
    entries: tuple[int, ...]

    def to_json(self) -> dict:
        return {
            "dispatch": f"0x{self.dispatch:04X}",
            "table": f"0x{self.table:04X}",
            "entry_count": len(self.entries),
            "entries": [f"0x{e:04X}" for e in self.entries],
        }


class CFG:
    """A control-flow graph over CPU addresses, allowing overlap."""

    def __init__(self, read_byte: Callable[[int], int], *,
                 table_reader: Callable[[int], tuple[int, ...]] | None = None,
                 code_range: tuple[int, int] = (0x8000, 0x10000)):
        self.read_byte = read_byte
        self.code_range = code_range
        self.nodes: dict[int, Node] = {}
        self.dispatches: dict[int, DispatchSite] = {}
        self.unresolved: list[tuple[int, str, str]] = []
        self.halts: list[int] = []
        self.undocumented: list[int] = []
        self._table_reader = table_reader or self._default_table_reader
        self._queue: deque[tuple[int, str]] = deque()
        #: addresses seeded before the walk started, i.e. the graph's own
        #: entry points (vectors, the JumpEngine, or a caller's choice)
        self.seeds: set[int] = set()
        self._building = False

    # -- construction ------------------------------------------------------

    def _in_range(self, address: int) -> bool:
        low, high = self.code_range
        return low <= address < high

    def _default_table_reader(self, table: int) -> tuple[int, int]:
        """Words until one falls outside the code range (heuristic!).

        This is deliberately the *same* heuristic the original `read_table`
        used, so `analysis.dispatch_tables` can compare it against independent
        boundary evidence instead of inheriting it as truth.
        """
        out: list[int] = []
        for index in range(80):
            low = self.read_byte((table + 2 * index) & 0xFFFF)
            high = self.read_byte((table + 2 * index + 1) & 0xFFFF)
            word = low | high << 8
            if not self._in_range(word):
                break
            out.append(word)
        return tuple(out)

    def add_entry(self, address: int, discovery: str) -> None:
        address &= 0xFFFF
        if not self._building:
            self.seeds.add(address)
        self._queue.append((address, discovery))

    def build(self) -> "CFG":
        self._building = True
        while self._queue:
            address, discovery = self._queue.popleft()
            self._visit(address, discovery)
        for node in self.nodes.values():
            for target, kind in node.successors:
                if target in self.nodes:
                    self.nodes[target].predecessors.append((node.address, kind))
        return self

    def _link(self, source: int, target: int, kind: str,
              discovery: str) -> None:
        self.nodes[source].successors.append((target, kind))
        if self._in_range(target):
            self.add_entry(target, discovery)

    def _visit(self, address: int, discovery: str) -> None:
        # keyed on instruction STARTS: an overlapping decoding is kept
        if address in self.nodes or not self._in_range(address):
            return
        instruction = decode(self.read_byte, address)
        node = Node(instruction, discovery)
        self.nodes[address] = node
        if not instruction.info.documented:
            self.undocumented.append(address)

        flow = instruction.info.flow
        provenance = f"${address:04X}"

        if flow is Flow.CALL and instruction.operand16 == JUMPENGINE:
            # JumpEngine: pulls the caller's return address off the stack and
            # jumps through the table that follows the JSR.  Control never
            # reaches the bytes after the table by falling through.
            table = instruction.end
            entries = tuple(self._table_reader(table))
            self.dispatches[address] = DispatchSite(address, table, entries)
            for entry in entries:
                self._link(address, entry, "dispatch", f"dispatch {provenance}")
            return

        if flow is Flow.CALL:
            self._link(address, instruction.operand16, "call",
                       f"call {provenance}")
            # The return point is where the callee is *expected* to resume.
            # It is an assumption about the callee, recorded as its own edge
            # kind so stack analysis can confirm or refute it.
            self._link(address, instruction.end, "return_point",
                       f"return of {provenance}")
            return

        if flow is Flow.INDIRECT_JUMP:
            pointer = instruction.operand16
            node.successors.append((pointer, "unresolved"))
            self.unresolved.append(
                (address, "indirect_jump", f"JMP (${pointer:04X})"))
            return

        if flow is Flow.RETURN:
            node.successors.append((0, "unresolved"))
            self.unresolved.append(
                (address, instruction.info.mnemonic.lower(),
                 "destination depends on the stack frame"))
            return

        if flow is Flow.BREAK:
            vector = (self.read_byte(0xFFFE) | self.read_byte(0xFFFF) << 8)
            self._link(address, vector, "interrupt", f"BRK at {provenance}")
            return

        if flow is Flow.HALT:
            self.halts.append(address)
            self.unresolved.append(
                (address, "halt", "JAM: the processor stops fetching"))
            return

        for target, kind in instruction.successors():
            self._link(address, target, kind, f"{kind} from {provenance}")

    # -- queries -----------------------------------------------------------

    @property
    def instruction_starts(self) -> set[int]:
        return set(self.nodes)

    def occupied_bytes(self) -> set[int]:
        occupied: set[int] = set()
        for node in self.nodes.values():
            for offset in range(node.instruction.length):
                occupied.add((node.address + offset) & 0xFFFF)
        return occupied

    def overlapping_starts(self) -> dict[int, list[int]]:
        """Instruction starts that fall strictly inside another instruction.

        The returned mapping is {interior start: [containing starts]}; a
        non-empty result is exactly what `trace.py` used to discard.
        """
        interior: dict[int, set[int]] = defaultdict(set)
        for node in self.nodes.values():
            for offset in range(1, node.instruction.length):
                inside = (node.address + offset) & 0xFFFF
                if inside in self.nodes:
                    interior[inside].add(node.address)
        return {k: sorted(v) for k, v in sorted(interior.items())}

    def paths_to(self, target: int, *, max_depth: int = 64,
                 kinds: frozenset[str] | None = None) -> list[list[int]]:
        """Backward instruction paths reaching `target` within `max_depth`.

        Walks predecessors, which is what index derivation needs: the question
        is always "how can the accumulator arrive here?".  Cycles are cut at
        first repetition so the result is finite.
        """
        allowed = kinds or frozenset({"fallthrough", "branch", "jump",
                                      "call", "dispatch", "return_point",
                                      "interrupt"})
        results: list[list[int]] = []
        stack: list[tuple[int, list[int]]] = [(target, [target])]
        while stack:
            address, path = stack.pop()
            node = self.nodes.get(address)
            incoming = [(src, kind) for src, kind in (node.predecessors if node else [])
                        if kind in allowed]
            if not incoming or len(path) >= max_depth:
                results.append(list(reversed(path)))
                continue
            for source, _kind in incoming:
                if source in path:                      # cut the cycle
                    results.append(list(reversed(path)))
                    continue
                stack.append((source, path + [source]))
        return results

    def summary(self) -> dict:
        return {
            "instruction_starts": len(self.nodes),
            "occupied_bytes": len(self.occupied_bytes()),
            "overlapping_starts": len(self.overlapping_starts()),
            "dispatch_sites": len(self.dispatches),
            "unresolved_transfers": len(self.unresolved),
            "halt_instructions": len(self.halts),
            "undocumented_instructions": len(self.undocumented),
        }

    def to_json(self) -> dict:
        return {
            "summary": self.summary(),
            "dispatches": [site.to_json() for site in self.dispatches.values()],
            "unresolved": [
                {"address": f"0x{a:04X}", "kind": k, "detail": d}
                for a, k, d in self.unresolved
            ],
            "overlapping_starts": {
                f"0x{inside:04X}": [f"0x{o:04X}" for o in outer]
                for inside, outer in self.overlapping_starts().items()
            },
            "undocumented": [f"0x{a:04X}" for a in sorted(self.undocumented)],
        }


def established_table_reader(read_byte: Callable[[int], int]
                             ) -> Callable[[int], tuple[int, ...]]:
    """Read a table only as far as independent boundary evidence supports.

    The heuristic reader walks words until one falls outside PRG, which
    over-reads a table whose following code bytes happen to form a ROM-range
    word.  At $C7AB that produced two phantom entries and a phantom dispatch
    edge to $A060, from which the tracer decoded data as `JAM`.
    """
    from .dispatch_tables import rom_only_entries

    def read_table(table: int) -> tuple[int, ...]:
        count = rom_only_entries(read_byte, table)
        return tuple(
            read_byte((table + 2 * i) & 0xFFFF)
            | read_byte((table + 2 * i + 1) & 0xFFFF) << 8
            for i in range(count)
        )

    return read_table


def build_from_vectors(read_byte: Callable[[int], int], *,
                       established_boundaries: bool = True, **kwargs) -> CFG:
    """Build a CFG from the three hardware vectors plus the JumpEngine.

    `established_boundaries` reads each dispatch table only as far as the
    boundary evidence supports.  Pass False to reproduce the original
    heuristic-only behaviour for comparison.
    """
    if established_boundaries and "table_reader" not in kwargs:
        kwargs["table_reader"] = established_table_reader(read_byte)
    graph = CFG(read_byte, **kwargs)
    for name, vector in (("nmi", 0xFFFA), ("reset", 0xFFFC), ("irq", 0xFFFE)):
        entry = read_byte(vector) | read_byte(vector + 1) << 8
        graph.add_entry(entry, f"{name} vector")
    graph.add_entry(JUMPENGINE, "jumpengine")
    return graph.build()


def main() -> None:  # pragma: no cover - CLI
    from rom import b, image

    graph = build_from_vectors(b)
    report = {"rom_sha1": image().sha1, **graph.to_json()}
    print(json.dumps(report["summary"], indent=2))
    overlap = graph.overlapping_starts()
    if overlap:
        print(f"\noverlapping instruction starts: {len(overlap)}")
        for inside, outer in list(overlap.items())[:10]:
            print(f"  ${inside:04X} lies inside "
                  + ", ".join(f"${o:04X}" for o in outer))
    print(f"\nunresolved transfers: {len(graph.unresolved)}")
    kinds: dict[str, int] = defaultdict(int)
    for _address, kind, _detail in graph.unresolved:
        kinds[kind] += 1
    for kind, count in sorted(kinds.items()):
        print(f"  {kind:14} {count}")
    with open("results/cfg.json", "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("\nwrote results/cfg.json")


if __name__ == "__main__":  # pragma: no cover
    main()
