"""Interrupt entry as a control-transfer mechanism (plan sections 9, 16E).

The audit dismissed IRQs with "NROM has no mapper IRQ".  That is incomplete:
the 2A03 itself has two IRQ sources, the APU frame counter and the DMC sample
unit, and neither depends on the cartridge.  It also leaves the vectors
unexamined, and SMB1's IRQ vector is the interesting part -- it points at
`$FFF0`, which is not code at all but the tail of a byte table
(`19 19 1A 1A 1C 1D 1D 1E ...`).  An IRQ that fired would send the program
counter into data.

So the question is whether an IRQ can fire, and the answer does not depend on
the APU at all:

  * `$8000` (reset) begins `SEI`, setting the interrupt disable flag.
  * No reachable instruction is `CLI`, and none is `PLP`.
  * The only reachable `RTI` is `$8181`, in the NMI handler.  `RTI` restores
    the status byte the interrupt sequence pushed, and the CPU pushes the
    status *as it was* before setting I.  So an `RTI` can only clear I if I was
    already clear when that NMI was taken.

By induction over the whole execution, I is set after reset and can never
become clear, so a maskable IRQ can never be serviced however the APU is
configured.  This is stronger than the mapper argument and it does not rely on
the `$4017` inhibit write.

Two caveats are reported rather than buried.  First, 101 bytes in PRG have the
value `$58` (`CLI`), and the induction only covers *reachable instruction
starts*: control flow that is already derailed onto one of those bytes could
clear I.  That is a consequence of derailment, not a way to cause it, so it
does not open an initial transfer.  Second, the NMI vector is a genuine
periodic entry that runs every frame regardless of the I flag; it is listed
here for completeness because it, not the IRQ, is the interrupt that actually
occurs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from memory import memory_region

from .cfg import CFG
from .decoder import decode

#: Flag-manipulating instructions that matter for interrupt masking.
I_FLAG_CLEARING = {"CLI", "PLP"}


@dataclass(frozen=True)
class VectorReport:
    name: str
    vector_address: int
    target: int
    region: str
    also_reached_by_normal_flow: bool
    decoded: str

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "vector_at": f"0x{self.vector_address:04X}",
            "target": f"0x{self.target:04X}",
            "region": self.region,
            "target_also_reached_by_normal_flow":
                self.also_reached_by_normal_flow,
            "first_instruction_if_decoded": self.decoded,
        }


def vectors(read_byte: Callable[[int], int], graph: CFG) -> list[VectorReport]:
    out = []
    for name, address in (("nmi", 0xFFFA), ("reset", 0xFFFC), ("irq", 0xFFFE)):
        target = read_byte(address) | read_byte(address + 1) << 8
        node = graph.nodes.get(target)
        # True only if something other than the vector edge itself executes
        # this address.  For NMI and reset the answer is normally "no" and
        # means nothing -- they are entry points.  For IRQ it is a hint that
        # the target is not code that the program ever runs deliberately.
        reachable = bool(node and any(
            kind != "interrupt" for _source, kind in node.predecessors))
        out.append(VectorReport(
            name=name,
            vector_address=address,
            target=target,
            region=memory_region(target),
            also_reached_by_normal_flow=reachable,
            decoded=str(decode(read_byte, target)),
        ))
    return out


def masking_report(read_byte: Callable[[int], int], graph: CFG) -> dict:
    """Whether the interrupt disable flag can ever be cleared."""
    clearing = {mnemonic: sorted(
        address for address in graph.nodes
        if decode(read_byte, address).info.mnemonic == mnemonic)
        for mnemonic in sorted(I_FLAG_CLEARING)}
    returns = sorted(address for address in graph.nodes
                     if decode(read_byte, address).info.mnemonic == "RTI")
    sets = sorted(address for address in graph.nodes
                  if decode(read_byte, address).info.mnemonic == "SEI")
    stray_cli_bytes = sum(1 for address in range(0x8000, 0x10000)
                          if read_byte(address) == 0x58)
    i_can_clear = any(clearing.values())
    return {
        "sei_sites": [f"0x{a:04X}" for a in sets],
        "cli_sites": [f"0x{a:04X}" for a in clearing["CLI"]],
        "plp_sites": [f"0x{a:04X}" for a in clearing["PLP"]],
        "rti_sites": [f"0x{a:04X}" for a in returns],
        "i_flag_clearable_on_reachable_paths": i_can_clear,
        "stray_cli_bytes_in_prg": stray_cli_bytes,
        "conclusion": (
            "a maskable IRQ can never be serviced: I is set by SEI at reset "
            "and no reachable CLI or PLP exists; RTI can only restore a "
            "status byte that already had I set"
            if not i_can_clear else
            "the I flag can be cleared on a reachable path; IRQ sources must "
            "be analysed individually"),
        "caveats": [
            f"{stray_cli_bytes} bytes in PRG hold $58 (CLI); the induction "
            "covers reachable instruction starts only, so already-derailed "
            "control flow could clear I. That is a consequence of derailment, "
            "not a mechanism for causing it.",
            "the NMI runs every frame regardless of the I flag; it is the "
            "interrupt that actually occurs, and it is in the reachable set.",
        ],
    }


def main() -> None:  # pragma: no cover - CLI
    from rom import b, image

    from .cfg import build_from_vectors

    graph = build_from_vectors(b)
    reports = vectors(b, graph)
    masking = masking_report(b, graph)

    print(f"ROM sha1 {image().sha1}\n")
    print("hardware vectors")
    print("name   vector  target  region    also in normal flow  decodes as")
    print("-" * 76)
    for report in reports:
        print(f"{report.name:6} ${report.vector_address:04X}   "
              f"${report.target:04X}   {report.region:9} "
              f"{'yes' if report.also_reached_by_normal_flow else 'no':>19}  "
              f"{report.decoded}")
    print("\n(NMI and reset are entry points, so 'no' is expected there.)")
    print("The IRQ vector points at $FFF0, which is table data rather than "
          "code: an IRQ would execute data bytes.")

    print("\ninterrupt masking")
    print(f"  SEI at: {', '.join(masking['sei_sites']) or 'none'}")
    print(f"  CLI at: {', '.join(masking['cli_sites']) or 'none'}")
    print(f"  PLP at: {', '.join(masking['plp_sites']) or 'none'}")
    print(f"  RTI at: {', '.join(masking['rti_sites']) or 'none'}")
    print(f"\n  => {masking['conclusion']}")
    for caveat in masking["caveats"]:
        print(f"  caveat: {caveat}")

    with open("results/interrupts.json", "w") as handle:
        json.dump({"rom_sha1": image().sha1,
                   "vectors": [r.to_json() for r in reports],
                   "masking": masking}, handle, indent=2, sort_keys=True)
    print("\nwrote results/interrupts.json")


if __name__ == "__main__":  # pragma: no cover
    main()
