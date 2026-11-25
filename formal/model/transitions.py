"""The transition relation `T` and the initial-state predicate `I`.

A state is taken at an instruction boundary.  From it the machine may:

1. execute the instruction at PC (`cpu.step`);
2. enter the NMI handler, if the ghost bit `nmi_enable` is set;
3. enter the IRQ handler, if the I flag is clear;
4. be reset (warm reset is an input the model always permits).

`nmi_enable` is a ghost copy of bit 7 of the last byte written to PPU control
(`$2000` and its mirrors every eight bytes through `$3FFF`).  It is determined
entirely by CPU writes, so tracking it adds no assumption.

Over-approximations, each of which only *adds* behaviours:

* NMI may be taken at **any** boundary while `nmi_enable` holds.  Real hardware
  needs a rising edge of (vblank flag AND enable), so it permits far fewer.
  The price: this model allows an NMI to re-enter its own handler before the
  handler's first instruction, without bound, which no NES can do.  A proof
  that needs to exclude that must add the timing assumption MA-NMI-EDGE
  (below) explicitly and is conditional on it.
* IRQ may be taken at any boundary while I is clear, whatever the APU state.
* Reset may occur at any boundary.

Model assumptions that are *not* over-approximations and therefore condition
every result that depends on them:

MA-PPU-POWERON   at cold boot the PPU control register is zero, so
                 `nmi_enable` starts false.
MA-PPU-WARMUP    writes to PPU control are assumed to take effect.  A real PPU
                 ignores them from power-on (and, on consoles whose reset
                 button resets the PPU, from reset) until the pre-render
                 scanline of the next frame.  That is a scanline-phase
                 condition, not a cycle count: the often-quoted 29,658 NTSC
                 CPU cycles holds only when CPU and PPU leave reset together.
                 Which consoles reset the PPU on the button varies (the
                 front-loading NES does; the Famicom and the top-loader are
                 documented as not doing so).
MA-NMI-EDGE      two NMI entries with no intervening 0->1 write of the enable
                 bit are at least one frame apart.  Not built into `T`.  The
                 edge rule (NMI on a rising edge of vblank flag AND enable) is
                 documented by NESdev; the consequence used here is derived
                 from it.
MA-NMI-LATENCY   an NMI whose edge is caused by the final cycle of an
                 instruction is serviced after the *following* instruction.
                 Not built into `T`.  NESdev documents that the interrupt
                 lines are sampled at the end of the second-to-last cycle;
                 this assumption is an inference from that, not a quoted
                 statement.  The uniform rule is wrong for taken branches,
                 which does not matter for the two instructions it is applied
                 to (`STA $2000` and `RTI`).
MA-CPU           `cpu.py` matches the 2A03 at instruction granularity; see the
                 validation report for what that rests on.

Cold boot: every register, every flag except I, and all of RAM are
unconstrained; PC is the reset vector; I is set.  Warm reset is the `reset`
transition from any reachable state, so it needs no separate initial
predicate.
"""
from __future__ import annotations

from dataclasses import dataclass

import z3

from . import cpu
from .cpu import State, Successor
from .memory import NESMemory, as_int


@dataclass(frozen=True)
class Machine:
    """A CPU state plus the ghost NMI-enable bit."""
    cpu: State
    nmi_enable: z3.BoolRef


def cold_boot(prg: bytes) -> Machine:
    memory = NESMemory.symbolic(prg, "RAM0")
    vector = prg[cpu.RESET_VECTOR - 0x8000] | prg[cpu.RESET_VECTOR - 0x7FFF] << 8
    state = State.symbolic(vector, memory, prefix="boot_")
    state = cpu.replace(state, i=z3.BoolVal(True))
    return Machine(state, z3.BoolVal(False))


def ppu_control_update(enable, writes) -> z3.BoolRef:
    """Fold a sequence of writes into the ghost enable bit."""
    for address, value in writes:
        bit = z3.Extract(7, 7, value) == 1
        concrete = as_int(address)
        if concrete is not None:
            if 0x2000 <= concrete < 0x4000 and concrete & 7 == 0:
                enable = bit
            continue
        hits = z3.And(z3.UGE(address, 0x2000), z3.ULT(address, 0x4000),
                      z3.Extract(2, 0, address) == 0)
        enable = z3.If(hits, bit, enable)
    return z3.simplify(enable)


def _after(machine: Machine, successor: Successor, kind: str | None = None):
    before = len(machine.cpu.mem.writes)
    enable = ppu_control_update(machine.nmi_enable,
                                successor.state.mem.writes[before:])
    return (successor.guard, Machine(successor.state, enable),
            kind or successor.kind)


def transitions(machine: Machine, *, asynchronous: bool = True):
    """All `(guard, machine', kind)` with `T(machine, _, machine')`."""
    state = machine.cpu
    out = [_after(machine, s) for s in cpu.step(state)]
    if not asynchronous:
        return out
    true = z3.BoolVal(True)
    if not z3.is_false(z3.simplify(machine.nmi_enable)):
        entered = cpu.enter_interrupt(state, cpu.NMI_VECTOR)
        out.append(_after(machine, Successor(machine.nmi_enable, entered,
                                             "nmi"), "nmi"))
    masked = z3.simplify(state.i)
    if not z3.is_true(masked):
        entered = cpu.enter_interrupt(state, cpu.IRQ_VECTOR)
        out.append(_after(machine, Successor(z3.Not(masked), entered, "irq"),
                          "irq"))
    out.append((true, Machine(cpu.reset(state), machine.nmi_enable), "reset"))
    return out
