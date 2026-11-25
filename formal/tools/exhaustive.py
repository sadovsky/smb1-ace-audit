"""Exhaustive per-opcode equivalence of `model/cpu.py` and `dyn/cpu6502.py`.

`formal.validate_model` compares the model with py65 on 40 *random* states per
documented opcode.  Random sampling of a 2^40 state space is weak evidence.
This module instead picks, for each opcode, the dimensions the instruction's
result actually depends on and enumerates them **completely**, comparing
against `formal.dyn.cpu6502.NMOS2A03` -- an independently written interpreter
(py65's core, extended for the 2A03 and the 105 undocumented encodings) that
shares no code with the model.

Every opcode gets one or more *domains*.  A domain names the axes it
enumerates exhaustively, the dimensions it holds fixed, and the dimensions it
only samples (always a fixed set of edge values, never random, so a run is
reproducible).  `--out` records that per opcode, so a reader can see exactly
what was and was not covered: "all 256x256 values of A and the operand with
both carries" is a different claim from "8 edge values of A".

What no domain here covers, for any opcode:

* the other three registers and the 2 KiB of RAM outside the cells the domain
  sets.  A full state sweep is 2^40 per opcode and is not attempted.
* cycle counts (the model has no cycle granularity) and interrupt timing.
* the `JAM` encodings: the model halts, `NMOS2A03` raises `Jam`.  Both stop,
  but there is no state to compare, so they are listed and skipped.
* the six unstable instructions.  The model havocs them and `NMOS2A03` folds
  in a magic constant, so what is checked is *admission*: everything the model
  still fixes must agree.  Never counted as agreement.

    python3 -m formal.tools.exhaustive [--jobs N] [--dry-run] [--opcodes 69,a9]
"""
from __future__ import annotations

import argparse
import itertools
import json
import multiprocessing
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from analysis.decoder import OPCODES

from ..model.cpu import HAVOC, State, step
from ..model.memory import FlatMemory, as_int
from ..dyn.cpu6502 import Jam, NMOS2A03
from .validate_full import (FLAG_BITS, HAVOC_OPCODES, HavocMemory,
                            JAM_OPCODES, MISMATCH_CAP, MAX_JOBS, observe)

BYTES = tuple(range(256))
#: deterministic edge values for the dimensions a domain only samples
EDGE8 = (0x00, 0x01, 0x3F, 0x7F, 0x80, 0x81, 0xA5, 0xFF)
EDGE4 = (0x00, 0x01, 0x80, 0xFF)
#: the 64 architecturally distinct status bytes: bit 5 reads 1 and bit 4 (B)
#: is not a register, so only bits 0,1,2,3,6,7 vary
P64 = tuple(0x20 | (v & 0x0F) | ((v & 0x30) << 2) for v in range(64))
#: a program counter far from page zero, the stack page and the vectors
PC = 0x1000
#: a page used for absolute targets that cannot collide with the instruction
FAR = 0x20


# -- the two interpreters ---------------------------------------------------

class LoggingFlat(list):
    """A flat 64 KiB space for `NMOS2A03` that records what was written."""

    def __init__(self):
        super().__init__([0] * 0x10000)
        self.writes: dict[int, int] = {}

    def __getitem__(self, address):
        return list.__getitem__(self, address & 0xFFFF)

    def __setitem__(self, address, value):
        address &= 0xFFFF
        value &= 0xFF
        self.writes[address] = value
        list.__setitem__(self, address, value)

    def put(self, address, value):
        """Set a cell without recording it as an instruction's write."""
        list.__setitem__(self, address & 0xFFFF, value & 0xFF)


class Reference:
    """One reusable `NMOS2A03`; the memory is restored after every case."""

    def __init__(self):
        self.memory = LoggingFlat()
        self.mpu = NMOS2A03(memory=self.memory, pc=0)

    def run(self, case: dict):
        memory, mpu = self.memory, self.mpu
        for address, value in case["cells"].items():
            memory.put(address, value)
        memory.writes = {}
        mpu.pc, mpu.a, mpu.x = case["pc"], case["a"], case["x"]
        mpu.y, mpu.sp, mpu.p = case["y"], case["s"], case["p"]
        mpu.processorCycles = 0
        jammed = False
        try:
            mpu.step()
        except Jam:
            jammed = True
        writes = memory.writes
        state = {"pc": mpu.pc & 0xFFFF, "a": mpu.a, "x": mpu.x, "y": mpu.y,
                 "s": mpu.sp}
        for name, bit in FLAG_BITS.items():
            state[name] = mpu.p >> bit & 1
        for address in itertools.chain(case["cells"], writes):
            memory.put(address, 0)
        return state, writes, jammed


def run_model(case: dict, *, havoc: bool):
    cells = case["cells"]
    memory = HavocMemory(cells) if havoc else FlatMemory(cells)
    state = State.concrete(pc=case["pc"], a=case["a"], x=case["x"],
                           y=case["y"], s=case["s"], p=case["p"], mem=memory)
    successors = step(state)
    return successors, memory


def compare(case: dict, reference: Reference, *, havoc: bool) -> dict | None:
    """None when the two implementations agree (or the havoc admits dyn)."""
    successors, memory = run_model(case, havoc=havoc)
    want, dyn_writes, jammed = reference.run(case)
    if len(successors) != 1:
        return {"fault": "the model forked on a concrete state",
                "successors": len(successors), "case": _describe(case)}
    after = successors[0].state
    got = observe(after)
    model_writes = {address: value for address, value in after.mem.writes}
    cells = case["cells"]

    if havoc:
        differences = {k: {"dyn": want[k], "model": got[k]}
                       for k in want
                       if got[k] is not None and got[k] != want[k]}
        changed = sorted(a for a, v in dyn_writes.items()
                         if cells.get(a, 0) != v)
        concrete = sorted(model_writes)
        admitted = (not differences and not concrete
                    and len(changed) <= len(memory.log))
        if admitted:
            return None
        return {"case": _describe(case), "differences": differences,
                "cells_dyn_changed": [f"${a:04X}" for a in changed],
                "unconstrained_writes_the_model_made": len(memory.log),
                "concrete_writes_the_model_made": [f"${a:04X}"
                                                   for a in concrete]}

    differences = {k: {"dyn": want[k], "model": got[k]}
                   for k in want if got[k] != want[k]}
    #: compare the resulting byte at every address either side touched
    for address in sorted(set(model_writes) | set(dyn_writes)):
        base = cells.get(address, 0)
        if model_writes.get(address, base) != dyn_writes.get(address, base):
            differences[f"ram[${address:04X}]"] = {
                "dyn": dyn_writes.get(address, base),
                "model": model_writes.get(address, base)}
    if jammed:
        differences["jam"] = {"dyn": "raised Jam",
                              "model": "halted" if after.halted else "ran on"}
    if not differences:
        return None
    return {"case": _describe(case), "differences": differences,
            "write_sets": {
                "model": [f"${a:04X}" for a in sorted(model_writes)],
                "dyn": [f"${a:04X}" for a in sorted(dyn_writes)]}}


def _describe(case: dict) -> dict:
    return {"pc": f"${case['pc']:04X}",
            "a": case["a"], "x": case["x"], "y": case["y"], "s": case["s"],
            "p": f"0x{case['p']:02X}",
            "cells": {f"${a:04X}": v
                      for a, v in sorted(case["cells"].items())}}


# -- domains ----------------------------------------------------------------

@dataclass
class Domain:
    label: str
    #: axis name -> every value it takes, enumerated
    axes: list
    build: Callable
    #: dimensions held at one value, as prose
    fixed: str = ""
    #: dimensions covered only by a fixed set of edge values, as prose
    sampled: str = ""

    @property
    def count(self) -> int:
        n = 1
        for _, values in self.axes:
            n *= len(values)
        return n

    def cases(self):
        names = [name for name, _ in self.axes]
        for combination in itertools.product(*[v for _, v in self.axes]):
            yield self.build(**dict(zip(names, combination)))

    def describe(self) -> dict:
        return {"domain": self.label,
                "exhausted": {name: len(values) for name, values in self.axes},
                "cases": self.count, "fixed": self.fixed,
                "sampled": self.sampled}


def _case(opcode: int, *, pc: int = PC, a: int = 0, x: int = 0, y: int = 0,
          s: int = 0xFD, p: int = 0x20, operands=(), cells=None) -> dict:
    content = dict(cells or {})
    content[pc] = opcode
    for offset, byte in enumerate(operands, 1):
        content[(pc + offset) & 0xFFFF] = byte
    return {"pc": pc, "a": a, "x": x, "y": y, "s": s, "p": p | 0x20,
            "cells": content}


def _carry(flag: int) -> int:
    return 0x20 | (flag & 1)


#: mnemonics whose immediate form consumes the carry flag
_READS_CARRY = frozenset({"ADC", "SBC", "USBC", "ARR"})
#: mnemonic -> the register its result is a function of, for value domains
_REGISTER = {"CPX": "x", "CPY": "y", "LDX": "x", "LDY": "y", "STX": "x",
             "STY": "y", "SAX": "a", "SHX": "x", "SHY": "y"}
#: the four accumulator-mode shifts and their read-modify-write twins
_RMW = frozenset({"ASL", "LSR", "ROL", "ROR", "INC", "DEC", "SLO", "RLA",
                  "SRE", "RRA", "DCP", "ISC"})
#: one representative opcode per addressing mode gets the full address atlas
ATLAS = {"zp": 0xA5, "zpx": 0xB5, "zpy": 0xB6, "abs": 0xAD, "abx": 0xBD,
         "aby": 0xB9, "izx": 0xA1, "izy": 0xB1}
#: mnemonics with no immediate encoding cannot inherit the exhaustive
#: register-by-operand sweep from `_immediate_domains`, so one encoding of
#: each carries it here instead
VALUE_ATLAS = {"BIT": 0x24, "LAX": 0xA7, "LAS": 0xBB, "SAX": 0x87,
               "SLO": 0x07, "RLA": 0x27, "SRE": 0x47, "RRA": 0x67,
               "DCP": 0xC7, "ISC": 0xE7}


def _immediate_domains(opcode: int, info) -> list[Domain]:
    mnemonic = mnemonic_of(info)
    register = _REGISTER.get(mnemonic, "a")
    if mnemonic in ("LDA", "LDX", "LDY", "NOP"):
        return [Domain(
            "every immediate operand against every architectural status byte",
            [("m", BYTES), ("p", P64)],
            lambda m, p: _case(opcode, operands=(m,), p=p, a=0x5A, x=0x5A,
                               y=0x5A),
            fixed="PC, S", sampled="A, X, Y held at 0x5A (the result does not "
                                   "read them)")]
    if mnemonic == "SBX":
        return [
            Domain("every A and operand, X held at 0xFF so A&X = A",
                   [("a", BYTES), ("m", BYTES)],
                   lambda a, m: _case(opcode, a=a, x=0xFF, operands=(m,)),
                   fixed="X = 0xFF, C, PC, S", sampled=""),
            Domain("every X and operand, A held at 0xFF so A&X = X",
                   [("x", BYTES), ("m", BYTES)],
                   lambda x, m: _case(opcode, a=0xFF, x=x, operands=(m,)),
                   fixed="A = 0xFF, C, PC, S", sampled=""),
            Domain("every A and X against edge operands",
                   [("a", BYTES), ("x", BYTES), ("m", EDGE4)],
                   lambda a, x, m: _case(opcode, a=a, x=x, operands=(m,)),
                   fixed="C, PC, S", sampled="operand: 4 edge values"),
        ]
    axes = [(register, BYTES), ("m", BYTES)]
    label = f"every {register.upper()} and every immediate operand"
    if mnemonic in _READS_CARRY:
        axes.append(("c", (0, 1)))
        label += ", both carries"
    build = lambda **kw: _case(
        opcode, operands=(kw["m"],), p=_carry(kw.get("c", 0)),
        **{register: kw[register]})
    domains = [Domain(label, axes, build,
                      fixed="PC, S, the registers the result does not read",
                      sampled="")]
    if mnemonic in ("ADC", "SBC", "USBC"):
        domains.append(Domain(
            "the same sweep with D set: the 2A03 adder must ignore it",
            [(register, BYTES), ("m", BYTES)],
            lambda **kw: _case(opcode, operands=(kw["m"],), p=0x28,
                               **{register: kw[register]}),
            fixed="C = 0, D = 1, PC, S", sampled=""))
    return domains


def _branch_domains(opcode: int, info) -> list[Domain]:
    #: pc+2 is the base the displacement is added to
    domains = [Domain(
        "every displacement against all 64 architectural status bytes",
        [("offset", BYTES), ("p", P64)],
        lambda offset, p: _case(opcode, operands=(offset,), p=p),
        fixed=f"PC = ${PC:04X}", sampled="")]
    if opcode == 0xD0:                      # BNE: the representative
        domains.append(Domain(
            "every displacement from every low byte of PC, in two pages, "
            "taken and not taken",
            [("offset", BYTES), ("low", BYTES), ("high", (0x12, 0xFF)),
             ("z", (0, 1))],
            lambda offset, low, high, z: _case(
                opcode, pc=high << 8 | low, operands=(offset,),
                p=0x20 | (z << 1)),
            fixed="", sampled="",
            ))
    else:
        domains.append(Domain(
            "every displacement from edge low bytes of PC, in two pages",
            [("offset", BYTES), ("low", EDGE8), ("high", (0x12, 0xFF))],
            lambda offset, low, high: _case(
                opcode, pc=high << 8 | low, operands=(offset,),
                p=0x20 | _branch_taken_status(info)),
            fixed="the branch is taken",
            sampled="PC low byte: 8 edge values.  0xD0 BNE carries the "
                    "exhaustive sweep over all 256 low bytes"))
    return domains


_BRANCH_FLAG = {"BPL": (7, 0), "BMI": (7, 1), "BVC": (6, 0), "BVS": (6, 1),
                "BCC": (0, 0), "BCS": (0, 1), "BNE": (1, 0), "BEQ": (1, 1)}


def _branch_taken_status(info) -> int:
    bit, wanted = _BRANCH_FLAG[info.mnemonic]
    return wanted << bit


def _stack_domains(opcode: int, info) -> list[Domain]:
    mnemonic = info.mnemonic
    pulled = lambda s: (0x100 | (s + 1) & 0xFF)
    if mnemonic == "PHA":
        return [Domain("every stack pointer against every accumulator",
                       [("s", BYTES), ("a", BYTES)],
                       lambda s, a: _case(opcode, s=s, a=a),
                       fixed="P, PC", sampled="")]
    if mnemonic == "PHP":
        return [Domain("every stack pointer against all 64 status bytes",
                       [("s", BYTES), ("p", P64)],
                       lambda s, p: _case(opcode, s=s, p=p),
                       fixed="PC", sampled="")]
    if mnemonic == "PLA":
        return [Domain("every stack pointer against every pulled byte",
                       [("s", BYTES), ("m", BYTES)],
                       lambda s, m: _case(opcode, s=s,
                                          cells={pulled(s): m}),
                       fixed="P, PC", sampled="")]
    if mnemonic == "PLP":
        return [Domain("every stack pointer against every pulled status byte",
                       [("s", BYTES), ("m", BYTES)],
                       lambda s, m: _case(opcode, s=s,
                                          cells={pulled(s): m}),
                       fixed="PC", sampled="")]
    if mnemonic == "JSR":
        return [Domain("every stack pointer against every low byte of PC",
                       [("s", BYTES), ("low", BYTES)],
                       lambda s, low: _case(opcode, s=s, pc=0x12 << 8 | low,
                                            operands=(0x34, 0x80)),
                       fixed="target $8034, P",
                       sampled="PC high byte = 0x12; the pushed value is "
                               "PC+2, so every low byte exercises the carry")]
    if mnemonic == "RTS":
        return [
            Domain("every stack pointer against every pulled low byte, "
                   "pulled high byte 0xFF so PC+1 carries and wraps",
                   [("s", BYTES), ("low", BYTES)],
                   lambda s, low: _case(
                       opcode, s=s,
                       cells={pulled(s): low,
                              0x100 | (s + 2) & 0xFF: 0xFF}),
                   fixed="P, PC", sampled=""),
            Domain("every stack pointer against every pulled high byte",
                   [("s", BYTES), ("high", BYTES)],
                   lambda s, high: _case(
                       opcode, s=s,
                       cells={pulled(s): 0xFF,
                              0x100 | (s + 2) & 0xFF: high}),
                   fixed="pulled low byte 0xFF, P, PC", sampled=""),
        ]
    if mnemonic == "RTI":
        return [
            Domain("every stack pointer against every pulled status byte",
                   [("s", BYTES), ("m", BYTES)],
                   lambda s, m: _case(
                       opcode, s=s,
                       cells={pulled(s): m,
                              0x100 | (s + 2) & 0xFF: 0x34,
                              0x100 | (s + 3) & 0xFF: 0x12}),
                   fixed="pulled PC = $1234, P", sampled=""),
            Domain("every stack pointer against every pulled low byte of PC",
                   [("s", BYTES), ("low", BYTES)],
                   lambda s, low: _case(
                       opcode, s=s,
                       cells={pulled(s): 0xFF,
                              0x100 | (s + 2) & 0xFF: low,
                              0x100 | (s + 3) & 0xFF: 0xFF}),
                   fixed="pulled status 0xFF, pulled PC high 0xFF",
                   sampled=""),
        ]
    if mnemonic == "BRK":
        return [Domain("every stack pointer against all 64 status bytes",
                       [("s", BYTES), ("p", P64)],
                       lambda s, p: _case(opcode, s=s, p=p,
                                          cells={0xFFFE: 0x34, 0xFFFF: 0x12}),
                       fixed="IRQ vector -> $1234, PC",
                       sampled="")]
    raise AssertionError(mnemonic)


def _implied_domains(opcode: int, info) -> list[Domain]:
    mnemonic = info.mnemonic
    source = {"TAX": "a", "TAY": "a", "TXA": "x", "TYA": "y", "TSX": "s",
              "TXS": "x", "INX": "x", "INY": "y", "DEX": "x",
              "DEY": "y"}.get(mnemonic)
    if source is None:                       # CLC/SEC/CLI/SEI/CLD/SED/CLV/NOP
        return [Domain("all 64 architectural status bytes (complete: the "
                       "result reads nothing else)",
                       [("p", P64)], lambda p: _case(opcode, p=p),
                       fixed="PC, registers (not read)", sampled="")]
    return [Domain(f"every {source.upper()} against all 64 status bytes "
                   f"(complete: the result reads nothing else)",
                   [(source, BYTES), ("p", P64)],
                   lambda p, **kw: _case(opcode, p=p, **kw),
                   fixed="PC and the registers the result does not read",
                   sampled="")]


def _jump_domains(opcode: int, info) -> list[Domain]:
    if info.mode == "abs":
        return [Domain("every one of the 65,536 jump targets",
                       [("low", BYTES), ("high", BYTES)],
                       lambda low, high: _case(opcode, operands=(low, high)),
                       fixed="registers, P", sampled="")]
    return [Domain("every one of the 65,536 indirect pointers, which covers "
                   "the NMOS page-crossing bug exhaustively",
                   [("low", BYTES), ("high", BYTES)],
                   lambda low, high: _case(
                       opcode, operands=(low, high),
                       cells={high << 8 | low: 0x34,
                              high << 8 | (low + 1) & 0xFF: 0x12}),
                   fixed="registers, P",
                   sampled="the pointed-to bytes are $34/$12; the target "
                           "value is not a dimension of the bug")]


def _memory_domains(opcode: int, info) -> list[Domain]:
    """Value and address domains for the eight memory addressing modes."""
    mnemonic, mode = info.mnemonic, info.mode
    register = _REGISTER.get(mnemonic, "a")
    full = ATLAS.get(mode) == opcode
    index = {"zpx": "x", "abx": "x", "izx": "x",
             "zpy": "y", "aby": "y", "izy": "y"}.get(mode)
    target = FAR << 8 | 0x34        # an address no sweep collides with

    def with_address(value, **registers):
        """A case whose effective address is fixed, whatever the index is.

        The operand bytes are solved backwards from the index register, so
        every case in a value domain reads and writes the same cell and the
        value axis is not entangled with the address axis.
        """
        x = registers.get("x", 0x04)
        y = registers.get("y", 0x04)
        if mode == "zp":
            return _case(opcode, operands=(0x34,), cells={0x0034: value},
                         **registers)
        if mode == "zpx":
            return _case(opcode, operands=((0x34 - x) & 0xFF,),
                         cells={0x0034: value}, **registers)
        if mode == "zpy":
            return _case(opcode, operands=((0x34 - y) & 0xFF,),
                         cells={0x0034: value}, **registers)
        if mode == "abs":
            return _case(opcode, operands=(0x34, FAR), cells={target: value},
                         **registers)
        if mode in ("abx", "aby"):
            base = (target - (x if mode == "abx" else y)) & 0xFFFF
            return _case(opcode, operands=(base & 0xFF, base >> 8),
                         cells={target: value}, **registers)
        if mode == "izx":
            return _case(opcode, operands=((0x14 - x) & 0xFF,),
                         cells={0x0014: 0x34, 0x0015: FAR, target: value},
                         **registers)
        if mode == "izy":
            base = (target - y) & 0xFFFF
            return _case(opcode, operands=(0x10,),
                         cells={0x0010: base & 0xFF, 0x0011: base >> 8,
                                target: value},
                         **registers)
        raise AssertionError(mode)

    #: whether this encoding carries its mnemonic's full value sweep
    value_atlas = VALUE_ATLAS.get(mnemonic) == opcode
    #: does the operation consume the incoming carry?
    #: both carries are enumerated for every memory operation: for the ones
    #: that consume C it is a real dimension, for the rest it is a check that
    #: the result does not depend on it
    carry_axis = [("c", (0, 1))]
    domains = []
    #: 1. the value domain: every byte at the effective address
    if mnemonic == "SAX":
        axes = ([("a", BYTES), ("x", BYTES)] if value_atlas
                else [("a", BYTES), ("x", EDGE4)])
        domains.append(Domain(
            "every A against " + ("every X" if value_atlas
                                  else "edge X values")
            + "; the byte stored is A&X",
            axes,
            lambda a, x: with_address(0x00, a=a, x=x),
            fixed="P, PC, the address and the byte already there",
            sampled="" if value_atlas else
                    "X: 4 edge values.  0x87 SAX zp carries the full "
                    "256x256 sweep"))
    elif mnemonic in _STORE_ONLY:
        domains.append(Domain(
            f"every {register.upper()} stored, against edge bytes already "
            f"at the address",
            [(register, BYTES), ("m", EDGE4)],
            lambda m, **kw: with_address(m, **kw),
            fixed="P, PC, the address",
            sampled="the byte already at the address: 4 edge values"))
    elif mnemonic == "LAS":
        domains.append(Domain(
            "every byte at the effective address against every stack "
            "pointer; the result is M&S",
            [("m", BYTES), ("s", BYTES)],
            lambda m, s: with_address(m, s=s),
            fixed="P, PC, the address", sampled=""))
    elif mnemonic in _RMW:
        combines = mnemonic in ("SLO", "RLA", "SRE", "RRA", "DCP", "ISC")
        axes = [("m", BYTES)] + carry_axis
        extra = ""
        if combines:
            axes.append(("a", BYTES if value_atlas else EDGE8))
            extra = ("" if value_atlas else
                     f"A: 8 edge values.  "
                     f"0x{VALUE_ATLAS[mnemonic]:02X} {mnemonic} zp carries "
                     f"the full 256x256 A-by-operand sweep")
        domains.append(Domain(
            "every byte at the effective address, both carries"
            + (", against every A" if combines and value_atlas else
               ", against edge A values" if combines else ""),
            axes,
            lambda m, c, a=0x5A: with_address(m, a=a, p=_carry(c)),
            fixed="PC, S, the address",
            sampled=extra or "A is not read by this instruction"))
    else:
        span = BYTES if value_atlas else EDGE8
        axes = [("m", BYTES), (register, span)] + carry_axis
        domains.append(Domain(
            f"every byte at the effective address against "
            + ("every " if value_atlas else "edge ")
            + f"{register.upper()}, both carries",
            axes,
            lambda m, c, **kw: with_address(m, p=_carry(c), **kw),
            fixed="PC, S, the address",
            sampled="" if value_atlas else
                    f"{register.upper()}: 8 edge values.  The immediate form "
                    f"of this operation carries the exhaustive 256x256 "
                    f"register-by-operand sweep"
                    if mnemonic not in VALUE_ATLAS else
                    f"{register.upper()}: 8 edge values.  "
                    f"0x{VALUE_ATLAS.get(mnemonic, 0):02X} carries the "
                    f"exhaustive 256x256 sweep"))

    #: 2. the address domain: every operand byte, and every index where the
    #: index is what makes the address interesting (wrap, page crossing)
    value, reg = 0xA5, {register: 0x5A}
    if mode == "zp":
        domains.append(Domain(
            "all 256 zero-page addresses",
            [("operand", BYTES)],
            lambda operand: _case(opcode, operands=(operand,),
                                  cells={operand: value}, **reg),
            fixed="the byte at the address", sampled=""))
    elif mode in ("zpx", "zpy"):
        span = BYTES if full else EDGE8
        domains.append(Domain(
            "every operand byte against "
            + ("every index value: page-zero wrap, exhaustively"
               if full else "edge index values"),
            [("operand", BYTES), (index, span)],
            lambda operand, **kw: _case(
                opcode, operands=(operand,),
                cells={(operand + list(kw.values())[0]) & 0xFF: value},
                **dict(reg, **kw)),
            fixed="the byte at the address",
            sampled="" if full else
                    f"{index.upper()}: 8 edge values.  "
                    f"0x{ATLAS[mode]:02X} carries the full 256x256 sweep"))
    elif mode == "abs":
        span = BYTES if full else EDGE8
        domains.append(Domain(
            "every absolute address"
            if full else "every low byte against edge high bytes",
            [("low", BYTES), ("high", span)],
            lambda low, high: _case(opcode, operands=(low, high),
                                    cells={high << 8 | low: value}, **reg),
            fixed="the byte at the address",
            sampled="" if full else
                    f"high byte: 8 edge values.  0x{ATLAS[mode]:02X} carries "
                    f"the full 65,536-address sweep"))
    elif mode in ("abx", "aby"):
        span = BYTES if full else EDGE8
        domains.append(Domain(
            "every base low byte against "
            + ("every index value, in a middle page and at the top of the "
               "address space: page crossing and 16-bit wrap, exhaustively"
               if full else "edge index values"),
            [("low", BYTES), (index, span), ("high", (FAR, 0xFF))],
            lambda low, high, **kw: _case(
                opcode, operands=(low, high),
                cells={(high << 8 | low) + list(kw.values())[0] & 0xFFFF:
                       value}, **dict(reg, **kw)),
            fixed="the byte at the address",
            sampled="" if full else
                    f"{index.upper()}: 8 edge values.  "
                    f"0x{ATLAS[mode]:02X} carries the full sweep"))
    elif mode == "izx":
        span = BYTES if full else EDGE8
        domains.append(Domain(
            "every pointer operand against "
            + ("every X: the page-zero pointer wrap, exhaustively"
               if full else "edge X values"),
            [("operand", BYTES), ("x", span)],
            lambda operand, x: _case(
                opcode, operands=(operand,),
                cells={(operand + x) & 0xFF: 0x34,
                       (operand + x + 1) & 0xFF: FAR, target: value}, **reg),
            fixed="the pointer contents ($2034) and the byte there",
            sampled="" if full else
                    f"X: 8 edge values.  0x{ATLAS[mode]:02X} carries the "
                    f"full 256x256 sweep"))
    elif mode == "izy":
        span = BYTES if full else EDGE8
        domains.append(Domain(
            "every base low byte in the pointer against "
            + ("every Y, with the base in a middle page and at the top: "
               "the base+Y carry, exhaustively"
               if full else "edge Y values"),
            [("low", BYTES), ("y", span), ("high", (FAR, 0xFF))],
            lambda low, y, high: _case(
                opcode, operands=(0x10,),
                cells={0x0010: low, 0x0011: high,
                       (high << 8 | low) + y & 0xFFFF: value}, **reg),
            fixed="the byte at the address",
            sampled="" if full else
                    f"Y: 8 edge values.  0x{ATLAS[mode]:02X} carries the "
                    f"full sweep"))
    return domains


_STORE_ONLY = frozenset({"STA", "STX", "STY", "SAX"})


def _havoc_domains(opcode: int, info) -> list[Domain]:
    mnemonic = info.mnemonic
    if mnemonic in ("XAA", "LXA"):
        return [Domain(
            "every immediate operand against edge A and X; only what the "
            "model still fixes is checked",
            [("m", BYTES), ("a", EDGE8), ("x", EDGE8)],
            lambda m, a, x: _case(opcode, operands=(m,), a=a, x=x),
            fixed="P, PC, S", sampled="A, X: 8 edge values each")]
    #: SHA / SHX / SHY / TAS: one unconstrained write
    index = "x" if mnemonic == "SHY" else "y"
    if info.mode == "izy":
        return [Domain(
            "every pointer base low byte against edge index values; only "
            "what the model still fixes is checked",
            [("low", BYTES), (index, EDGE8), ("a", EDGE4), ("x", EDGE4)],
            lambda low, a, x, **kw: _case(
                opcode, operands=(0x10,), a=a, x=x,
                cells={0x0010: low, 0x0011: FAR}, **kw),
            fixed="P, PC, S", sampled="index, A, X: edge values")]
    return [Domain(
        "every base low byte against edge index values; only what the model "
        "still fixes is checked",
        [("low", BYTES), (index, EDGE8), ("a", EDGE4), ("x", EDGE4)],
        lambda low, a, x, **kw: _case(opcode, operands=(low, FAR), a=a, x=x,
                                      **kw),
        fixed="P, PC, S", sampled="index, A, X: edge values")]


def mnemonic_of(info) -> str:
    return info.mnemonic


def domains_for(opcode: int) -> list[Domain]:
    info = OPCODES[opcode]
    mnemonic, mode = info.mnemonic, info.mode
    if opcode in JAM_OPCODES:
        return []
    if opcode in HAVOC_OPCODES:
        return _havoc_domains(opcode, info)
    if mode == "rel":
        return _branch_domains(opcode, info)
    if mnemonic in ("PHA", "PHP", "PLA", "PLP", "JSR", "RTS", "RTI", "BRK"):
        return _stack_domains(opcode, info)
    if mnemonic == "JMP":
        return _jump_domains(opcode, info)
    if mode == "imm":
        return _immediate_domains(opcode, info)
    if mode == "acc":
        return [Domain("every accumulator against all 64 status bytes "
                       "(complete: the result reads nothing else)",
                       [("a", BYTES), ("p", P64)],
                       lambda a, p: _case(opcode, a=a, p=p),
                       fixed="PC, S", sampled="")]
    if mode == "imp":
        return _implied_domains(opcode, info)
    return _memory_domains(opcode, info)


# -- driver -----------------------------------------------------------------

def check_opcode(job: tuple) -> dict:
    opcode, = job
    info = OPCODES[opcode]
    result = {"opcode": f"0x{opcode:02X}", "mnemonic": info.mnemonic,
              "mode": info.mode, "documented": info.documented}
    if opcode in JAM_OPCODES:
        result.update(group="jam", compared=0, agreed=0, admitted=0,
                      mismatch_count=0, mismatches=[], domains=[],
                      note="the model halts and NMOS2A03 raises Jam; there "
                           "is no instruction outcome to compare")
        return result
    havoc = opcode in HAVOC_OPCODES
    reference = Reference()
    started = time.time()
    failures, bad, total = [], 0, 0
    described = []
    for domain in domains_for(opcode):
        described.append(domain.describe())
        for case in domain.cases():
            total += 1
            try:
                failure = compare(case, reference, havoc=havoc)
            except Exception as exc:
                failure = {"case": _describe(case),
                           "fault": f"{type(exc).__name__}: {exc}"}
            if failure is not None:
                bad += 1
                if len(failures) < MISMATCH_CAP:
                    failure["domain"] = domain.label
                    failures.append(failure)
    result.update(group="havoc" if havoc else "stable", compared=total,
                  mismatch_count=bad, mismatches=failures,
                  domains=described, seconds=round(time.time() - started, 1))
    if havoc:
        result.update(admitted=total - bad, agreed=0,
                      note="modelled as havoc; the number is how many of "
                           "NMOS2A03's outcomes the havoc admits, not "
                           "agreement")
    else:
        result.update(agreed=total - bad, admitted=0)
    return result


def run(jobs: int, opcodes=None) -> dict:
    opcodes = sorted(opcodes if opcodes is not None else range(256))
    jobs = max(1, min(jobs, MAX_JOBS))
    started = time.time()
    work = [(op,) for op in opcodes]
    if jobs == 1:
        results = [check_opcode(job) for job in work]
    else:
        with multiprocessing.Pool(jobs) as pool:
            results = list(pool.imap_unordered(check_opcode, work,
                                               chunksize=1))
    results.sort(key=lambda r: r["opcode"])
    elapsed = time.time() - started
    groups = {}
    for group in ("stable", "havoc", "jam"):
        rows = [r for r in results if r["group"] == group]
        groups[group] = {
            "opcodes": len(rows),
            "compared": sum(r["compared"] for r in rows),
            "agreed": sum(r["agreed"] for r in rows),
            "admitted": sum(r["admitted"] for r in rows),
            "mismatches": sum(r["mismatch_count"] for r in rows),
        }
    compared = sum(g["compared"] for g in groups.values())
    return {
        "model": "formal/model/cpu.py",
        "reference": "formal/dyn/cpu6502.py (NMOS2A03: py65's core, extended "
                     "for the 2A03 and all 256 opcodes)",
        "kind": "exhaustive over the named per-opcode domains; the dimensions "
                "each domain samples are named with it",
        "shared_code": "the two implementations share only the opcode table "
                       "in analysis/decoder.py, which fixes mnemonic, "
                       "addressing mode and length but no semantics",
        "not_covered": [
            "the remaining registers and the RAM outside each domain's cells",
            "cycle counts and interrupt timing",
            "the 12 JAM encodings (both stop; no outcome to compare)",
            "the six unstable instructions, where only admission is checked",
        ],
        "jobs": jobs,
        "wall_seconds": round(elapsed, 1),
        "instructions_per_second": (round(compared / elapsed, 1)
                                    if elapsed else None),
        "mismatch_cap_per_opcode": MISMATCH_CAP,
        "totals": groups,
        "per_opcode": results,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=MAX_JOBS)
    parser.add_argument("--opcodes", default=None)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the domain sizes and exit")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    opcodes = (list(range(256)) if args.opcodes is None
               else [int(t, 16) for t in args.opcodes.split(",")])
    if args.dry_run:
        total = 0
        for opcode in opcodes:
            info = OPCODES[opcode]
            domains = domains_for(opcode)
            count = sum(d.count for d in domains)
            total += count
            print(f"0x{opcode:02X} {info.mnemonic:5s} {info.mode:4s} "
                  f"{count:9d}  " + "; ".join(d.label[:40] for d in domains))
        print(f"total cases {total}")
        return 0
    report = run(args.jobs, opcodes)
    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "results", "reports", "model_exhaustive_equivalence.json")
    with open(out, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    for group, counts in report["totals"].items():
        print(f"{group:7s} opcodes {counts['opcodes']:3d}  "
              f"compared {counts['compared']:8d}  "
              f"agreed {counts['agreed']:8d}  "
              f"admitted {counts['admitted']:7d}  "
              f"mismatches {counts['mismatches']}")
    print(f"{report['wall_seconds']}s on {report['jobs']} cores, "
          f"{report['instructions_per_second']} instructions/second")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
