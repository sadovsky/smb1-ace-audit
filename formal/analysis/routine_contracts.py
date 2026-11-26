"""Routine contracts for the proposer (plan section 8).

A contract is `(Mod, use, Post, kind, s0)` exactly as
`formal/verify/certificate.py` reads it.  Everything here is derived from the
abstract interpretation in `invariants.py` and is **untrusted**: a `Mod` that
is too small, a `use` that is too small or a `Post` that is too strong shows
up as a failed `VC-MOD`, `VC-CALL-USE`, `VC-CALL-MOD` or `VC-RET-POST`, not as
a wrong conclusion.

A routine is named by its entry address.  Entries are the targets of `JSR`
(other than the JumpEngine, which is not a routine: the certificate checker
executes it inline inside `VC-DISPATCH`), plus the reset and NMI vectors.  A
node can belong to several routines -- shared tails, and the `BIT abs` overlap
idiom that gives a routine two entry points -- which is why a certificate
context is a *pair* of an instruction start and a routine.
"""
from __future__ import annotations

from dataclasses import dataclass

from analysis.cfg import JUMPENGINE, CFG
from analysis.decoder import Flow

from .abstract_domains import FULL, Abs

ALL_CELLS = frozenset(range(0x800))


@dataclass
class Contract:
    entry: int
    kind: str = "normal"                 # "normal" | "handler" | "root"
    mod: frozenset = frozenset()
    use: int = 0
    post: Abs = Abs.BOTTOM               # joined exit state
    post_en: frozenset = frozenset()
    s0: int | None = None
    #: no write in this routine or its callees can reach PPU control, so a
    #: call to it leaves the ghost NMI-enable bit alone
    no_ppu: bool = True
    #: registers no instruction in this routine or its callees writes
    preserves: frozenset = frozenset({"a", "x", "y"})
    #: `(register, bit)` when every exit's enable value equals that bit of
    #: that register, which is how `$8EED` keeps the enable bit pinned
    en_bit: tuple | None = None
    #: diagnostics, not part of the certificate
    reason_mod_all: str = ""
    returns: int = 0

    def to_json(self, tracked: frozenset) -> dict:
        from formal.verify.certificate import encode_cell_runs

        out: dict = {"kind": self.kind, "mod": encode_cell_runs(self.mod),
                     "use": self.use, "no_ppu": self.no_ppu}
        if self.s0 is not None:
            out["s0"] = self.s0
        post: dict = {"en": sorted(self.post_en) or [0, 1]}
        if self.preserves and self.kind == "normal":
            post["preserves"] = sorted(self.preserves)
        if self.en_bit is not None:
            post["en_bit"] = list(self.en_bit)
        state = self.post
        if not state.bottom:
            for name in ("a", "x", "y"):
                mask = state.register(name)
                if mask != FULL:
                    post[name] = _runs(mask)
            if self.kind != "handler":
                for name in ("c", "z", "n", "v"):
                    value = getattr(state, name)
                    if value is not None:
                        post[name] = value
            # For the handler the other flags are omitted: `Post[H]` is
            # checked on the state after the `RTI`, which restores them from
            # the interrupt frame, so such a clause could never be discharged
            # (`formal/lean/FINDINGS.md` F3).  `I` is the exception -- the
            # saved status has it set, which is the `status_i` conjunct.
            cells = {f"{cell:04X}": _runs(mask)
                     for cell, mask in state.cells
                     if cell in tracked and cell in self.mod}
            if cells:
                post["cells"] = cells
        out["post"] = post
        return out


def _runs(mask: int):
    from .abstract_domains import _runs as runs

    return runs(mask)


def routine_entries(graph: CFG) -> dict[int, str]:
    """Entry address -> routine kind."""
    out: dict[int, str] = {}
    for node in graph.nodes.values():
        instruction = node.instruction
        if (instruction.info.flow is Flow.CALL
                and instruction.operand16 != JUMPENGINE
                and instruction.operand16 in graph.nodes):
            out[instruction.operand16] = "normal"
    word = lambda a: graph.read_byte(a) | graph.read_byte(a + 1) << 8
    out[word(0xFFFA)] = "handler"
    out[word(0xFFFC)] = "root"
    return out
