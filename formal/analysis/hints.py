"""Hand-supplied invariant hints for the proposer.

A hint is an *untrusted suggestion*: it adds conjuncts to a proposed abstract
state at one program point.  The checker decides whether the result is
inductive, so a wrong hint produces a failed verification condition and never
a wrong conclusion.  Hints exist for shapes the abstract domain cannot infer
on its own.

Two forms, both keyed by `"PPPP"` or the full context key `"PPPP@RRRR/E"`:

* a function `(Abs, Proposer) -> Abs`, applied when the proposer reaches that
  context;
* `"json:..."` -> a dict merged into the emitted invariant, for conjuncts the
  abstract domain has no field for.

## The RAM-clearing loop at `$90CC`

Everything here is for one loop, and that loop is the reason any RAM cell has
a domain at all.  Reset reaches `$8057` with the ghost NMI-enable bit set, and
from there the NMI handler runs the game; the handler's entry state is
therefore the join over every state in which an NMI may begin, and if RAM is
unconstrained there then no cell invariant exists anywhere.  Reset's only
RAM-establishing step is the loop at `$90CC`, and `transitions.py` admits a
warm reset at every instruction boundary, so the loop has to work from a
completely unconstrained RAM.

The loop, from the image:

    $90CC  LDX #$07          ; page counter, 7 down to 0
    $90CE  LDA #$00
    $90D0  STA $06           ; pointer low
    $90D2  STX $07           ; pointer high = the page   <- outer head
    $90D4  CPX #$01                                      <- inner head
    $90D6  BNE $90DC         ; page 1 is special
    $90D8  CPY #$60
    $90DA  BCS $90DE         ; ... its top half is the stack, skip it
    $90DC  STA ($06),Y       ; RAM[page, Y] = 0
    $90DE  DEY
    $90DF  CPY #$FF
    $90E1  BNE $90D4
    $90E3  DEX
    $90E4  BPL $90D2
    $90E6  RTS

`Y` enters as `$FE` or `$D6` (the warm-boot check at `$8018-$8029` chooses),
and inside the loop it runs `$FF` down to `$00` and then wraps to `$FF`, which
is how the inner loop terminates.  That wrap is why the invariant cannot be
stated at the inner head with a single comparison: `Y = $FF` is both the first
and the last value.  So the run is written three ways around the loop body --
strictly above `Y` before the store, from `Y` after the store, and from
`Y + 1` after the `DEY`, which is the point where `Y = $FF` means "the whole
page".

`upto` differs per page: page 1 is only cleared to `$015F`, and page 7 only to
`$0700 + Y`, so `$D6` is the sound bound for both of `Y`'s entry values.  The
cells above those bounds are the `except` list, and they are exactly the cells
a warm reset preserves -- the stack and the top of page 7, which is where the
game's own warm-boot signature lives.
"""
from __future__ import annotations

from dataclasses import replace

from . import abstract_domains as ad


#: the highest index each page is cleared up to
UPTO = {0: 0xFF, 1: 0x5F, 2: 0xFF, 3: 0xFF, 4: 0xFF, 5: 0xFF, 6: 0xFF,
        7: 0xD6}
#: cells the loop does not clear: the stack and the top of page 7
PRESERVED = ("0160-01FF", "07D7-07FF")
PRESERVED_CELLS = frozenset(range(0x160, 0x200)) | frozenset(
    range(0x7D7, 0x800))

ZERO_PAGES = {"reg": "x", "except": list(PRESERVED)}


def _runs(comparison: str) -> list[dict]:
    return [{"page": page, "reg": "y", "cmp": comparison,
             "upto": UPTO[page], "when": ["x", page]} for page in range(8)]


#: before the store: cells strictly above Y are already zero
BEFORE = {"zero_pages": ZERO_PAGES, "zero_runs": _runs("ult")}
#: after the store: cell Y is zero too
AFTER = {"zero_pages": ZERO_PAGES, "zero_runs": _runs("ule")}
#: after the DEY: Y + 1, so Y = $FF means the whole page
DECREMENTED = {"zero_pages": ZERO_PAGES, "zero_runs": _runs("ule1")}
#: after the DEX: only the page-level fact survives, and it survives because
#: the comparison is signed -- X = $FF is "every page"
OUTER = {"zero_pages": ZERO_PAGES}


def _common(state, pages):
    """What the value-set domain loses to widening inside the loop.

    The store's address set is 2048 wide, so the domain forgets every tracked
    cell, and the loop is re-entered often enough that the proposer widens the
    registers too.  Each fact restored here is a one-step consequence of the
    previous iteration: `A` is only ever the zero loaded at `$90CE`, the
    pointer's low byte stays zero because zero is the only value stored, and
    `X` stays inside `0..7` because of the `BPL` at `$90E4`.

    Every fact is *intersected* with what the proposer already has, never
    substituted.  That matters on the skip path for page 1, where the
    `CPX #$01` has narrowed `X` to exactly 1: replacing `X` by `0..7` there
    would make the other pages' guarded runs claim a cell the skipped store
    never wrote.
    """
    state = state.set_cell(0x06, state.cell(0x06) & ad.one(0))
    return replace(state, a=state.a & ad.one(0),
                   x=state.x & ad.from_values(pages))


def _outer(state, proposer):
    """At `$90D2`: `RAM[$07]` is still the previous page, so say nothing."""
    return _common(state, range(8))


def _page_set(state, proposer):
    """At `$90CE` and `$90D0`: the page counter is still its initial 7."""
    return _common(state, (7,))


def _loop_body(state, proposer):
    """Inside the loop: `RAM[$07]` is the page and equals `X`.

    `RAM[$07] == X` survives the store because the only cell of page `X` that
    can be `$0007` is reached when `X` is zero, and then zero is what is
    stored.
    """
    state = _common(state, range(8))
    state = state.set_cell(0x07, state.cell(0x07) & ad.from_values(range(8)))
    return replace(state, copies=state.copies | {("x", 0x07)})


def _after_dex(state, proposer):
    """At `$90E4`: `X` has just been decremented, so `$FF` is possible."""
    state = _common(state, list(range(8)) + [0xFF])
    return state.set_cell(0x07, state.cell(0x07) & ad.from_values(range(8)))


def _cleared(state, proposer):
    """At the `RTS`: every tracked cell the loop reaches is zero."""
    for cell in sorted(proposer.tracked):
        if cell not in PRESERVED_CELLS:
            state = state.set_cell(cell, ad.one(0))
    return state


#: The return point of reset's `JSR $90CC`.  Before it, RAM is whatever the
#: previous run or power-on left, so the mirror says nothing; the clearing
#: loop is what establishes it.  The enable bit cannot be set in that window
#: either way: the only PPU-control write reset makes before it is `$8004`,
#: with `#$10`.
MIRROR_FROM = 0x802E


def _enable_mirror(state, proposer, en, pc, routine):
    """Bit 7 of `RAM[$0778]` is set only while NMI is enabled.

    `$0778` is the program's own mirror of PPU control, and every write to
    PPU control except two writes the same byte to both.  The two exceptions
    both keep the implication: reset's `$8004` writes `#$10` (bit 7 clear,
    enable clear), and the handler's `$817E` writes `A | $80` without
    touching the mirror, which sets the enable bit while the mirror's bit 7
    stays clear.

    So for every context whose ghost enable bit is 0, bit 7 of the mirror is
    clear.  That is the fact the handler needs at `$8168`, where it copies the
    mirror back into PPU control: without it the copy might re-enable NMI, the
    enable bit forks, and from there it leaks into every context in the
    program.  It is *not* something the value-set domain can discover, because
    the mirror is written through routines shared with reset, which enables
    NMI on purpose.

    It does not hold on reset's first instructions, before the clearing loop
    has run; see `MIRROR_FROM`.

    Stated as a hint and checked like everything else: `VC-STEP` has to show
    every store preserves it, and `VC-CALL-RETURN` that every contract does.
    """
    if en or (routine == proposer.root and pc < MIRROR_FROM):
        return state
    return state.set_cell(0x778, state.cell(0x778)
                          & ad.from_values(range(0x80)))


HINTS: dict = {
    "*": _enable_mirror,
    # the invariant conjuncts the domain cannot hold
    "json:90CE": BEFORE, "json:90D0": BEFORE, "json:90D2": BEFORE,
    "json:90D4": BEFORE, "json:90D6": BEFORE, "json:90D8": BEFORE,
    "json:90DA": BEFORE, "json:90DC": BEFORE,
    "json:90DE": AFTER,
    "json:90DF": DECREMENTED, "json:90E1": DECREMENTED,
    "json:90E3": DECREMENTED,
    "json:90E4": OUTER,
    # the value-set facts the wide store and the widening destroy
    "90CE": _page_set, "90D0": _page_set,
    "90D2": _outer,
    "90D4": _loop_body, "90D6": _loop_body,
    "90D8": _loop_body, "90DA": _loop_body, "90DC": _loop_body,
    "90DE": _loop_body, "90DF": _loop_body, "90E1": _loop_body,
    "90E3": _loop_body,
    "90E4": _after_dex,
    "90E6": _cleared,
}
