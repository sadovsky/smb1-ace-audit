# Cycle-level NMI timing: MA-NMI-EDGE and MA-NMI-LATENCY

`model/transitions.py` is an instruction-granularity relation. It cannot say
*when* inside an instruction an NMI is taken, so it lets one be taken at every
boundary at which the ghost enable bit is set, and the two statements the joint
invariant needs are listed there as assumptions. This file says what happens
when they are instead derived from a stated cycle-level model.

Nothing here changes `transitions.py` or `cpu.py`. `model/interrupt_timing.py`
is a separate module; `python3 -m formal.model.interrupt_timing` writes
`results/reports/interrupt_timing.json`, and
`formal/tests/test_interrupt_timing.py` is its test suite.

## The model

Three parts and nothing else.

1. **Instruction shape**, read out of the SingleStepTests `nes6502` vectors:
   cycles per instruction, and which cycle each write lands on. Not typed from
   memory; a disagreement among vectors raises rather than being averaged.
2. **The CPU's NMI path**, as a five-bit state machine: `vblank_flag`,
   `NMI_output`, the detector's previous sample, the edge flip-flop, and the
   delayed internal signal. Every rule carries the NESdev sentence it came
   from, in the module docstring and in the report's `cycle_model.rules`.
3. **The PPU reduced to one bit**: `vblank_flag`, which the CPU clears by
   reading `$2002` and which the environment may set or clear on *any* cycle.
   That over-approximates the real set and clear events by dropping when they
   happen. Where a derivation needs the timing back, it is named as a premise.

Both windows are straight-line code. Instructions whose poll point NESdev
documents as special are **refused**, not approximated: a taken branch polls
before the third cycle rather than the second-to-last, and `BRK` can be
hijacked, so `build_window` raises on either. Neither window contains one.
`RTI`/`PLP`/`CLI`/`SEI` are peculiar only about the `I` flag, which does not
mask NMI, so the uniform rule is used for the `RTI` at `$8181`.

Two rules the sources do not settle are left as parameters and **both settings
are enumerated**, so no verdict rests on a guess: whether a `$2000` write is
visible to the detector on its own cycle, and whether the CPU's poll reads the
delayed internal signal or the flip-flop. Every verdict below is identical
under all four combinations.

## Method

Exhaustive enumeration of every adversarial `vblank_flag` timing, as
reachability over the 32-configuration state space: two strategies that reach
the same configuration at the same cycle have the same futures, so breadth-first
search over `(cycle, configuration)` covers every strategy. For the epilogue
that is 2 initial states x 3^20 = `6.97 x 10^9` strategies, in 102-106 state
expansions; for the prologue, where the premise leaves the environment two
actions per cycle, 4 x 2^23 = `3.36 x 10^7` strategies in 142 expansions.
`test_search_agrees_with_literal_enumeration`
checks the collapse against literal enumeration of every action sequence on a
short window, for all four parameter settings.

## Results

| id | claim | status | premise |
|---|---|---|---|
| `L-NMI-EDGE-DISABLED` | while the enable bit is clear no NMI can be taken, so two NMI entries need an intervening 0→1 write of it | **proved** | none |
| `L-NMI-EDGE-WINDOW` | no second NMI between interrupt entry and the disabling write at `$808C` | **conditional** | `P-EDGE-NO-SET` |
| `L-NMI-LATENCY` | no NMI between `STA $2000` at `$817E` and the completion of the `RTI` at `$8181` | **conditional** | `P-LATENCY-DISABLED` |

### `L-NMI-EDGE-DISABLED` — proved, and horizon-free

`/NMI` low requires `vblank_flag AND NMI_output`. With `NMI_output` false the
line is high on every φ2 sample, so no high→low transition occurs and the
flip-flop is never set. Checked over the whole 32-configuration space and all
three environment actions rather than over a window of some length, so the
conclusion holds for an unbounded number of cycles. This is the half of
MA-NMI-EDGE that needs no premise, and it is the half the joint invariant
mostly uses.

### `L-NMI-EDGE-WINDOW` — conditional, and refuted without its premise

The window is the 7-cycle entry sequence plus the image's own
`LDA $0778 / AND #$7F / STA $0778 / AND #$7E / STA $2000`: 23 cycles, with the
disabling write landing on cycle 23. Bit 7 of the value it writes is derived
from the image's own `AND #$7F` and `AND #$7E` masks, not asserted.

Inside the window `NMI_output` stays 1 and the only `$2000` write clears it, so
`/NMI` can only go high→low again if `vblank_flag` goes 0→1. Under
`P-EDGE-NO-SET` that cannot happen: no service, and no NMI even pending at the
window's end. Drop the premise and the result is **refuted** on cycle 12 — the
witness is in the report:

    cycle 8   environment clears vblank_flag   (/NMI goes high)
    cycle 9   environment sets   vblank_flag   (/NMI goes low: an edge)
    cycle 10  end of LDA $0778's 3rd of 4 cycles: the poll sees the signal
    cycle 12  the second interrupt sequence begins, at $8085

So the whole weight of this half is on `P-EDGE-NO-SET`, a PPU frame-timing
premise the instruction-level model cannot see. The verdict is unchanged for
entry-sequence lengths 1 through 12, so the one number in the model that is not
vector-validated is not load-bearing.

### `L-NMI-LATENCY` — conditional on a *program* premise, not a timing one

The window is the real epilogue, `$8178`-`$8181`:
`LDA $2002 / PLA / ORA #$80 / STA $2000 / RTI`, 20 cycles. `STA abs` takes 4
cycles and writes on the fourth (vector-validated), so the earliest edge the
write can cause is on cycle 4 of the `STA`, while the `STA`'s poll is at the end
of its cycle 3. The `RTI`'s poll, at the end of its fifth of six cycles, does
see it. Hence: no service between the two instructions, and the NMI is serviced
on absolute cycle 21 — the cycle after the `RTI` completes. That is
MA-NMI-LATENCY, and the derivation is not vacuous: the deferred NMI does
arrive, one instruction late.

The premise is **not** a hardware fact. `P-LATENCY-DISABLED` says `NMI_output`
is false and no NMI is pending when the epilogue starts. Without it the
statement is **refuted**, with two distinct witnesses:

- an NMI already pending at the epilogue's start is taken at the `STA`'s poll
  (cycle 13), between the `STA` and the `RTI`;
- `NMI_output` already set, with `vblank_flag` set by the environment on cycle
  12, gives an edge in time for the same poll.

MA-NMI-LATENCY is therefore not a statement about the instruction pair alone.
It needs the handler to have arrived at `$8178` with NMI disabled, which is a
program property.

## Premises, and whether NESdev states them

| premise | sourcing | what that means |
|---|---|---|
| `P-EDGE-NO-SET` — no event sets `vblank_flag` for 23 cycles from interrupt entry | **implied** | arithmetic from stated numbers, stated nowhere |
| `P-LATENCY-DISABLED` — `NMI_output` clear and no NMI pending at `$8178` | **program** | not a hardware premise at all |
| `P-WRITE-ON-LAST-CYCLE` — the cycle table | **vectors** | established here from the vectors |
| `P-ENTRY-SEQUENCE-7` — 7-cycle entry, no polling | **stated**, with a caveat | the no-polling half is a sentence; the 7 is read off a seven-row table, and is shown not to be load-bearing |
| `P-POLL-READS-DELAYED-SIGNAL` | **implied** | two sentences, composed nowhere; enumerated both ways |
| `P-NO-STATUS-READ-IN-WINDOW` | **program** | checked from the image by the derivation |
| `P-ENABLE-IMMEDIATE-EDGE` | **silent** | no page states it — and **no derivation needs it** |

`P-EDGE-NO-SET` is the one that matters, so here is its arithmetic in full.
`vblank_flag` is set true by one event only, "Start of vertical blanking
(scanline 241, dot 1)"; a frame is "341\*262/3 = 29780 2/3 CPU clocks long" and
the PPU "runs at 3 times the CPU clock rate", so consecutive sets are about
29780 CPU cycles apart. The edge that caused this NMI needed `vblank_flag`
true, and "the VBL flag is cleared 6820 PPU clocks (exactly 20 scanlines) after
it is set", i.e. about 2273 CPU cycles, so that edge was at most ~2273 cycles
after the last set; servicing follows the edge within one instruction plus one
detector cycle. The next set is therefore some 27000 cycles away — far outside
a 23-cycle window. **But** neither page states "`vblank_flag` is set once per
frame" in words, and neither states the vblank duration in CPU cycles. The
premise is implied by arithmetic over four stated numbers, and that is the
honest status.

One note on the reduced PPU. Letting the environment set `vblank_flag` on any
cycle over-approximates the start-of-vblank event; letting it *clear* on any
cycle over-approximates both the end-of-vblank event and a `$2002` read. The
end-of-vblank clear is stated ("End of vertical blanking (scanline 261, dot 1):
Set `vblank_flag` to false."), so a model in which only a `$2002` read clears
the flag would be unsound. The model here does not make that mistake: clears
are free in both derivations, and only *sets* are constrained, by the premise.

## Validation

| | |
|---|---|
| source | SingleStepTests `nes6502` vectors |
| field | `cycles`: one entry per CPU cycle, `[address, value, read\|write]` |
| opcodes | 6 (`AD`, `29`, `09`, `8D`, `40`, `68`) |
| vectors read | 1,800 (300 per opcode) |
| disagreements | 0 |
| derived from them | cycle count; which cycle each write lands on; which cycles touch the operand rather than the instruction's own bytes |

Not validated by anything here, and stated in the report:

- the interrupt entry sequence — the vectors contain no interrupts, so its 7
  cycles and its no-polling rule are prose only;
- the edge detector and the poll point — prose only, no vectors, no
  measurement;
- PPU dot timing — there is no dot or scanline counter in this model, the PPU
  is one bit;
- the two race parameters — enumerated rather than resolved;
- DMA — OAM and DMC DMA stall the CPU and would stretch either window in real
  cycles. They cannot create a `$2000` write or a `vblank_flag` set, so they do
  not affect these derivations, but the cycle counts here are stall-free;
- **no hardware measurement of any kind was taken.**

## The program side, and one finding

`L-NMI-EDGE-DISABLED` says no NMI while the enable bit is clear. Turning that
into "no NMI between `$808C` and `$817E`" needs the program fact that nothing
in between sets the bit. The census in the report finds five direct writes to a
PPUCTRL mirror in the graph, and a three-valued bit-7 analysis settles each:

| site | bit 7 written |
|---|---|
| `$8004` (reset) | clear |
| `$8054` → `JSR $8EED` (reset) | set — the deliberate enable |
| `$808C` | clear |
| `$816C` | bit 7 of `RAM[$0778]` |
| `$817E` | set |
| `$8E23` → `JSR $8EED` | bit 7 of `RAM[$0778]` |
| `$8EA9` → `JSR $8EED` | bit 7 of `RAM[$0778]` |

**Finding.** The routine at `$8EED` is `STA $2000 / STA $0778 / RTS`, and the
handler body reaches it: the graph has
`$8212 → … → $858E → $8E19 → JSR $8EED` at `$8E23`. So a PPUCTRL write *does*
happen inside the game logic the handler calls at `$8175`; the premise is not
"no write in the handler body" but "no write with bit 7 set". It happens that
`$8E23` writes bit 7 of `RAM[$0778]` — the same cell `$816C` writes from — so
it adds no new assumption and reduces to the same RAM invariant, which
`verify/JOINT_INVARIANT.md` section 1 already lists as open. But the earlier
statement that NMI is simply disabled across the handler body was resting on an
unchecked claim.

**Still open.** Nine stores through a RAM pointer (`STA ($06),Y` and friends)
are reachable from the handler body and their effective address is not bounded
here. If any can be made to address a PPUCTRL mirror with bit 7 of the stored
value set, the enable bit can be raised inside the handler body and both halves
of MA-NMI-EDGE lose their program premise. That is a residual obligation, not a
result.

## Recommended wording for the `transitions.py` docstring

**MA-NMI-EDGE.** Split it in two. The half that needs nothing becomes a
derived lemma: while the PPU NMI-enable bit is clear no NMI can be taken, so
two NMI entries must have an intervening 0→1 write of that bit
(`L-NMI-EDGE-DISABLED`, proved against the cycle model in
`model/interrupt_timing.py`, no premise, no horizon). The half that is still an
assumption is narrow: no second NMI inside the 23 cycles from interrupt entry
to the disabling write at `$808C`. That is derived
(`L-NMI-EDGE-WINDOW`) but conditional on `P-EDGE-NO-SET`, a PPU frame-timing
premise NESdev implies by arithmetic and states nowhere; dropped, it is refuted
with a witness. Drop the phrase "at least one frame apart" — the frame is not
what the derivation uses — and say that the program premise (no PPUCTRL write
with bit 7 set between `$808C` and `$817E`) is settled for every direct write
but open for nine stores through a RAM pointer.

**MA-NMI-LATENCY.** Keep it as an assumption, but say what it rests on.
Derived (`L-NMI-LATENCY`) by exhaustive enumeration over the real epilogue
`$8178`-`$8181` and every adversarial `vblank_flag` timing, under both
unsettled timing parameters, and conditional on `P-LATENCY-DISABLED`, which is
a *program* premise and not a timing one: `NMI_output` must be clear and no NMI
pending when the epilogue starts. Without it the statement is refuted with two
witnesses. The sample point is quoted; the consequence is derived. The existing
caveat "the uniform rule is wrong for taken branches" can go: the model refuses
branches rather than approximating them, and neither window contains one.
