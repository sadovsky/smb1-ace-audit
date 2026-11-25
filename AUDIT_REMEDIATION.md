# SMB1 ACE Audit — Remediation and Research Plan

## 1. Objective and scope

Strengthen the static and dynamic analysis of controller-only arbitrary code execution (ACE) in NTSC Super Mario Bros. The existing negative result is structural and empirical evidence, not an impossibility proof. Remain outcome-neutral: either a reproducible counterexample or a machine-checked negative result is valuable.

Target: NTSC / World, NROM mapper 0, 32 KiB PRG, 8 KiB CHR; expected complete ROM SHA-1 `ea343f4e445a9050d4b4fbac2c77d0693b1d0922`. Do not redistribute the ROM.

Define the permitted input model explicitly: controller sequences, timing, simultaneous directional inputs, multiple controllers, power-on and reset behavior. Distinguish physical feasibility from TAS feasibility. Exclude ROM patches, direct RAM injection, debugger manipulation, emulator bugs, electrical faults and hardware modifications from controller-only evidence. Keep assisted experiments separate.

Distinguish state invariant violations, unintended control flow, RAM execution, and chosen-payload ACE. These are not equivalent.

## 2. Preserve and reproduce the baseline (P0)

- Record the repository commit, ROM hash, emulator versions and patch revisions.
- Run `python3 -m unittest -v`, `python3 trace.py`, `python3 reach.py`, `python3 controlflow.py`, `python3 classify.py --json`, and `python3 audit.py`.
- Save outputs and experiment manifests; explicitly mark experiments that cannot be reproduced.
- Preserve historical results rather than overwriting them.

## 3. Correct the `$92C8` bound (P0)

Affected files: `classify.py`, `audit.py`, `ACE_AUDIT.md`, `README.md`, paper source and regression tests.

The reported `LDY $071F / BNE / LDY #$08 / DEY` sequence substitutes eight only for zero. It does not clamp the upper bound. Its transformation is:

```python
def dispatch_index(value: int) -> int:
    value &= 0xff
    return ((value or 8) - 1) & 0xff
```

| Input | Result |
|---|---|
| `$00` | 7 |
| `$01` | 0 |
| `$08` | 7 |
| `$09` | 8 |
| `$80` | 127 |
| `$FF` | 254 |

Verify the complete surrounding instruction sequence against the ROM. Downgrade the bound to conditional or observed until `RAM[$071F] <= 8` is established. Enumerate all potential writers, including indexed and indirect stores, and prove initialization and preservation.

Regression tests:

```python
def test_92c8_zero_substitution():
    assert dispatch_index(0) == 7

def test_92c8_upper_bound():
    assert dispatch_index(8) == 7

def test_92c8_does_not_clamp():
    assert dispatch_index(9) == 8
    assert dispatch_index(255) == 254
```

Acceptance: test all 256 inputs; remove the unconditional clamp claim and document the upstream invariant.

## 4. Separate observed bounds from proven exclusions (P0)

In `classify.py`, the current condition `bound is not None and i > bound` excludes candidates regardless of provenance. The reported 2,181 exclusions and zero unknowns therefore overstate the evidence.

Represent independent dimensions:

```python
from enum import Enum

class BoundProvenance(Enum):
    PROVEN = 'proven'
    STRUCTURAL_CONDITIONAL = 'structural_conditional'
    DERIVED_CONDITIONAL = 'derived_conditional'
    OBSERVED = 'observed'
    ASSUMED = 'assumed'
    UNPROVED = 'unproved'

class Reachability(Enum):
    PROVEN_UNREACHABLE = 'proven_unreachable'
    CONDITIONALLY_UNREACHABLE = 'conditionally_unreachable'
    OBSERVED_REACHABLE = 'observed_reachable'
    NOT_OBSERVED = 'not_observed'
    UNKNOWN = 'unknown'

class ExecutionOutcome(Enum):
    EXPECTED_ROM = 'expected_rom'
    UNEXPECTED_ROM = 'unexpected_rom'
    INTERNAL_RAM = 'internal_ram'
    IO_DEPENDENT = 'io_dependent'
    OPEN_BUS_DEPENDENT = 'open_bus_dependent'
    UNKNOWN = 'unknown'
```

Every conditional exclusion must list its assumptions. Observations cannot generate unconditional exclusions. Regenerate all totals and update the README and paper. Add regression tests for these distinctions.

## 5. Correct recursive disassembly (P0)

Affected: `trace.py`, `controlflow.py`, `d65.py`.

The current `if pc in code: return` suppresses entry into previously decoded operand bytes. Replace it with a check against instruction starts, not occupied bytes. Preserve overlapping instruction streams and their provenance.

Construct a control-flow graph with explicit edges for fallthrough, branches, direct jumps, calls, returns, JumpEngine dispatch, interrupts and unresolved transfers. Record instruction bytes, length, successors and discovery provenance. Model documented and undocumented NMOS 6502 opcodes, 16-bit PC wrapping, relative displacements, zero-page wrapping and indirect-JMP page wrapping. Do not treat an unsupported opcode as proof of data.

Acceptance: overlapping decodings preserved, unresolved transfers reported, coverage regenerated.

## 6. Establish canonical jump-table boundaries (P0)

The current `read_table` stops at the first word below `$8000`. This is a heuristic, not an independent boundary proof.

Create `data/dispatch_tables.json` containing dispatch address, table address, entry count, expected targets, index source, provenance and notes. Independently verify all 18 reported tables using annotated disassembly, surrounding routines, ROM bytes and native traces. Pin the upstream disassembly revision. Compare heuristic and canonical boundaries automatically; report disagreements.

Acceptance: every table has independently established boundaries; the 18-site census is re-evaluated.

## 7. Enumerate unexpected PRG-ROM destinations (P0)

Do not discard anomalous destinations simply because they resolve to PRG ROM. Unexpected ROM execution can enter data or operand bytes, violate routine preconditions or lead to subsequent control-flow corruption.

Generate a complete matrix of all 256 accumulator values at every dispatch. Record raw accumulator, effective index, actual table-read addresses, destination, expected entry, memory region, instruction-start/operand/data classification, reachability evidence and subsequent observed behavior. Account for `$80–$FF` aliasing and effective index `$7F` wrapping.

Acceptance: no destination omitted solely because it is ROM; raw and effective bounds are separate.

## 8. Replace the RTS pattern scan (P1)

The current sorted-address, 24-instruction scan does not follow actual execution paths and cannot prove return integrity.

Implement `stack_analysis.py` with control-flow-aware abstract stack semantics. Distinguish return-address low/high bytes, interrupt PC low/high bytes, processor status, register values and unknown values. Model JSR, RTS, RTI, BRK, PHA, PLA, PHP, PLP, TXS, TSX, interrupts, stack-page writes and RAM mirrors. Give JumpEngine its intentional return-address consumption semantics. Track 8-bit SP wrapping and validate return frames independently of depth. Report unresolved returns rather than asserting safety.

Acceptance: graph-based analysis, stack-page writes included, verified and unresolved returns separated.

## 9. Correct the hardware memory model (P1)

The NES has no executable-memory permissions. CPU instruction fetches from I/O and open-bus regions remain bus transactions.

| Range | Region |
|---|---|
| `$0000–$07FF` | Internal RAM |
| `$0800–$1FFF` | RAM mirrors |
| `$2000–$3FFF` | PPU register mirrors |
| `$4000–$4017` | APU/controller registers |
| `$4018–$401F` | Test-mode/hardware-dependent |
| `$4020–$5FFF` | Cartridge expansion |
| `$6000–$7FFF` | Cartridge-dependent memory |
| `$8000–$FFFF` | PRG ROM |

Model register responses, open bus, read side effects and cartridge configuration. Treat the reported `$C88F` index 34 destination `$2060` as hardware-dependent pending independent verification, not automatically incapable of further control flow. Qualify IRQ assumptions: NROM lacks mapper IRQ but APU/DMC behavior must also be considered.

Acceptance: memory classification reflects actual bus behavior; emulator limitations documented.

## 10. Build a complete RAM write census (P1)

Suggested modules: `analysis/write_census.py`, `analysis/effective_address.py`, `analysis/invariants.py`.

Begin with `$000E`, `$001D`, `$0016–$001A`, `$071F`, `$0733`, `$073C`, `$0746`, `$0770`, `$0772`, JumpEngine scratch `$04–$07`, stack-page memory and any additional slots or temporary index sources discovered.

Include direct, indexed and indirect stores, read-modify-write instructions, zero-page wrapping, mirrors, stack operations, initialization loops and interrupt writes. Initially overapproximate effective addresses; refine through register and path constraints.

Each writer record should contain instruction address, opcode, addressing mode, possible effective addresses and values, register dependencies, path prerequisites, controller dependencies, invariant dependencies and analysis status.

Acceptance: every critical variable has a conservative writer manifest; unresolved writers remain explicit.

## 11. Establish inductive state invariants (P1)

For each invariant, establish initialization, every possible modification, preservation and dependencies. For example, prove `RAM[$071F] in [0,8]` only after all reachable writers and prerequisites are verified. Track dependencies in a machine-readable graph. Mutually dependent invariants require a simultaneous inductive proof, not circular assumptions.

Start with constant values, finite 8-bit sets, intervals, bit masks, register equality, CPU flag constraints and abstract addresses. Use conservative merging/widening.

Acceptance: proven invariants have initialization and preservation evidence; unresolved and refuted properties remain distinct.

## 12. Audit enemy-ID routing (P1)

In `reach.py` and `classify.py`, separate target computation, legal identifier domain, reachability of a dispatch and preservation of the identifier between gate and downstream use. Review all identifier writers, slot selection, intervening mutations, interrupts and alternate entries. Make routing assumptions explicit. Assisted injection does not establish controller reachability.

Acceptance: derived routing results are conditional where appropriate, and global enemy-ID bounds have independent evidence.

## 13. Introduce compositional symbolic analysis (P2)

Use a tested 6502 instruction model, control-flow graph, abstract interpretation, writer and stack analyses, controller-dependency tracking and an SMT solver such as Z3. Model 8-bit registers, 16-bit addresses, flags, RAM, stack, controller reads, relevant I/O and interrupts. Begin with individual routines and compositional summaries rather than whole-game symbolic execution.

Distinguish UNSAT under established assumptions, UNSAT under unproved assumptions, SAT abstract counterexamples, replayable counterexamples, UNKNOWN and TIMEOUT. Save queries, assumptions and solver versions. A timeout is not proof.

## 14. Validate emulator fidelity (P1)

Use patched `nes-py` for throughput and Mesen 2 or an equivalent independent emulator for verification. Physical NES or validated FPGA testing is optional. Undocumented NMOS opcodes are not universally NOPs; some perform memory operations or halt the processor. An emulator abort is not proof of a hardware crash.

Pin versions and compare CPU registers, flags, SP, PC, relevant RAM, dispatches, interrupts, controller inputs and timing at suitable synchronization points. Reproduce existing experiments independently or mark them unverified.

## 15. Improve coverage and reproducibility (P1)

Record site-specific dispatch events: frame, CPU cycle, dispatch address, raw accumulator, effective index, table size, SP, resolved destination, input sequence ID and assisted flag. An aggregate maximum index is not a site-specific bound.

Report instruction/edge coverage, site/index pairs, RAM value domains, interrupt events, SP ranges and enemy slot/ID combinations. Define coverage denominators. Dropped events invalidate exhaustive observation claims for affected intervals.

Each experiment manifest should include experiment ID, ROM SHA-1, repository commit, emulator and patch versions, random seed, initial-state hash, input model, frames and instructions executed, dropped events, assisted flag, termination reason and result files. Persist input sequences, parameters, trace hashes and failure diagnostics. Generate paper statistics directly from artifacts.

## 16. Proof obligations

Track in `results/proof_obligations.json`, with status, assumptions, supporting artifacts, limitations and verification method.

| ID | Obligation |
|---|---|
| A | All reachable instruction starts and transfers identified or conservatively represented |
| B | JumpEngine consumes the expected return address and resolves to allowed targets |
| C | Variables influencing dynamic control flow satisfy required invariants |
| D | RTS/RTI consume valid frames except explicitly modeled intentional alternatives |
| E | Hardware and input model covers all relevant execution semantics |
| F | Unintended execution is independently evaluated for input controllability |

Do not claim impossibility while any necessary obligation is unresolved.

## 17. Correct documentation and paper (P0)

Qualify claims that there is exactly one computed transfer in the entire game, every RTS returns to a genuine frame, all dispatch indices are bounded, 2,181 candidates are excluded, no unknowns remain, I/O necessarily crashes, undocumented opcodes are NOPs, stack depth proves integrity, ROM destinations are safe, or ACE requires a direct target below `$0800`.

Recommended interim conclusion:

> Static and dynamic analysis of the specified NTSC Super Mario Bros. ROM identifies a highly constrained indirect control-flow architecture centered on the JumpEngine routine. No controller-only arbitrary code execution has been demonstrated in the experiments reported here. Several dispatch invariants can be established locally or conditionally, while others remain empirical. A definitive negative result requires establishing control-flow completeness, state invariants, return-address integrity, and relevant hardware execution semantics across all states permitted by the controller-input model.

Distinguish original, reproduced, corrected and newly discovered results and open questions. Regenerate the PDF when findings materially change.

## 18. Suggested repository organization

Preserve existing entry points until replacements are tested. Refactoring is secondary to correctness.

```text
smb1-ace-audit/
  README.md
  ACE_AUDIT.md
  AUDIT_REMEDIATION.md
  CHANGELOG.md
  analysis/       # decoder, memory, CFG, dispatch, writer census, invariants, stack, symbolic
  data/           # canonical tables, memory map, assumptions
  experiments/    # native traces, fuzz, injection, search, replay, emulator comparison
  results/        # static, dynamic, assisted, manifests, proof obligations
  tests/          # decoder, memory, dispatch, CFG, stack, invariants
  paper/          # source, figures, PDF
  tools/          # reproduce, generate tables, generate report
```

## 19. Testing requirements

Unit tests: all 256 accumulator values, aliasing, index `$7F` wrapping, RAM mirroring, branch displacement, PC/zero-page/indirect-JMP wrapping, overlapping decoding, SP wrapping, observed vs proven classification, conditional assumptions and unexpected ROM targets.

Original synthetic ROM fixtures: overlapping streams, computed RTS, unbalanced stack, interrupt frames, jump tables followed by ROM-like words, unexpected transfers, indexed and indirect writes. Do not include Nintendo ROM content.

ROM integration tests: reproduce census, verify canonical tables, generate complete destination matrix, regenerate coverage, invariant and classification reports and compare historical results. CI runs ROM-independent tests; ROM-dependent tests explicitly skip when the verified ROM is unavailable.

## 20. Implementation milestones

| Milestone | Work | Priority |
|---|---|---|
| M0 | Pin revision and reproduce baseline | P0 |
| M1 | Correct `$92C8` and classifier provenance | P0 |
| M2 | Correct decoder and table boundaries | P0 |
| M3 | Generate complete destination matrix | P0 |
| M4 | Correct README and paper | P0 |
| M5 | RAM write census | P1 |
| M6 | Graph-based stack analysis | P1 |
| M7 | Establish initial invariants | P1 |
| M8 | Independent emulator validation | P1 |
| M9 | Reproducible experiment manifests | P1 |
| M10 | Compositional symbolic analysis | P2 |
| M11 | Reassess proof obligations | P2 |
| M12 | Publish revised paper | P2 |

Complete M1–M4 before major new infrastructure. Report partial proofs and unresolved properties instead of forcing a predetermined conclusion.

## 21. Definition of done

All concrete errors corrected; 18 reported sites independently reviewed; every destination represented; observations cannot generate unconditional exclusions; overlapping decodings supported; stack integrity evaluated along actual paths; critical writer sets documented; hardware-dependent outcomes classified accurately; experiments reproduced or explicitly unverified; numerical claims generated from artifacts; proof assumptions documented; paper distinguishes evidence from proof.

Completion does not require proving ACE impossible.

## 22. Instructions for coding agents

Read the repository and paper first. Verify the ROM hash. Preserve baseline results. Work incrementally; write regression tests before fixes. Commit independently verifiable changes separately. Never fabricate experiments, silently strengthen assumptions or equate absence of failures with proof. Record blockers. Separate assisted and controller-only evidence. Update documentation and regenerate the PDF when material findings change. Preserve original author attribution; acknowledge `ChatGPT (OpenAI)` if its analysis or implementation materially contributes to the revised paper.

**Guiding principle:** The objective is not to prove the original conclusion correct. The objective is to determine whether it is correct.

## Review limitations

This plan derives from a source-level review of the repository, including `ACE_AUDIT.md`, `trace.py`, `controlflow.py` and `classify.py`. The original ROM experiments, table boundaries and quantitative results have not been independently reproduced. The proposed architecture and milestone ordering are recommendations, not verified implementation requirements.
