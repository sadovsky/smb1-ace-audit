# Literature Review

**Purpose.** Establish what prior work exists before any novelty claim is made for this
project (machine-checked proof that *every instruction fetch occurs within program ROM for
all controller input sequences*, over the unmodified Super Mario Bros. (1985) NES ROM,
using an SMT-based 2A03 instruction model validated against single-instruction test
vectors, recursive-descent CFG recovery, backward symbolic execution, per-routine contracts
with a frame rule, and a per-instruction inductive-invariant certificate).

**Search date.** 2026-11-25. **Method.** Web search plus direct retrieval of primary pages.
Every reference below was seen in a search result or a retrieved page. Where a
bibliographic detail could not be confirmed from a primary source it is marked
**(unverified)** rather than guessed. Claims that were sought but not confirmed are listed
in §8.

---

## 1. Binary-level and machine-code formal verification

**Synthesis.** Three traditions; this project sits in the third.

*(i) Refinement down to the binary.* seL4 extended its Isabelle/HOL C-level proof to the
compiled binary by *translation validation* — model the binary, model the C, prove they
agree per function, so the compiler need not be trusted (Sewell, Myreen, Klein, PLDI 2013).
The enabling technique is Myreen's **decompilation into logic**: proof-certified extraction
of a functional model from concrete machine code by symbolic simulation over a program
logic, every step reduced to HOL4 kernel inferences (FMCAD 2008; FMCAD 2012; UCAM-CL-TR-765).
Methodologically the closest ancestor of "validated instruction model + proofs about the
real bytes", but it needs a source-level artefact to refine against. This project has none;
that is the structural difference.

*(ii) Sound static analysis of executables.* Balakrishnan and Reps' **value-set analysis**
(CC 2004; the WYSINWYX line; TR-1603, 2007) gave the abstract domain for recovering
addresses and integers together from stripped binaries. **Jakstab** (Kinder and Veith,
CAV 2008; Kinder, Zuleger, Veith, VMCAI 2009) is the reference point for *this project's
CFG problem*: it resolves indirect branches by interleaving disassembly with dataflow
analysis until the CFG closes, framed as abstract interpretation over *partial* CFGs.
Recursive-descent recovery that must discharge indirect jumps is a less general version of
exactly this, so CFG recovery should be cited, not claimed.

*(iii) Verified lifting and verified sandboxing.* Verbeek, Bockenek, Fu and Ravindran claim
"the first approach to provably overapproximative x86-64 binary disassembly", exporting to
Isabelle/HOL (PLDI 2022). Naus, Verbeek and Ravindran give the first formal operational
semantics for Ghidra **P-Code** and report that P-Code as shipped "cannot be given an
executable semantics" without extension (VSTTE 2022) — a reason not to build on an RE IR.
BAP and angr are the standard unverified platforms. **BinSym** (Tempel et al., DATE 2025)
drives symbolic execution from formal ISA semantics and found five previously unknown bugs
in angr's ISA implementation: direct evidence that a vector-validated SMT CPU model earns
its cost.

**Most relevant to novelty: ARMor and RockSalt.** ARMor (Zhao, Li, De Sutter, Regehr,
EMSOFT 2011) rewrites an ARM binary to insert checks and then machine-checks *in HOL* that
the result enforces memory safety and control-flow integrity, claimed as the first fully
verified realistic SFI implementation, with the trusted base reduced to the formal ARM
semantics. RockSalt (Morrisett, Tan, Tassarotti, Tristan, Gan, PLDI 2012) is a Native
Client checker whose core is generated from a specification proven correct against a **Coq
model of IA-32**. Both mechanically prove a property of the shape *"all control transfers
of this real binary stay inside a permitted region"* — the same shape as this project's
invariant.

## 2. Formal semantics of the 6502 and other 8-bit CPUs

**Synthesis.** No machine-checked formal semantics of the 6502 or 2A03 surfaced in any
search. This is the clearest apparent gap, and also the claim most exposed to
non-publication: hobby formalisations are poorly indexed. The nearest thing found is a
6502.org forum thread describing a Z3-backed 6502 symbolic-execution engine that proves
equivalences between short instruction sequences — a hobby tool, not a published result.

For the 6502 what exists instead is very strong *empirical* specification: **visual6502**'s
polygon/transistor model from a die photograph (G. James, B. Silverman, B. Silverman) and
Steil's **perfect6502**, a half-cycle-exact netlist simulator whose complete behaviour,
internal state and outputs match the chip at roughly 1/30 of 1 MHz; Steil's 27C3 (2010)
talk documents the decapping-to-netlist method and PLA decode. Validation corpora:
**SingleStepTests/65x02**, a language-agnostic JSON instruction-by-instruction suite
including bus activity (archived predecessor TomHarte/ProcessorTests), ~10,000 vectors per
opcode; and Lorenz's older suite covering illegal opcodes and BCD with invalid operands.
For other ISAs the formal artefacts are mature — Goel/Hunt's x86 in ACL2, Dasgupta et al.'s
x86-64 in K, Sail/Isla for ARM and RISC-V, CakeML on a verified processor — and those, not
any 6502 work, are the methodological benchmark.

## 3. Legacy and interrupt-driven binary verification

**Synthesis.** A direct and older precedent. **[mc]square** (Schlich and Kowalewski;
RWTH report AIB-2008-14; STTT 2009) is an explicit-state CTL model checker building its
state space *directly from microcontroller assembly* (ATmega16 and 8051-class parts) with
no manual preprocessing, adding "delayed nondeterminism" to mix symbolic and explicit
states; later work applies interval analysis to the same binaries. On interrupts: Regehr's
"Thread Verification vs. Interrupt Verification" (2006) and Regehr and Cooprider (ENTCS
174, 2007) show interrupts are *not* threads and give transformations letting thread tools
handle them. Regehr, Reid and Webb, "Eliminating stack overflow by abstract interpretation"
(EMSOFT 2003 / TECS 2005) is the canonical sound stack-depth bound for interrupt-driven
*object code*, and states that modelling when interrupts are enabled or disabled is
essential to precision — the same obligation this project carries for the NMI. Also IntAbs
(arXiv:1709.10078) and interrupt sequentialisation for numeric abstract interpreters;
AbsInt's StackAnalyzer/aiT are the commercial equivalents. **Astrée is routinely cited here
but no Astrée-specific source on interrupt or stack analysis was retrieved, so it is not
cited in this review.**

## 4. Inductive invariants and certificate checking

**Synthesis.** The certificate is a classical object and should be presented as one.
Per-location assertions proved locally go back to Floyd (1967) and Hoare (1969)
**(unverified — not retrieved)**. Mechanised proposers: **k-induction** (Sheeran, Singh,
Stålmarck, FMCAD 2000 — cited via Bradley's slides, not retrieved); **IC3/PDR** (Bradley,
VMCAI 2011; "Understanding IC3", SAT 2012), explicitly motivated by BMC and k-induction
choking on unrollings; **Houdini** (Flanagan and Leino, FME 2001), which guesses many
candidate annotations and keeps those a modular checker cannot refute — the standard
citation for "propose invariants, discharge per location". Certificate-shipping traditions:
**proof-carrying code** (Necula, POPL 1997) and **translation validation** (Pnueli, Siegel,
Singerman, TACAS 1998). Abstract interpretation as proposer with SMT as per-instruction
checker is the standard pairing and is not itself novel.

## 5. Games and consoles

**Synthesis.** Two disjoint literatures; neither touches the binary the way this project
does.

*(i) Complexity of idealised games.* Aloupis, Demaine, Guo and Viglietta, "Classic Nintendo
games are (computationally) hard" (FUN 2014; TCS 586, 2015) prove **NP-hardness** of
generalised Super Mario Bros. 1-3, Lost Levels and Super Mario World by reduction from
3-SAT, with PSPACE-completeness for *Donkey Kong Country 1-3* and *Zelda: A Link to the
Past* — **not** for Mario. The Mario PSPACE result is the separate Demaine, Viglietta and
Williams, "Super Mario Bros. Is Harder/Easier than We Thought" (FUN 2016), proving
generalised SMB **PSPACE-complete**, noting the proof survives known glitches and relies on
levels of arbitrary size; MIT's own coverage stresses no *commercial* level is shown hard.
These papers reason about an abstract game, never about 6502 code; the relation is
rhetorical only. **The brief's phrasing "SMB is NP-hard / PSPACE-complete (Aloupis, Demaine,
Guo, Viglietta)" conflates two papers and should be split.**

*(ii) Exploitation by the TAS community.* This is where real knowledge of SMB1 control flow
lives, and it bears on correctness, not just citation. TASVideos submission #8991
(OnehundredthCoin, 2024-04-01, published; BizHawk 2.9.1; ROM "Super Mario Bros. (W) [!].nes")
achieves **ACE in SMB1** by driving object C9 to index a jump table out of bounds, sending
PC to **$53AE — an unmapped address** — where the CPU *executes open-bus bytes* including an
undocumented `SRE` and an `RTI` that lands PC at **$1181** in never-cleared RAM, whence a
controller-fed payload runs `JMP ($00C2)`. The earlier attempt (#8197, cancelled) used a
custom hot-swap BizHawk fork; #8991 reports it "syncs on console" after Alyosha's
verification and attributes an earlier desync to "emulator inaccuracies with 'Open Bus'".
The setup requires a **Super Mario Bros. 3 cartridge swap** to pre-seed RAM (e.g. $7FD =
0x16 for world 'N'), so it is *not* reached by controller input alone from a clean
power-on. Comparable precedents: Lord_Tom's SMB3 ACE TAS (#4961, 2016); ais523/TASBot's
SMB3 ACE at SGDQ 2016; SethBling's SNES Super Mario World credits warp on original hardware
(2015, 5:59.6; sub-minute February 2018).

*(iii) Automated glitch finding.* Forward, Limmer, Hallett and Page, "Super Mario in the
Pernicious Kingdoms" (arXiv:2404.14870; GAS @ ICSE 2024) classify 237 glitches across SMB1,
SMB3, SMW and SM64 against the Seven Pernicious Kingdoms taxonomy and CWE, add seven
game-specific weakness categories, and state that bug-discovery techniques such as fuzzing
or symbolic execution "are not typically deployed as part of glitch discovery in games",
which is done by reverse engineering. Adjacent: Bernstein's "Symbolically executing
emulators" (2025) symbolically executes an emulator's instruction semantics with angr, for
cryptographic code rather than games.

---

## 6. NES hardware references for the model's assumptions

All quotations are from the NESdev Wiki, retrieved 2026-11-25. **Where the source does not
say what the assumption asserts, that is flagged.**

### (a) Interrupt polling point — bears on `MA-NMI-LATENCY`
Source: <https://www.nesdev.org/wiki/CPU_interrupts>

The page states the loose rule and then corrects it: "For most instructions, this polling
happens during the final cycle of the instruction", but "Many references will claim that
interrupts are polled during the last cycle of an instruction" and in fact "it's really the
status of the interrupt lines at the end of the second-to-last cycle that matters."

**The assumption's *consequence* is not stated literally.** The page never says "an NMI
edge produced by a write on an instruction's last cycle is serviced only after the
following instruction"; that follows by inference from the sample point, supported by "the
next 'instruction' executed is the interrupt sequence" and "at least one instruction from
the interrupt handler will execute before another interrupt is serviced".

**Qualifications that a uniform "second-to-last cycle" rule gets wrong:**
- **Taken branches contradict it.** "Interrupts are always polled before the second CPU
  cycle (the operand fetch)" "but not before the third CPU cycle on a taken branch", and
  "for taken branches that cross a page boundary, interrupts are polled before the PCH
  fixup cycle". For a 3-cycle taken branch the effective poll is therefore at the end of
  cycle 1, i.e. the *third*-to-last cycle, not the second-to-last. Behaviour of
  *not-taken* branches is not stated.
- **An extra detector delay.** "This edge detector polls the status of the NMI line during
  φ2 of each CPU cycle", and the internal NMI signal "goes high during φ1 of the cycle that
  follows the one where the edge is detected" — so there is a cycle of detector latency on
  top of the polling rule.
- **Two-cycle instructions:** "like all two-cycle instructions they poll the interrupt
  lines at the end of the first cycle" and "can effectively delay an interrupt until after
  the next instruction" (CLI/SEI/PLP); RTI is the exception, "restoring the I flag from the
  stack before polling for interrupts".
- **Hijacking:** if NMI is asserted during the first four ticks of `BRK`, control goes to
  the NMI vector; "The BRK instruction, however, can effectively be cancelled by an NMI (or
  an IRQ) this way". The B flag pushed differs between BRK and IRQ/NMI.
- "The interrupt sequences themselves do not perform interrupt polling."
- With both pending, "the NMI will be handled and the pending status of the IRQ forgotten".

### (b) NMI edge-triggering — bears on `MA-NMI-EDGE`
Source: <https://www.nesdev.org/wiki/NMI>

Confirmed: "The PPU pulls /NMI low if and only if both vblank_flag and NMI_output are
true." and "The check for this is edge-sensitive, meaning that if other circuitry on the
board pulls the /NMI pin from high to low voltage, this sets a flip-flop in the CPU."
Sources of the two terms: "Start of vertical blanking (scanline 241, dot 1): Set vblank_flag
in PPU to true."; "Write to PPUCTRL: Set NMI_output to the state of bit 7."; "Read
[PPUSTATUS]: Return old status of vblank_flag in bit 7, then set vblank_flag to false." The
page says these hold "regardless of whether rendering is enabled". Multiple NMIs per vblank
are confirmed: "By toggling NMI_output (PPUCTRL.7) during vertical blank without reading
PPUSTATUS, a program can cause /NMI to be pulled low multiple times, causing multiple NMIs
to be generated."

**Flag.** The *immediate NMI on enabling bit 7 while the vblank flag is already set is not
stated in terms.* It follows from the "if and only if both" rule but the page does not say
it. The page also does not use the phrasing "0→1 transition of the AND"; it states the
condition on the active-low /NMI pin. A **race condition** is documented: if vblank onset
and the $2002 read coincide, "PPUSTATUS bit 7 is read as false, and vblank_flag is set to
false anyway", so "the NMI won't fire, and that the program will be unaware that the
hardware is in VBLANK" — a polling loop "is likely to miss an occasional frame".

### (c) PPU power-up/reset, the $2000 write-ignore window, and reset-button scope
Sources: <https://www.nesdev.org/wiki/PPU_power_up_state>,
<https://www.nesdev.org/wiki/PPU_registers>

- "Writes to the following registers are ignored if earlier than ~29658 CPU clocks after
  reset: PPUCTRL, PPUMASK, PPUSCROLL, PPUADDR." "This also means that the PPUSCROLL/PPUADDR
  latch will not toggle." Unaffected: "PPUSTATUS, OAMADDR, OAMDATA ($2004), PPUDATA, and
  OAMDMA ($4014)". Mechanism: "Attempting to write to a register while it is being cleared
  has no effect".
- **The two pages state the window differently.** PPU_registers says writes to "$2000,
  $2001, $2005 and $2006" are ignored "until reaching the pre-render scanline of the next
  frame" and gives the counts as "around 29658 NTSC CPU cycles or 33132 PAL CPU cycles,
  assuming the CPU and PPU are reset at the same time." A cycle-count model is therefore an
  approximation of a scanline-phase condition, and is conditional on simultaneous reset.
- Power-on is not exempt: "If the NES is powered on after having been off for less than 20
  seconds, register writes are ignored as if it were a reset." What happens after ≥20 s is
  not stated.
- VBL flag: "random at power, and unchanged by reset. It is next set around 27384, then
  around 57165."
- **Reset button, and an internal inconsistency to be aware of.** "On front-loading
  consoles (NES-001), the Reset button on the Control Deck resets both the CPU and PPU."
  "On top-loaders (Famicom, NES-101), only the CPU is reset." But the same page also says
  "On the NTSC NES, the PPU and CPU are reset at the exact same time." NES-101 is an NTSC
  NES; the page does not reconcile these.

### (d) Decimal mode
Source: <https://www.nesdev.org/wiki/Status_flags>. "On the NES, decimal mode is disabled
and so this flag has no effect." "However, it still exists and can be observed and
modified, as normal." "Can be set or cleared directly with SED or CLD." **Flag:** the page
says "On the NES", not "the 2A03", and does not say the BCD correction logic is absent —
only that the flag has no effect. A model that treats D as a plain storage bit matches the
source.

### (e) Mirroring
Source: <https://www.nesdev.org/wiki/CPU_memory_map>: "$0000–$07FF | $0800 | 2 KB internal
RAM"; "$0800–$0FFF | $0800 | Mirrors of $0000–$07FF"; "$2000–$2007 | $0008 | NES PPU
registers"; "$2008–$3FFF | $1FF8 | Mirrors of $2000–$2007 (repeats every 8 bytes)";
"$4000–$4017 | $0018 | NES APU and I/O registers". PPU_registers: "because their addresses
are incompletely decoded, they're mirrored in every 8 bytes from $2008 through $3FFF" and
"a write to $3456 is the same as a write to $2006". *Minor:* in the retrieved text the
$1000–$17FF and $1800–$1FFF rows carried no device column, so only the $0800–$0FFF mirror
row is quotable verbatim; the 3× further RAM mirroring is standard but should be cited to
the table as a whole, not to a quoted sentence.

### (f) Open bus
Source: <https://www.nesdev.org/wiki/Open_bus_behavior>. "When the CPU attempts to read
from an address which has no devices active, the result is open bus behavior." "The value
that results from a read in such a region is undefined" "but on specific hardware
predictable results may appear." "On a standard NES, reading open bus repeats the last
value that was read from the bus before this read." Also: "A DMC DMA may also alter the last
value read if it interrupts an instruction."; controller ports affect only bits 4-0 with
"Bits 7-5 repeat the corresponding bits from the previous read, usually 010"; and "Reading
any PPU port, including write-only ports $2000, $2001, $2003, $2005, $2006, returns the PPU
I/O bus's value", a latch of which "At least one bit ... decays after 3ms to 30ms".
Clones and flash carts "may differ".

---

## 7. Novelty assessment

Stated cautiously, and with the closest prior work named in each case.

**Not novel.** (1) Proving a machine-checked confinement property of a real binary against a
formal ISA model: **ARMor** (EMSOFT 2011) and **RockSalt** (PLDI 2012) already do this, with
an ARM-in-HOL and an IA-32-in-Coq model respectively; RockSalt's property — all control
transfers stay inside a sandbox — is the same shape as "every fetch lies in ROM".
(2) Recursive-descent CFG recovery with indirect-branch resolution: **Jakstab** (CAV 2008 /
VMCAI 2009) and value-set analysis (CC 2004) are the reference points. (3) Carrying a
validated instruction-level CPU model into SMT: **BinSym** (DATE 2025). (4) Per-instruction
inductive-invariant certificates: Floyd/Hoare, Houdini, IC3/k-induction, proof-carrying
code. (5) Verifying interrupt-driven microcontroller *binaries*: **[mc]square** and the
Regehr line. None of the project's individual techniques is new.

**Plausibly novel, with caveats.** No published work was found that (a) gives a formal,
machine-checked semantics of the **6502/2A03**, as opposed to transistor-level simulation
(visual6502/perfect6502) and large empirical vector suites (SingleStepTests/65x02); or
(b) applies binary-level formal verification to a **commercial console game ROM** at all.
The combination — a 2A03 model validated against single-instruction vectors, plus an
NMI-aware whole-program control-flow invariant over a 1985 shipped game — did not appear in
any search. The glitch-classification paper's own statement that fuzzing and symbolic
execution "are not typically deployed as part of glitch discovery in games" is independent
support that this application area is open. The honest framing is therefore
**"first application of X to Y", not "new technique"**, and the claim should be hedged: an
unpublished or hobby 6502 formalisation would not appear in these searches (one Z3-based
6502 symbolic-execution engine was found only as a forum thread).

**A finding that constrains the theorem, not just the citations.** The invariant as phrased
— every fetch in program ROM *for all controller input sequences* — is **already known to
be false in the general case**: the published, console-verified SMB1 ACE (TASVideos #8991)
works precisely by sending PC to the unmapped address **$53AE** and executing **open-bus
bytes**, then `RTI`-ing into RAM at **$1181**. The invariant can only be true under
explicit, stated restrictions: a clean power-on with no cartridge swap, a specific
assumption about initial RAM (the exploit depends on "$1181 ... uninitialized RAM that SMB
never clears"), and controller input as the only external nondeterminism. Those
restrictions must appear in the theorem statement, and the ACE run should be cited as the
reason they are there — it is the sharpest available sanity check on the model, and the
fact that the mechanism requires both **open-bus read semantics** and an **undocumented
opcode** tells you which parts of the 2A03 model the proof genuinely depends on.

## 8. What this search could not establish

- No Astrée-specific source on interrupt or stack analysis was retrieved; do not cite it.
- Abstracts/texts not opened: Sheeran-Singh-Stålmarck (FMCAD 2000), Necula (POPL 1997),
  Pnueli-Siegel-Singerman (TACAS 1998), Regehr-Cooprider (ENTCS 2007), Floyd (1967),
  Hoare (1969) — bibliographic details come from other papers' reference lists.
- Whether BinSym uses **Sail** specifically is unconfirmed; the paper speaks of "formal ISA
  specifications" generally.
- Whether any 6502/2A03 formalisation exists in unpublished, hobby, or non-English
  venues. The negative result in §2 is "not found", not "does not exist".
- The exact repository layout of SingleStepTests/65x02 (the README was not opened).
- Whether SMB1 ACE has ever been achieved **without** a cartridge swap, from a clean
  power-on using controller input only. #8991 uses a swap; the speedrun community states
  ACE is "not RTA viable in SMB". This is the single most important open question for the
  project's threat model and should be resolved with the TAS community directly.

---

## References

**Binary-level verification**
1. T. Sewell, M. Myreen, G. Klein. "Translation Validation for a Verified OS Kernel." PLDI 2013, pp. 471-481. DOI 10.1145/2491956.2462183. <https://www.cl.cam.ac.uk/~mom22/pldi13.pdf>
2. M. O. Myreen, M. J. C. Gordon, K. Slind. "Decompilation into Logic — Improved." FMCAD 2012. <https://www.cs.utexas.edu/~hunt/FMCAD/FMCAD12/016.pdf>
3. M. O. Myreen. "Formal verification of machine-code programs." PhD thesis / Univ. of Cambridge TR UCAM-CL-TR-765. <https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-765.pdf> · project page <https://www.cl.cam.ac.uk/~mom22/decompilation>
4. G. Balakrishnan, T. Reps. "Analyzing Memory Accesses in x86 Executables." CC 2004, LNCS 2985. <https://link.springer.com/content/pdf/10.1007/978-3-540-24723-4_2.pdf>
5. G. Balakrishnan. "WYSINWYX: What You See Is Not What You eXecute." PhD thesis, Univ. of Wisconsin, TR-1603, 2007. <https://research.cs.wisc.edu/techreports/2007/TR1603.pdf>
6. J. Kinder, H. Veith. "Jakstab: A Static Analysis Platform for Binaries." CAV 2008, LNCS 5123, pp. 423-427. <https://link.springer.com/content/pdf/10.1007/978-3-540-70545-1_40.pdf>
7. J. Kinder, F. Zuleger, H. Veith. "An Abstract Interpretation-Based Framework for Control Flow Reconstruction from Binaries." VMCAI 2009. <https://www.plai.ifi.lmu.de/publications/vmcai09-cfr.pdf> · thesis <https://www.plai.ifi.lmu.de/publications/phdthesis-kinder.pdf>
8. F. Verbeek, J. Bockenek, Z. Fu, B. Ravindran. "Formally Verified Lifting of C-Compiled x86-64 Binaries." PLDI 2022. <https://www.ssrg.ece.vt.edu/papers/pldi22.pdf>
9. N. Naus, F. Verbeek, B. Ravindran. "A Formal Semantics for P-Code." VSTTE 2022, LNCS 13800. <https://link.springer.com/chapter/10.1007/978-3-031-25803-9_7> · <https://www.ssrg.ece.vt.edu/papers/vstte22.pdf>
10. S. Tempel, T. Brandt, C. Lüth, C. Dietrich, R. Drechsler. "Accurate and Extensible Symbolic Execution of Binary Code based on Formal ISA Semantics." DATE 2025. arXiv:2404.04132. <https://arxiv.org/abs/2404.04132>
11. L. Zhao, G. Li, B. De Sutter, J. Regehr. "ARMor: Fully Verified Software Fault Isolation." EMSOFT 2011, pp. 289-298. <https://www-old.cs.utah.edu/~regehr/papers/emsoft11.pdf>
12. G. Morrisett, G. Tan, J. Tassarotti, J.-B. Tristan, E. Gan. "RockSalt: Better, Faster, Stronger SFI for the x86." PLDI 2012, pp. 395-404. DOI 10.1145/2254064.2254111. <https://cs.nyu.edu/~jt4767/papers/rocksalt/rocksalt.pdf>
13. angr. <https://angr.io/> · <https://github.com/angr/angr>. BAP. <https://github.com/BinaryAnalysisPlatform/bap>
14. A. Djoudi, S. Bardin. "BINSEC: Binary Code Analysis with Low-Level Regions." TACAS 2015, LNCS 9035. <https://link.springer.com/chapter/10.1007/978-3-662-46681-0_17>

**6502 / 8-bit CPU semantics and validation**
15. Visual6502 project (G. James, B. Silverman, B. Silverman). <http://visual6502.org/>
16. M. Steil. perfect6502 (half-cycle-exact NMOS 6502 netlist simulator). <https://github.com/mist64/perfect6502> (mirror: <https://git.applefritter.com/6502/perfect6502>)
17. M. Steil. "Reverse Engineering the MOS 6502 CPU." 27C3, 2010. <https://fahrplan.events.ccc.de/congress/2010/Fahrplan/events/4159.en.html>
18. SingleStepTests — 65x02 JSON instruction test suite (incl. bus activity). <https://github.com/SingleStepTests/65x02> · org <https://github.com/SingleStepTests>
19. 6502.org forum thread, "6502 (well 2a03) symbolic execution engine" (Z3-based; hobby tool, not peer-reviewed). <http://forum.6502.org/viewtopic.php?f=8&t=5069>
20. S. Dasgupta et al. "A Complete Formal Semantics of x86-64 User-Level Instruction Set Architecture." PLDI 2019. <https://dl.acm.org/doi/pdf/10.1145/3314221.3314601>
21. S. Goel, W. A. Hunt et al. "Verifying x86 Instruction Implementations" (ACL2 x86 model). arXiv:1912.10285. <https://arxiv.org/pdf/1912.10285>
22. A. Lööw et al. "Verified Compilation on a Verified Processor." PLDI 2019. <https://cakeml.org/pldi19.pdf>
23. A. Armstrong et al. "Isla: Integrating full-scale ISA semantics and axiomatic concurrency models" (Sail-based). <https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11494631/>

**Embedded / interrupt-driven verification**
24. B. Schlich, S. Kowalewski. "Model checking C source code for embedded systems" / [mc]square. STTT 2009, DOI 10.1007/s10009-009-0106-5. <https://unpaywall.org/10.1007%2FS10009-009-0106-5>
25. B. Schlich. "Model Checking of Software for Microcontrollers." RWTH Aachen report AIB-2008-14, 2008. <https://typeset.io/pdf/model-checking-of-software-for-microcontrollers-2cks8bo411.pdf>
26. J. Regehr. "Thread Verification vs. Interrupt Verification." 2006. <https://www-old.cs.utah.edu/~regehr/papers/tv06.pdf>
27. J. Regehr, N. Cooprider. "Interrupt verification via thread verification." ENTCS 174, 2007. **(details from a secondary reference list; abstract unverified)**
28. J. Regehr, A. Reid, K. Webb. "Eliminating stack overflow by abstract interpretation." EMSOFT 2003, LNCS 2855 / ACM TECS 2005. <https://link.springer.com/doi/10.1007/978-3-540-45212-6_20> · <https://www-old.cs.utah.edu/~regehr/papers/p751-regehr.pdf>
29. X. Wu et al. "Modular Verification of Interrupt-Driven Software" (IntAbs). arXiv:1709.10078. <https://arxiv.org/pdf/1709.10078> **(author list unverified)**

**Invariants and certificates**
30. A. R. Bradley. "SAT-Based Model Checking without Unrolling." VMCAI 2011. <https://theory.stanford.edu/~arbrad/papers/Understanding_IC3.pdf> (companion: "Understanding IC3", SAT 2012)
31. M. Sheeran, S. Singh, G. Stålmarck. "Checking Safety Properties Using Induction and a SAT-Solver." FMCAD 2000. **(cited via Bradley's slides; not retrieved)**
32. C. Flanagan, K. R. M. Leino. "Houdini, an Annotation Assistant for ESC/Java." FME 2001, pp. 500-517. DOI 10.1007/3-540-45251-6_29. <https://users.soe.ucsc.edu/~cormac/papers/fme01.pdf>
33. G. C. Necula. "Proof-Carrying Code." POPL 1997, pp. 106-119. **(bibliographic details from a secondary reference list)**
34. A. Pnueli, M. Siegel, E. Singerman. "Translation Validation." TACAS 1998, LNCS 1384, pp. 151-166. **(bibliographic details from a secondary reference list)**

**Games and consoles**
35. G. Aloupis, E. D. Demaine, A. Guo, G. Viglietta. "Classic Nintendo games are (computationally) hard." FUN 2014, LNCS 8496; Theoretical Computer Science 586 (2015). arXiv:1203.1895. <https://arxiv.org/abs/1203.1895> · <https://erikdemaine.org/papers/Nintendo_TCS/paper.pdf>
36. E. D. Demaine, G. Viglietta, A. Williams. "Super Mario Bros. Is Harder/Easier than We Thought." FUN 2016, LIPIcs. <https://drops.dagstuhl.de/opus/volltexte/2016/5880/> · <https://erikdemaine.org/papers/Mario_FUN2016>
37. L. Forward, I. Limmer, J. Hallett, D. Page. "Super Mario in the Pernicious Kingdoms: Classifying glitches in old games." GAS @ ICSE 2024. arXiv:2404.14870. <https://arxiv.org/abs/2404.14870>
38. OnehundredthCoin. TASVideos submission #8991, NES Super Mario Bros. "arbitrary code execution" in 04:52.65, published 2024. <https://tasvideos.org/8991S>
39. OnehundredthCoin. TASVideos submission #8197, NES Super Mario Bros. "Stop 'n' Swop arbitrary code execution" in 01:16.97 (cancelled). <https://tasvideos.org/8197S>
40. Lord_Tom. TASVideos submission #4961, NES Super Mario Bros. 3 "arbitrary code execution, playaround", 2016. <https://tasvideos.org/4961S>
41. D. J. Bernstein. "Symbolically executing emulators." 2025. <https://cr.yp.to/papers/symexemu-20250505.pdf>

**NES hardware documentation (NESdev Wiki, retrieved 2026-11-25)**
42. "CPU interrupts." <https://www.nesdev.org/wiki/CPU_interrupts>
43. "NMI." <https://www.nesdev.org/wiki/NMI>
44. "PPU power up state." <https://www.nesdev.org/wiki/PPU_power_up_state>
45. "PPU registers." <https://www.nesdev.org/wiki/PPU_registers>
46. "CPU memory map." <https://www.nesdev.org/wiki/CPU_memory_map>
47. "Open bus behavior." <https://www.nesdev.org/wiki/Open_bus_behavior>
48. "Status flags." <https://www.nesdev.org/wiki/Status_flags>
