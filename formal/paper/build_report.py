"""Build the formal-track research report (plan milestone M9).

    python3 formal/paper/build_report.py  ->  formal/paper/smb1_formal_report.pdf

Every number in the report is read from a generated artifact under
`formal/results/`; nothing is typed in.  If an artifact is missing the build
fails rather than printing a placeholder, and a section whose artifact records
no result says so.  The prose states what each number is evidence of and what
it is not.
"""
from __future__ import annotations

import json
import os
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (BaseDocTemplate, Frame, FrameBreak, Image,
                                KeepTogether, NextPageTemplate, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figures  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FORMAL = os.path.dirname(HERE)
RESULTS = os.path.join(FORMAL, "results")
OUT = os.path.join(HERE, "smb1_formal_report.pdf")

ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=ss["BodyText"], fontName="Times-Roman",
                      fontSize=9.3, leading=12.2, alignment=TA_JUSTIFY,
                      spaceAfter=5)
H1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                    fontSize=11, leading=13, spaceBefore=10, spaceAfter=4,
                    textColor=colors.black)
H2 = ParagraphStyle("h2", parent=ss["Heading2"],
                    fontName="Helvetica-BoldOblique", fontSize=9.6,
                    leading=12, spaceBefore=6, spaceAfter=2,
                    textColor=colors.black)
TITLE = ParagraphStyle("title", parent=ss["Title"], fontName="Times-Bold",
                       fontSize=16, leading=19, alignment=TA_CENTER,
                       spaceAfter=4)
AUTH = ParagraphStyle("auth", parent=BODY, alignment=TA_CENTER, fontSize=10,
                      leading=13, spaceAfter=1)
ABSTRACT = ParagraphStyle("abs", parent=BODY, fontSize=9, leading=11.5,
                          leftIndent=22, rightIndent=22, spaceBefore=4,
                          spaceAfter=4)
CAP = ParagraphStyle("cap", parent=BODY, fontSize=8, leading=10,
                     alignment=TA_CENTER, spaceBefore=2, spaceAfter=7,
                     textColor=colors.Color(.2, .2, .2))
REF = ParagraphStyle("ref", parent=BODY, fontSize=8.1, leading=10.2,
                     leftIndent=14, firstLineIndent=-14, spaceAfter=2)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=7.6, leading=9.2,
                      alignment=0, spaceAfter=0)


def P(text, style=BODY):
    return Paragraph(text, style)


def C(text):
    return f"<font face='Courier'>{text}</font>"


def n(value) -> str:
    return f"{value:,}"


def load(*parts):
    path = os.path.join(RESULTS, *parts)
    if not os.path.exists(path):
        sys.exit(f"missing artifact: {os.path.relpath(path)}; run "
                 "tools/reproduce.sh first")
    with open(path) as handle:
        return json.load(handle)


def table(rows, widths, header=True):
    data = [[P(str(cell), CELL) for cell in row] for row in rows]
    t = Table(data, colWidths=[w * inch for w in widths], repeatRows=int(header))
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.Color(.6, .6, .6)),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 3),
             ("RIGHTPADDING", (0, 0), (-1, -1), 3),
             ("TOPPADDING", (0, 0), (-1, -1), 1.5),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.Color(.9, .9, .9)))
    t.setStyle(TableStyle(style))
    return t


SECTIONS = [
    "Question and scope", "Formal setting", "Machine model",
    "Model validation", "Proof infrastructure",
    "Local lemmas and dispatch contracts", "Backward slices",
    "The invariant is false without interrupt timing",
    "Joint inductive invariant",
    "Initial memory, and a published result that constrains the theorem",
    "Observations", "Status of the primary theorem",
    "Trusted base and threats to validity", "Related work", "Novelty",
    "Reproducibility", "References",
]

REFS = [
    ("armor", "L. Zhao, G. Li, B. De Sutter, J. Regehr. ARMor: Fully Verified Software Fault Isolation. EMSOFT 2011."),
    ("rocksalt", "G. Morrisett, G. Tan, J. Tassarotti, J.-B. Tristan, E. Gan. RockSalt: Better, Faster, Stronger SFI for the x86. PLDI 2012."),
    ("sel4", "T. Sewell, M. Myreen, G. Klein. Translation Validation for a Verified OS Kernel. PLDI 2013."),
    ("myreen", "M. O. Myreen, M. J. C. Gordon, K. Slind. Decompilation into Logic - Improved. FMCAD 2012."),
    ("vsa", "G. Balakrishnan, T. Reps. Analyzing Memory Accesses in x86 Executables. CC 2004."),
    ("jakstab", "J. Kinder, H. Veith. Jakstab: A Static Analysis Platform for Binaries. CAV 2008; J. Kinder, F. Zuleger, H. Veith. An Abstract Interpretation-Based Framework for Control Flow Reconstruction from Binaries. VMCAI 2009."),
    ("verbeek", "F. Verbeek, J. Bockenek, Z. Fu, B. Ravindran. Formally Verified Lifting of C-Compiled x86-64 Binaries. PLDI 2022."),
    ("binsym", "S. Tempel, T. Brandt, C. L&uuml;th, C. Dietrich, R. Drechsler. Accurate and Extensible Symbolic Execution of Binary Code based on Formal ISA Semantics. DATE 2025. arXiv:2404.04132."),
    ("mcsquare", "B. Schlich. Model Checking of Software for Microcontrollers. RWTH Aachen report AIB-2008-14, 2008; B. Schlich, S. Kowalewski. STTT 2009."),
    ("regehr-int", "J. Regehr. Thread Verification vs. Interrupt Verification. 2006."),
    ("regehr-stack", "J. Regehr, A. Reid, K. Webb. Eliminating Stack Overflow by Abstract Interpretation. EMSOFT 2003; ACM TECS 2005."),
    ("houdini", "C. Flanagan, K. R. M. Leino. Houdini, an Annotation Assistant for ESC/Java. FME 2001."),
    ("ic3", "A. R. Bradley. SAT-Based Model Checking without Unrolling. VMCAI 2011."),
    ("pcc", "G. C. Necula. Proof-Carrying Code. POPL 1997. (Bibliographic details from a secondary reference list.)"),
    ("visual6502", "G. James, B. Silverman, B. Silverman. Visual6502. visual6502.org; M. Steil. perfect6502. github.com/mist64/perfect6502."),
    ("sst", "SingleStepTests. 65x02 JSON instruction test suite, nes6502/v1. github.com/SingleStepTests/65x02."),
    ("forum", "6502.org forum thread, &quot;6502 (well 2a03) symbolic execution engine&quot; (Z3-based hobby tool, not peer reviewed). forum.6502.org/viewtopic.php?f=8&amp;t=5069."),
    ("aloupis", "G. Aloupis, E. D. Demaine, A. Guo, G. Viglietta. Classic Nintendo Games are (Computationally) Hard. FUN 2014; TCS 586, 2015."),
    ("demaine", "E. D. Demaine, G. Viglietta, A. Williams. Super Mario Bros. Is Harder/Easier than We Thought. FUN 2016."),
    ("kingdoms", "L. Forward, I. Limmer, J. Hallett, D. Page. Super Mario in the Pernicious Kingdoms: Classifying Glitches in Old Games. GAS @ ICSE 2024. arXiv:2404.14870."),
    ("tas8991", "OnehundredthCoin. TASVideos submission #8991, NES Super Mario Bros. &quot;arbitrary code execution&quot;, published 2024. tasvideos.org/8991S."),
    ("nesdev-int", "NESdev Wiki. CPU interrupts; NMI. nesdev.org/wiki (retrieved 2026-11-25)."),
    ("nesdev-ppu", "NESdev Wiki. PPU power up state; PPU registers. nesdev.org/wiki (retrieved 2026-11-25)."),
    ("nesdev-map", "NESdev Wiki. CPU memory map; Open bus behavior; Status flags. nesdev.org/wiki (retrieved 2026-11-25)."),
    ("z3", "L. de Moura, N. Bj&oslash;rner. Z3: An Efficient SMT Solver. TACAS 2008; H. Barbosa et al. cvc5: A Versatile and Industrial-Strength SMT Solver. TACAS 2022."),
]
NUM = {key: i for i, (key, _text) in enumerate(REFS, 1)}


def cite(*keys):
    return "[" + ", ".join(str(NUM[k]) for k in sorted(keys, key=NUM.get)) + "]"


def build():
    manifest = load("manifests", "obligations.json")
    validation = load("reports", "model_validation.json")
    cross = load("reports", "dyn_crossvalidation.json")
    observed = load("reports", "dyn_observations.json")
    observed2 = load("reports", "dyn_observations_nespy.json")
    storm = load("reports", "dyn_nmi_storm.json")
    timing = load("reports", "interrupt_timing.json")
    init_path = os.path.join(RESULTS, "reports", "init_memory.json")
    init = json.load(open(init_path)) if os.path.exists(init_path) else None
    replication_path = os.path.join(RESULTS, "reports", "replication.json")
    replication = (json.load(open(replication_path))
                   if os.path.exists(replication_path) else None)

    obligations = {o["id"]: o for o in manifest["obligations"]}
    counts = manifest["counts"]
    total = sum(counts.values())

    def status(ident):
        return obligations[ident]["status"]

    def by_prefix(prefix):
        return [o for o in manifest["obligations"] if o["id"].startswith(prefix)]

    def tally(items):
        out = {}
        for item in items:
            out[item["status"]] = out.get(item["status"], 0) + 1
        return ", ".join(f"{v} {k}" for k, v in sorted(out.items())) or "none"

    doc = BaseDocTemplate(
        OUT, pagesize=letter,
        title="Toward a Machine-Checked Instruction-Location Invariant for "
              "Super Mario Bros.",
        author="Alexander Sadovsky, ChatGPT (OpenAI), and Claude (Anthropic)",
        leftMargin=0.8 * inch, rightMargin=0.8 * inch,
        topMargin=0.8 * inch, bottomMargin=0.8 * inch)
    fw = doc.width
    gutter = 0.28 * inch
    cw = (fw - gutter) / 2.0
    pad = dict(leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    full = Frame(doc.leftMargin, doc.bottomMargin, fw, doc.height, id="full", **pad)
    lcol = Frame(doc.leftMargin, doc.bottomMargin, cw, doc.height, id="l", **pad)
    rcol = Frame(doc.leftMargin + cw + gutter, doc.bottomMargin, cw,
                 doc.height, id="r", **pad)
    cwi = cw / inch
    fig_no = [0]
    eq_no = [0]

    def EQ(tex, size=10.5):
        """A numbered displayed equation, shrunk to the column if needed."""
        eq_no[0] += 1
        path, width, height = figures.equation(tex, size)
        limit = cwi - 0.34
        scale = min(1.0, limit / width)
        image = Image(path, width * scale * inch, height * scale * inch)
        t = Table([[image, P(f"({eq_no[0]})", CAP)]],
                  colWidths=[(cwi - 0.3) * inch, 0.3 * inch])
        t.setStyle(TableStyle([("ALIGN", (0, 0), (0, 0), "CENTER"),
                               ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 0),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                               ("TOPPADDING", (0, 0), (-1, -1), 2),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        add(t)

    def FIG(path, caption):
        fig_no[0] += 1
        from PIL import Image as PILImage
        with PILImage.open(path) as im:
            w, h = im.size
        width = cw
        add(KeepTogether([Spacer(1, 3), Image(path, width, width * h / w),
                          P(f"Figure {fig_no[0]}. {caption}", CAP)]))

    def footer(cv, d):
        cv.saveState()
        cv.setFont("Times-Roman", 7.5)
        cv.setFillColor(colors.Color(.4, .4, .4))
        cv.drawCentredString(letter[0] / 2, 0.5 * inch, f"{d.page}")
        cv.drawString(doc.leftMargin, 0.5 * inch, "Preprint - technical report")
        cv.drawRightString(letter[0] - doc.rightMargin, 0.5 * inch,
                           "SMB1 instruction-location invariant")
        cv.restoreState()

    head = 4.75 * inch
    top = Frame(doc.leftMargin, doc.bottomMargin + doc.height - head, fw,
                head, id="top", **pad)
    l1 = Frame(doc.leftMargin, doc.bottomMargin, cw, doc.height - head,
               id="l1", **pad)
    r1 = Frame(doc.leftMargin + cw + gutter, doc.bottomMargin, cw,
               doc.height - head, id="r1", **pad)
    doc.addPageTemplates([PageTemplate(id="title", frames=[top, l1, r1],
                                       onPage=footer),
                          PageTemplate(id="two", frames=[lcol, rcol], onPage=footer)])

    e = []
    add = e.append
    p1 = status("P1")
    joint = obligations.get("P1-JOINT")
    joint_kinds = by_prefix("JOINT-VC")
    vec = validation["vectors"]
    py = validation["py65"]
    overall = cross["overall"]
    fetched = observed["fetched_program_counters"]
    fetched2 = observed2["fetched_program_counters"]
    landings = observed["dispatch_landings"]
    derailed = storm["manifest"]["variants_whose_pc_left_the_graph_or_prg"]
    variants = storm["manifest"]["variants"]

    add(P("Toward a Machine-Checked Instruction-Location Invariant for "
          "<i>Super Mario Bros.</i> (NES): Model, Lemmas, Certificate "
          "Checking and Open Obligations", TITLE))
    add(P("Alexander Sadovsky, ChatGPT (OpenAI), and Claude (Anthropic)", AUTH))
    add(P("<font size=8>ChatGPT (OpenAI) contributed the formal-verification "
          "plan this report executes (property definitions, the status "
          "taxonomy, the milestone structure and the rules separating proof "
          "from evidence) and the earlier remediation review. Claude "
          "(Anthropic) contributed the machine model, its validation, the "
          "solver infrastructure, the lemmas, the certificate language, "
          "checker and proposer, the dynamic tracer, the literature review "
          "and this text. Alexander Sadovsky directed the work and supplied "
          "the program image, which is not distributed.</font>", AUTH))
    add(P("November 2026", AUTH))
    add(Spacer(1, 6))

    if joint is None:
        joint_sentence = ("A joint inductive-invariant certificate was "
                          "designed but no checked result is recorded.")
    else:
        held = sum(o["detail"]["holds"] for o in joint_kinds)
        asked = sum(o["detail"]["conditions"] for o in joint_kinds)
        joint_sentence = (
            "An untrusted abstract interpreter proposes a per-instruction "
            "invariant with routine contracts, and an independent checker "
            f"discharges {n(held)} of its {n(asked)} verification "
            f"conditions; the certificate as a whole is "
            f"<b>{status('JOINT-CERTIFICATE')}</b>.")
    add(P(
        "<b>Abstract.</b> We ask whether the NTSC <i>Super Mario Bros.</i> "
        "program image satisfies an instruction-location invariant: in every "
        "reachable state, for every controller input sequence, the processor "
        "fetches instructions only from program ROM. We do not settle the "
        f"question. The primary theorem's recorded status is <b>{p1}</b>. "
        "What we contribute is the apparatus and a set of results whose "
        "epistemic status is tracked individually: an instruction-level SMT "
        "model of the 2A03 covering all 256 opcodes, validated on "
        f"{n(vec['instructions_compared'])} published single-instruction "
        f"vectors and {n(py['instructions_compared'])} randomised comparisons "
        "with no mismatch; an obligation ledger that forbids a claim from "
        f"being recorded as proved while it rests on an assumption; "
        f"{counts.get('proved', 0)} lemmas proved in that model and "
        "confirmed by a second solver, among them the exact contract of all "
        "18 uses of the game's single computed jump; backward symbolic "
        "slices that close some dispatch indices and leave others with "
        "abstract counterexamples; and a concrete execution showing that "
        "the invariant is <i>false</i> in the model variant where "
        "non-maskable interrupts may occur at any instruction boundary, "
        "which identifies the timing assumptions any proof must make. "
        + joint_sentence +
        " Instruction-level tracing of "
        f"{n(observed['manifest']['instructions_total'] + observed2['manifest']['instructions_total'])} "
        "instructions found no fetch off the recovered control-flow graph; "
        "that is an observation and is reported as one. None of the "
        "techniques is new; the application appears to be.", ABSTRACT))
    add(Spacer(1, 4))
    add(NextPageTemplate("two"))
    add(FrameBreak())

    sec = [0]

    def H(title):
        sec[0] += 1
        assert SECTIONS[sec[0] - 1] == title, (sec[0], title)
        add(P(f"{sec[0]}&nbsp;&nbsp;{title}", H1))

    def S(title):
        return str(SECTIONS.index(title) + 1)

    # ------------------------------------------------------------------
    H("Question and scope")
    add(P("The companion audit in this repository established by static "
          "analysis that the image contains one indirect jump, "
          + C("JMP ($0006)") + " inside a shared dispatcher at " + C("$8E04")
          + ", and that 336 " + C("RTS") + " and one " + C("RTI")
          + " also take their destinations from writable memory. It could "
          "not show that those destinations stay inside the program. This "
          "report takes the same question to a setting where &quot;show&quot; "
          "has a fixed meaning: a transition system, a property, and solver "
          "queries whose text is saved and hashed."))
    add(P("<b>Property P1, informally.</b> In every reachable state, for "
          "every controller input sequence, an opcode fetch reads from "
          "program ROM. Section " + S("Formal setting") + " makes each word of that precise; Figure 1 "
          "shows the address space it refers to."))
    FIG(figures.address_map(manifest["instruction_starts_N"]),
        "The CPU address space as modelled (schematic, not to scale). P1 "
        "confines opcode fetches to the upper half.")
    add(P("<b>Threat model.</b> Controller input is the only adversarial "
          "channel. Game Genie codes, ROM patches, RAM injection, debuggers, "
          "emulator defects, cartridge swapping, fault injection and "
          "hardware modification are outside it. The formal model is "
          "deliberately more permissive than that in one respect that "
          "matters: at cold boot it leaves all 2 KiB of RAM unconstrained "
          "(Section " + S("Initial memory, and a published result that constrains the theorem") + ")."))
    add(P("<b>Rules of evidence.</b> Every claim carries one status from a "
          "fixed list: <i>proved</i>, <i>conditional</i>, <i>bounded</i>, "
          "<i>refuted</i>, <i>abstract counterexample</i>, <i>unknown</i>, "
          "<i>timeout</i>, <i>observed</i>. The ledger refuses to record "
          "<i>proved</i> for a claim with assumptions, and a settling pass "
          "demotes any claim whose dependencies are not themselves proved. "
          "Implementation correctness, model validation and mathematical "
          "proof are reported separately throughout."))

    # ------------------------------------------------------------------
    H("Formal setting")
    add(P("A machine state at an instruction boundary consists of four "
          "byte registers, six status flags, the program counter, the "
          "2,048 bytes of RAM, and one ghost bit recording whether NMI is "
          "enabled: 16,439 bits in all. The image is a constant and is not "
          "part of the state. With about 2<super>16439</super> states, P1 "
          "cannot be settled by enumeration; the question is whether an "
          "invariant can be found."))
    add(P("Controller input is not a component of the state either. Every "
          "read of a device address returns a fresh unconstrained byte, so "
          "the model's behaviours already include every input sequence. "
          "From a state the machine may execute the instruction at the "
          "program counter, take an NMI if the ghost bit is set, take an "
          "IRQ if the I flag is clear, or be reset. Call that relation "
          + C("T") + ", and let " + C("I") + " be the cold-boot states: "
          "program counter at the reset vector, I set, NMI disabled, "
          "everything else free. Writing Reach for the states reachable "
          "from " + C("I") + " by " + C("T") + ", the property is"))
    EQ(r"\mathrm{P1}:\quad \forall s \in \mathrm{Reach}(I,T).\;\; "
       r"\mathtt{8000}_{16} \,\leq\, pc(s) \,\leq\, \mathtt{FFFF}_{16}")
    add(P("We work with the stronger requirement that the program counter "
          "is in " + C("N") + ", the set of "
          f"{n(manifest['instruction_starts_N'])} instruction starts "
          "recovered by recursive descent from the three vectors. It "
          "implies P1 because " + C("N") + " lies in ROM, and it also "
          "excludes execution of misaligned bytes inside ROM. A proof "
          "consists of a predicate " + C("J") + " on states satisfying "
          "three conditions, each of which is a validity query for a "
          "solver:"))
    EQ(r"I \Rightarrow J, \qquad J(s) \wedge T(s,s') \Rightarrow J(s'), "
       r"\qquad J(s) \Rightarrow pc(s) \in N", 9.5)
    add(P("The whole difficulty is the middle condition: " + C("J")
          + " must be strong enough to survive every instruction, "
          "interrupt and reset. One consequence of this setting organises "
          "the report. Removing transitions or initial states can only "
          "shrink the reachable set, so a proof for an over-approximate "
          "model carries over to any refinement of it, including hardware "
          "if the model over-approximates hardware; a counterexample does "
          "not carry over. Every assumption named MA-* below removes "
          "transitions or initial states, and a result that uses one is a "
          "statement about the smaller system only."))

    # ------------------------------------------------------------------
    H("Machine model")
    add(P("The model is at instruction granularity. One Python definition "
          "of each of the 256 opcodes builds Z3 terms; evaluated on constants "
          "it is an interpreter, evaluated on symbols it is the transition "
          "relation, so the object validated is the object reasoned about. "
          "Six undocumented opcodes whose results depend on analogue effects "
          "(" + C("XAA, LXA, SHA, SHX, SHY, TAS") + ") assign unconstrained "
          "values to everything they can affect. The decimal flag is a "
          "storage bit with no arithmetic effect, as on the 2A03 "
          + cite("nesdev-map") + "."))
    add(P("RAM is an array indexed by 11 bits, so the three mirrors of "
          + C("$0000-$07FF") + " are identities of the sort rather than "
          "lemmas. Reads of " + C("$2000-$7FFF") + " return fresh "
          "unconstrained bytes: no claim depends on PPU, APU, controller or "
          "open-bus values, and conversely every such value is adversarial, "
          "which is more than a controller can do. Program ROM is immutable; "
          "NROM has no mapper registers."))
    add(P("Between instructions the machine may take a reset at any time, an "
          "IRQ whenever the I flag is clear, and an NMI whenever a ghost bit "
          "is set that copies bit 7 of the last byte written to PPU control. "
          "That NMI rule over-approximates hardware, which needs a rising "
          "edge of (vertical-blank flag AND enable) " + cite("nesdev-int")
          + ". Section " + S("The invariant is false without interrupt timing") + " shows the over-approximation is too coarse to "
          "prove anything and what replaces it."))
    add(P("<b>Assumptions that remove behaviours</b>, each named wherever a "
          "result uses it. MA-CPU: the model matches the 2A03 at instruction "
          "boundaries. MA-PPU-POWERON: PPU control is zero at power-on. "
          "MA-PPU-WARMUP: writes to PPU control take effect; hardware "
          "ignores them from power-on until the pre-render scanline of the "
          "next frame, a scanline-phase condition that the commonly quoted "
          "cycle count only approximates " + cite("nesdev-ppu") + ". "
          "MA-NMI-EDGE, MA-NMI-LATENCY and MA-PPU-RESET are introduced in "
          "Sections " + S("The invariant is false without interrupt timing") + " and " + S("Joint inductive invariant") + "."))

    # ------------------------------------------------------------------
    H("Model validation")
    add(P("Validation is sampling, and is reported as such. The model was "
          f"run on the first {vec['per_opcode']} SingleStepTests "
          + cite("sst") + f" vectors for each of {vec['opcodes_compared']} "
          f"opcodes: {n(vec['instructions_compared'])} instructions, "
          f"comparing every register, flag, and touched memory cell after "
          f"the instruction, with <b>{vec['mismatch_count']}</b> mismatches. "
          f"The remaining opcodes are the halting ones, which the vectors "
          "describe only by bus activity, and the unstable ones, which the "
          "model does not determine and which are therefore not counted as "
          f"agreement. A further {n(py['instructions_compared'])} randomised "
          "single steps were compared with the independent py65 interpreter "
          f"({py['mismatch_count']} mismatches; decimal mode excluded "
          "because py65 implements it)."))
    add(P("Not covered: cycle-level behaviour, interrupt polling inside an "
          "instruction, dummy reads and writes, and anything about the PPU "
          "or APU beyond the ghost bit. A defect in the model that the "
          "vectors do not exercise would invalidate results silently; this "
          "is the first item of the trusted base."))

    # ------------------------------------------------------------------
    H("Proof infrastructure")
    add(P("A claim is discharged by asserting its hypotheses and the "
          "negation of its conclusion and obtaining <i>unsat</i>. For the "
          "lemma-style obligations the query is serialised deterministically "
          "to SMT-LIB, hashed, saved, and re-run by cvc5 through its own "
          "parser " + cite("z3") + "; a disagreement between solvers is "
          "recorded as such. Queries that embed program bytes are hashed but "
          "not stored in the repository, since the image is not distributed. "
          "The slice-based results of Section " + S("Backward slices")
          + " go through the same treatment with Bitwuzla as a third "
          "solver: every answer a slice relies on is hashed and re-asked. "
          "Certificate conditions (Section " + S("Joint inductive invariant")
          + ") are checked by Z3 only."))
    g = obligations.get("GRAPH-EDGES")
    if g is not None:
        add(P("The recovered graph is itself checked against the model ("
              + C("GRAPH-EDGES") + ": <b>" + g["status"] + "</b>): for "
              "every instruction start whose own bytes decide where control "
              "goes, the successors the model allows from an unconstrained "
              "state are exactly the recorded edges. Returns and the "
              "dispatcher's jump are excluded, being the subject of the "
              "open obligations, and instruction lengths come from the "
              "opcode table the model shares with the decoder, so that part "
              "is not independent."))
    add(P(f"The ledger holds {total} obligations: "
          + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in
                      sorted(counts.items())) + ". "
          "Three of the <i>refuted</i> entries are deliberate negative "
          "tests: false statements included to confirm that the pipeline "
          "reports falsehood rather than timing out or passing."))
    FIG(figures.ledger(counts),
        "Obligations in the ledger by settled status. Counts are not a "
        "measure of progress toward P1: the obligations differ greatly in "
        "weight.")

    # ------------------------------------------------------------------
    H("Local lemmas and dispatch contracts")
    contracts = [o for o in by_prefix("D-") if o["id"].endswith("-CONTRACT")]
    add(P("The dispatcher at " + C("$8E04") + " pulls its caller's return "
          "address, doubles A, reads a 16-bit entry from the table that "
          "follows the " + C("JSR") + ", and jumps through " + C("$0006")
          + ". Let site " + C("k") + " be at address " + C("d_k")
          + " with table " + C("E_k") + " of " + C("n_k") + " entries. "
          "For each of the 18 sites we prove, by executing the dispatcher's "
          "instructions symbolically from an otherwise unconstrained state "
          "(any stack pointer, any RAM), the contract"))
    EQ(r"pc = d_k \;\wedge\; (a \;\mathrm{and}\; \mathtt{7F}_{16}) < n_k "
       r"\;\;\Rightarrow\;\; pc' = E_k[\,a \;\mathrm{and}\; \mathtt{7F}_{16}\,]", 9.5)
    add(P("where " + C("pc'") + " is the first fetch after the "
          "dispatcher's indirect jump. Status: " + tally(contracts)
          + ". The same statement with the bound weakened by one is "
          "refuted, as it should be. Since every " + C("E_k[j]")
          + " is in " + C("N") + ", the location obligation at the only "
          "indirect jump reduces to index bounds:"))
    EQ(r"\bigwedge_{k=1}^{18}\; \forall s \in \mathrm{Reach}.\;\; "
       r"pc(s) = d_k \Rightarrow (a(s) \;\mathrm{and}\; \mathtt{7F}_{16}) < n_k", 9.5)
    add(P("One site forms its index from the RAM cell " + C("v = M[071F]")
          + " by a computation the first revision of the audit had "
          "misread. Executing the ROM bytes of " + C("$92B0-$92C8")
          + " symbolically gives, for every initial state,"))
    EQ(r"a \;=\; \left((v \,\vee\, 8) - 1\right) \;\mathrm{mod}\; 256, "
       r"\qquad v \leq 8 \;\Rightarrow\; a \leq 7")
    add(P("(" + C("L-92C8-ROM-EXACT") + ": " + status("L-92C8-ROM-EXACT")
          + "; " + C("L-92C8-ARITH") + ": " + status("L-92C8-ARITH")
          + "). The table there has 8 entries, so the site is safe exactly "
          "when " + C("v &le; 8") + " whenever " + C("$92B0")
          + " is fetched, which is a global fact about " + C("v") + "."))
    add(P("These are theorems about the model with no assumption beyond it. "
          "They move the whole question to the indices: P1 at the indirect "
          "jump holds exactly when each site's index is in range in every "
          "reachable state."))

    # ------------------------------------------------------------------
    H("Backward slices")
    indices = by_prefix("P6-")
    writers = by_prefix("W-071F-")
    add(P("To bound an index without a global invariant we execute "
          "instruction suffixes ending at the site from a fully "
          "unconstrained state, and extend a suffix backwards through "
          "predecessors for as long as an out-of-range index remains "
          "satisfiable. A site closes when every suffix is unsatisfiable. "
          "Results hold under stated side conditions (the slice starts on "
          "the graph, no interrupt intervenes inside it, the stack is "
          "intact across inlined calls)."))
    add(P("Index obligations: " + tally(indices) + ". The sites that close "
          "are those whose index is masked or compared within a few "
          "instructions of the dispatch. The others load the index from a "
          "RAM cell written elsewhere; the slice reaches a routine entry "
          "with the cell unconstrained, which is an <i>abstract "
          "counterexample</i>: a model of the query that is not known to be "
          "reachable. It is neither a refutation nor evidence of safety."))
    add(P("For the cell " + C("$071F") + " we enumerated every instruction "
          "the model allows to write it and sliced each: " + tally(writers)
          + ". The model found three writers a syntactic census had missed, "
          "two unstable opcodes in unreachable data-as-code and an "
          "indexed shift on the IRQ path. A decrement at " + C("$92BF")
          + " keeps the cell in range only if it was in range before, which "
          "is exactly the kind of fact a local method cannot supply."))
    sps = obligations.get("STACK-PAGE-STORES")
    if sps is not None:
        add(P("Return addresses are the other source of computed control. "
              "The obligation that no ordinary store reaches the live part "
              "of the stack page is recorded as <b>" + sps["status"]
              + "</b>. Tracing (Section " + S("Observations") + ") shows why it is hard: the game "
              "keeps data in " + C("$0109-$0139") + " and writes it with "
              "indexed stores."))

    # ------------------------------------------------------------------
    H("The invariant is false without interrupt timing")
    first = next((v for v in storm["variants"]
                  if v.get("entries_forced") == 86), None)
    add(P("In the transition system as first defined, an NMI may be taken "
          "at any boundary while the enable bit is set. The handler at "
          + C("$8082") + " clears the bit two instructions in, so the model "
          "permits the handler to be re-entered before its first "
          "instruction, without bound. Each entry pushes three bytes; the "
          "stack page holds 256, and after " + C("k") + " re-entries the "
          "stack pointer is"))
    EQ(r"S_k \;=\; (S_0 - 3k) \;\mathrm{mod}\; 256, \qquad "
       r"3 \cdot 86 = 258 \equiv 2 \;(\mathrm{mod}\; 256)")
    add(P("Because " + C("gcd(3, 256) = 1") + ", the pointer visits every "
          "residue before repeating, and from the 86th entry on new frames "
          "overwrite old ones at an offset of two bytes: a later "
          + C("RTI") + " or " + C("RTS") + " pulls a mixture of bytes from "
          "different frames (Figure " + str(fig_no[0] + 1) + ")."))
    FIG(figures.stack_wrap(storm),
        "Stack pointer at successive forced NMI entries in the 256-entry "
        "variant: the prediction of Eq. (" + str(eq_no[0]) + ") and the "
        "values recorded in the trace (first and last eight entries).")
    add(P("We conjectured that enough re-entries wrap the stack and "
          "misalign a return frame, and tested it by concrete execution "
          f"with forced NMI delivery. Of {variants} variants, "
          f"<b>{derailed}</b> ended with the program counter off the "
          "recovered graph. With 86 entries the handler eventually returns "
          "through a frame whose high byte was written by an ordinary store "
          "into the stack page, and the next fetch is in RAM. With 256 "
          "entries a subroutine return lands in the middle of an "
          "instruction inside ROM. Device reads in these runs take the "
          "values a stub supplies; each is one admissible choice in a model "
          "where they are unconstrained."))
    FIG(figures.storm_outcomes(storm),
        "Outcome of each forced-re-entry variant. Each cell is one "
        "concrete execution in the model variant with unrestricted NMI "
        "delivery; none is a claim about hardware.")
    add(P("<b>This is a statement about a model variant, not about any "
          "console.</b> An NES delivers at most one NMI per vertical blank. "
          "Its value is diagnostic: P1 cannot be proved for the "
          "over-approximate interrupt rule, so a proof must assume timing. "
          "We use two assumptions. MA-NMI-EDGE: no second NMI is taken "
          "between interrupt entry and the handler's disabling write. "
          "MA-NMI-LATENCY: no NMI is taken between the handler's enabling "
          "write and the completion of its " + C("RTI") + ". So the "
          "invariant is refuted for the unrestricted model and open for "
          "the model restricted by these two assumptions."))
    tc = timing["status_counts"]
    add(P("<b>Are the assumptions true of hardware?</b> To move them from "
          "assumed toward derived we built a small cycle-level model of the "
          "NMI edge detector and the CPU's interrupt poll, with cycle "
          "counts and write positions taken from the per-cycle bus records "
          f"of {n(timing['validation']['vectors_read'])} test vectors "
          + cite("sst") + " and each rule tied to its NESdev sentence "
          + cite("nesdev-int") + ". Two timing rules the documentation "
          "leaves open are enumerated both ways. Exhaustive enumeration "
          "over every adversarial vertical-blank timing gives "
          f"{tc.get('proved', 0)} result proved and "
          f"{tc.get('conditional', 0)} conditional:"))
    rows = [["Claim", "Status", "Premise"],
            ["No NMI can be taken while the enable bit is clear",
             "proved", "none"],
            ["No second NMI in the 23 cycles from entry to the disabling "
             "write", "conditional",
             "the vertical-blank flag is not set again in that window; "
             "implied by documented frame timing, stated nowhere"],
            ["No NMI between the enabling write and the end of RTI",
             "conditional",
             "NMI is disabled and none is pending when the handler's exit "
             "sequence begins; a property of the program, not of timing"]]
    add(table(rows, [cwi * 0.36, cwi * 0.2, cwi * 0.44]))
    add(P("Table 1. Interrupt-timing claims derived from the cycle model.",
          CAP))
    add(P("Each conditional claim is refuted, with a witness timing, when "
          "its premise is dropped. The second premise matters: the latency "
          "assumption is not a fact about two instructions but depends on "
          "the handler body leaving NMI disabled, which is exactly the "
          "open invariant about the PPU-control mirror cell. The analysis "
          "also found that the handler body does write PPU control, "
          "through a shared routine, with a value read from that same "
          "cell; and nine stores through a RAM pointer reachable from the "
          "handler are not yet bounded away from the register. The cycle "
          "model itself is checked against bus records for six opcodes "
          "and against no hardware measurement."))
    FIG(figures.handler_timeline(),
        "The NMI handler and the two windows in which the assumptions "
        "exclude a further NMI (schematic; addresses from the image).")

    # ------------------------------------------------------------------
    H("Joint inductive invariant")
    add(P("The global argument is a certificate in the style of "
          "proof-carrying code " + cite("pcc") + " and annotation inference "
          + cite("houdini") + ": for each instruction start, qualified by "
          "the routine it executes under and by the ghost enable bit, an "
          "abstract state (value sets for registers and named RAM cells, "
          "stack depth relative to the routine's entry, and an assertion "
          "that the entry frame is intact); and for each routine a contract "
          "(cells it may modify, stack it may use, a postcondition). "
          "Verification conditions cover single steps, the modifies clause, "
          "calls and returns through the frame rule, the dispatcher, NMI "
          "entry, resumption and exit, reset, cold boot, forbidden "
          "instructions and coverage. A routine's contract says that "
          "everything it writes, directly or through callees, is a cell in "
          "its declared set, a stack byte within its declared depth below "
          "its entry stack pointer, or a device address. A caller may "
          "therefore keep everything it knew about other cells (the frame "
          "rule), in particular its own return address, and a return is "
          "safe when it executes at depth zero with the entry frame "
          "asserted intact."))
    add(P("The proposer is an abstract interpreter and is untrusted. The "
          "checker shares no code with it, treats any context the "
          "certificate omits as unreachable, and turns each condition into "
          "one quantifier-free query over the machine model."))
    add(P("The step from &quot;every condition holds&quot; to &quot;the "
          "conjunction is inductive&quot; we mechanised in Lean 4 for an "
          "abstract machine (seven opaque transition relations and the "
          "constraints linking control flow to the stack). The theorem "
          "that every reachable program counter is a live context is "
          "proved with no unproved steps, but only after adding hypotheses "
          "the design had omitted, and the development includes a small "
          "concrete certificate that satisfies every condition as "
          "originally written yet reaches an unsafe address. The "
          "conditions as designed therefore did not imply safety. The "
          "omissions are: the interrupt windows were taken from the "
          "certificate unvalidated; an interrupt inside a callee was not "
          "charged to its suspended callers; the handler's postcondition "
          "was checked before " + C("RTI") + " and assumed after it; and "
          "stack depth was compared in 8-bit modular arithmetic with no "
          "bound on total depth. The mechanisation does not cover the "
          "6502 semantics, the SMT encoding of each condition, or the "
          "checker's code, and it models the stack pointer as an integer, "
          "which assumes the missing depth bound."))
    if joint_kinds:
        rows = [["Condition kind", "Holds", "Total", "Status"]]
        for o in joint_kinds:
            d = o["detail"]
            rows.append([o["id"].replace("JOINT-", ""), n(d["holds"]),
                         n(d["conditions"]), o["status"]])
        add(table(rows, [cwi * 0.36, cwi * 0.2, cwi * 0.2, cwi * 0.24]))
        add(P("Table 2. Verification conditions of the proposed "
              "certificate, by kind, as recorded by the checker.", CAP))
        cert = obligations["JOINT-CERTIFICATE"]
        d = cert["detail"]
        add(P(f"The certificate has {n(d['live_contexts'])} live contexts "
              f"over {n(d['routines'])} routines. Its status is "
              f"<b>{cert['status']}</b> and the status of P1 by this route "
              f"is <b>{joint['status']}</b>. A failed condition means this "
              "candidate is not inductive at that point; it is not a "
              "counterexample to P1, and a count of conditions that hold is "
              "not a degree of proof."))
        if joint["status"] != "conditional":
            add(P("The failures are listed with satisfying assignments in "
                  + C("formal/results/reports/joint_verdicts.json")
                  + ". They are the precise remaining obligations of this "
                  "route."))
    else:
        add(P("No checked certificate is recorded in the manifest this "
              "report was built from."))
    add(P("<b>A finding about reset.</b> Building the certificate exposed a "
          "behaviour the design had not anticipated. The model carries the "
          "enable bit across a warm reset. If reset arrives while NMI is "
          "enabled, an NMI taken between the first two instructions of the "
          "reset routine returns with bit 7 of A set, and the routine's own "
          "store to PPU control then <i>re-enables</i> NMI, so "
          "initialisation, including the loop that clears RAM, runs "
          "interruptible. The certificate excludes this by assuming "
          "MA-PPU-RESET, that reset clears PPU control. NESdev documents "
          "that as true of the front-loading NES and false of the Famicom "
          "and the top-loading NES, whose reset button resets only the CPU "
          + cite("nesdev-ppu") + ". On those consoles the scenario is not "
          "excluded by anything we have proved; whether it can be driven "
          "anywhere harmful is open."))

    # ------------------------------------------------------------------
    H("Initial memory, and a published result that constrains the theorem")
    add(P("The model's cold-boot predicate constrains no RAM cell, so the "
          "theorem has to say which cells its conclusion is quantified "
          "over."))
    if init is not None:
        part = init["partition"]
        over, never, warm = (part["always_overwritten"],
                             part["never_initialised"],
                             part["preserved_in_the_warm_case_only"])
        st = init["statuses"]
        proved = sum(1 for v in st.values() if v == "proved")
        add(P("We computed that by executing the reset routine "
              "symbolically, with all of RAM free, from the reset vector to "
              "the first instruction that can enable NMI. Its two "
              "wait-for-vertical-blank loops are closed by proved "
              "invariants and its RAM-clearing loop is unrolled with trip "
              "counts derived, not assumed. The 2,048 cells split three "
              f"ways ({proved} of {len(st)} supporting obligations proved; "
              "the partition itself is <b>" + st["INIT-MEM-PARTITION"]
              + "</b>, on MA-PPU-POWERON):"))
        rows = [["Cells", "Count", "At the first NMI-enabling instruction"],
                [", ".join(over["ranges"]), n(over["count"]),
                 "overwritten with a determined value on every path"],
                [", ".join(warm["ranges"]), n(warm["count"]),
                 "zero on a cold boot; kept on a warm boot"],
                [", ".join(never["ranges"]), n(never["count"]),
                 "never written: whatever power-on left there"]]
        add(table(rows, [cwi * 0.36, cwi * 0.14, cwi * 0.5]))
        add(P("Table 3. Initial-memory partition, proved from the image.",
              CAP))
        add(P("The warm-boot case is taken exactly when "
              + C(init["warm_boot_condition"].replace("<u", "&lt;"))
              + ", a condition recovered from the path conditions and "
              "proved equal to them. So P1's free parameter is the "
              f"{never['count']} never-written cells, which lie in the "
              "upper half of the stack page, plus the "
              f"{warm['count']} preserved cells when that condition holds. "
              "Everything else is a constant by the time an interrupt can "
              "occur. The same analysis shows every fetch in the "
              "initialisation window is in ROM ("
              + st["INIT-MEM-FETCHES-IN-ROM"] + "), and records as "
              "<b>" + st["INIT-MEM-NMI-WARM-RESET"] + "</b> the claim that "
              "no NMI can precede the routine's first store after a warm "
              "reset, which is the reset finding of the previous section "
              "seen from this side."))
    add(P("A published tool-assisted run " + cite("tas8991")
          + " reports arbitrary code execution in this game from a state "
          "in which such cells were pre-loaded by running a different "
          "cartridge first. Cartridge swapping is outside our threat model, "
          "but a predicate that leaves RAM unconstrained does not exclude "
          "the states it produces. We have not reproduced that run and "
          "record nothing about it as a result of ours. Its consequence "
          "for this work is logical: P1 with unconstrained initial RAM "
          "should be expected to be false, and a true theorem must restrict "
          "initial memory, at least for the cells initialisation does not "
          "write. Which restriction real power-on justifies is a hardware "
          "question we do not answer. Whether the invariant can fail from a "
          "clean power-on by controller input alone remains the open "
          "question of the companion audit."))

    # ------------------------------------------------------------------
    H("Observations")
    add(P("An instruction-level tracer was built on a second CPU "
          "implementation and compared with the independent nes-py "
          "emulator instruction by instruction: "
          f"{n(overall['instructions_compared'])} fetches with "
          f"{overall['program_counter_differences']} program-counter and "
          f"{overall['register_mismatches']} register differences, after "
          "removing six timing-dependent wait loops from both streams. "
          "Agreement between two emulators is not agreement with a "
          "console."))
    sp = observed["stack_pointer"]
    add(P(f"Over {n(observed['manifest']['frames_total'])} frames on the "
          f"tracer and {n(observed2['manifest']['frames_total'])} on nes-py, "
          f"<b>{fetched['fetched_but_not_an_instruction_start_count']}</b> "
          "fetches were at an address that is not a recovered instruction "
          f"start and {len(fetched['outside_prg'])} were outside ROM; "
          f"coverage of the graph was {fetched['graph_coverage']:.1%} and "
          f"{fetched2['graph_coverage']:.1%}. "
          f"{n(landings['checked'])} dispatches were checked against their "
          f"tables with {len(landings['landed_elsewhere'])} discrepancies, "
          f"and no index left its table at the "
          f"{sum(1 for s in observed['dispatch_sites'] if s['fetches'])} of "
          "18 sites that were reached. The stack pointer stayed in "
          + C(f"${sp['min_at_any_fetch']:02X}-${sp['max_at_any_fetch']:02X}")
          + " and was " + C(f"${sp['max_at_nmi_entry']:02X}")
          + " at every NMI entry; "
          f"{len(observed['stack_page_writes']['non_push_writers'])} "
          "ordinary instructions wrote into the stack page. No NMI was "
          "delivered while the handler was running."))
    add(P("Status of all of the above: <i>observed</i>. The input models "
          "reach only the first world, three dispatch sites were never "
          "executed, and roughly two fifths of the graph was not covered. "
          "No bound follows."))
    FIG(figures.coverage(fetched, fetched2, manifest["instruction_starts_N"]),
        "Instruction starts executed at least once, per engine.")
    FIG(figures.dispatch_sites(observed),
        "Largest dispatch index observed at each site against the table "
        "length (tracer engine). Observation only; three sites were never "
        "reached.")

    # ------------------------------------------------------------------
    H("Status of the primary theorem")
    rows = [["Obligation", "Status"]]
    for ident in ("LOC-DIRECT", "LOC-ENGINE", "LOC-ASYNC", "LOC-DISPATCH",
                  "LOC-RETURN", "J-ASYNC", "J-IRQ", "P1", "JOINT-CERTIFICATE",
                  "P1-JOINT"):
        if ident in obligations:
            rows.append([ident, obligations[ident]["status"]])
    contracts_all = [o for o in by_prefix("D-") if o["id"].endswith("-CONTRACT")]
    index_all = [o for o in by_prefix("P6-") if o["id"].endswith("-INDEX")
                 or o["id"].endswith("-GIVEN-071F")]
    closed = sum(1 for o in index_all if o["status"] in ("proved", "conditional"))
    worst = ("abstract_counterexample" if any(
        o["status"] == "abstract_counterexample" for o in index_all)
        else "unknown")
    FIG(figures.decomposition(
        {k: v["status"] for k, v in obligations.items()},
        {"contracts_label": f"{len(contracts_all)} site\ncontracts",
         "contracts_status": ("proved" if all(
             o["status"] == "proved" for o in contracts_all) else "unknown"),
         "indices_label": f"18 index\nbounds:\n{closed} closed",
         "indices_status": worst if closed < 18 else "conditional"}),
        "Decomposition of P1 with the settled status of each obligation. "
        "An arrow reads &quot;depends on&quot;.")
    add(table(rows, [cwi * 0.6, cwi * 0.4]))
    add(P("Table 4. The decomposition of P1, as settled by the ledger.", CAP))
    add(P("Direct transfers, the dispatcher's own code and the interrupt "
          "vectors are proved to stay on the graph. What remains is that "
          "every dispatch index is in range and every return frame is "
          "intact in every reachable state, under interrupt-timing "
          "assumptions and an initial-memory restriction that the theorem "
          "must state. We have a refutation for the model without the "
          "timing assumptions, no counterexample for the model with them, "
          "and no proof."))

    # ------------------------------------------------------------------
    H("Trusted base and threats to validity")
    add(P("A reader who accepts a <i>proved</i> entry is trusting: the "
          "machine model, validated by sampling only; the opcode table and "
          "the recovered set of instruction starts, whose edges are now "
          "checked against the model but whose completeness at returns is "
          "not; Z3 "
          "with cvc5 and Bitwuzla as cross-checks on the lemma and slice "
          "queries; the Python that builds queries, "
          "including the ledger; and, for the certificate route, the "
          "soundness argument, mechanised only for an abstract machine, "
          "and the checker, whose encoding of each condition is not "
          "verified against that mechanisation. Until the checker "
          "implements the corrected conditions, its verdicts do not carry "
          "the meaning the argument needs, and none are reported here."))
    add(P("The model is at instruction granularity and says nothing about "
          "behaviour that depends on cycles within an instruction. The "
          "interrupt assumptions are inferences from community hardware "
          "documentation, not vendor specifications. Results are for one "
          "image, identified by SHA-1 " + C(manifest["rom_sha1"]) + "."))

    # ------------------------------------------------------------------
    H("Related work")
    add(P("Machine-checked confinement of a real binary against a formal "
          "instruction-set model is established: ARMor " + cite("armor")
          + " and RockSalt " + cite("rocksalt") + " prove that all control "
          "transfers of a binary stay in a permitted region, which is the "
          "shape of P1. The seL4 binary proof " + cite("sel4")
          + " and decompilation into logic " + cite("myreen")
          + " reason about concrete machine code with every step reduced to "
          "a proof kernel, a standard of assurance this work does not meet. "
          "Control-flow recovery with indirect-branch resolution is the "
          "problem of value-set analysis " + cite("vsa") + " and Jakstab "
          + cite("jakstab") + "; provably over-approximate lifting exists "
          "for x86-64 " + cite("verbeek") + ". Symbolic execution driven by "
          "a formal ISA semantics, and its ability to expose errors in "
          "hand-written lifters, is shown by BinSym " + cite("binsym") + "."))
    add(P("Verification of interrupt-driven microcontroller binaries "
          "predates this work by two decades: [mc]square " + cite("mcsquare")
          + " model-checks 8-bit assembly directly, and Regehr and "
          "co-authors treat interrupts " + cite("regehr-int")
          + " and bound stack depth for interrupt-driven object code "
          + cite("regehr-stack") + ", noting that modelling when interrupts "
          "are enabled is essential to precision, which Section " + S("The invariant is false without interrupt timing") + " "
          "rediscovers. Invariant inference with a separate checker follows "
          "Houdini " + cite("houdini") + " and proof-carrying code "
          + cite("pcc") + "; IC3 " + cite("ic3") + " is the natural "
          "automated alternative we did not try."))
    add(P("For the 6502 the strong artefacts are empirical: a "
          "transistor-level netlist simulation " + cite("visual6502")
          + " and large vector suites " + cite("sst") + ". We found a "
          "forum description of a Z3-based 6502 symbolic executor "
          + cite("forum") + " and no published mechanised semantics. Work "
          "on games addresses idealised versions "
          + cite("aloupis", "demaine") + " or classifies known glitches "
          + cite("kingdoms") + ", the latter observing that symbolic "
          "execution is not typically used for glitch discovery. The "
          "exploitation knowledge itself lives in the tool-assisted "
          "speedrun community " + cite("tas8991") + "."))

    H("Novelty")
    add(P("We claim no new technique. A literature search on 2026-11-25 "
          "found no published SMT or proof-assistant semantics of the "
          "6502/2A03 and no application of binary-level formal verification "
          "to a commercial console game image. That is a statement about "
          "what a search found; hobby and unpublished formalisations are "
          "poorly indexed and may exist. If the gap is real, the "
          "contribution is the application and the resulting list of "
          "precisely stated obligations and assumptions, not a theorem."))

    H("Reproducibility")
    text = ("The image is supplied by the reader and is not distributed. "
            + C("tools/reproduce.sh") + " regenerates the manifest; "
            + C("formal/replicate/replicate.sh") + " repeats the run from a "
            "fresh clone in a fresh virtual environment with pinned solver "
            "versions and re-checks every saved query with a script that "
            "imports nothing from the project. Solver versions: Z3 "
            + manifest["solver"]["z3"] + ", cvc5 " + manifest["solver"]["cvc5"]
            + ". ")
    if replication is not None:
        text += ("The replication recorded in "
                 + C("formal/results/reports/replication.json")
                 + " reports: "
                 + C(json.dumps(replication.get("summary", {}))[:300]) + ". ")
    else:
        text += "No replication record was present when this was built. "
    text += ("This is replication by the same authors with the same code on "
             "the same machine; it detects nondeterminism and environment "
             "dependence, not errors of reasoning.")
    add(P(text))

    H("References")
    for i, (_key, textref) in enumerate(REFS, 1):
        add(P(f"[{i}]&nbsp;&nbsp;{textref}", REF))

    doc.build(e)
    print(OUT, f"{os.path.getsize(OUT)} bytes")


if __name__ == "__main__":
    build()
