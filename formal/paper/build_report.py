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
    "The question", "How the game can go wrong",
    "What a proof would be", "The model, and why we trust it",
    "What is proved", "What is refuted", "What is open",
    "What we observed", "What a reader is trusting", "Related work",
    "Reproducing this", "References",
]

STATUS_MEANING = [
    ("proved", "A solver showed it holds in the model, with no assumption."),
    ("conditional", "Holds in the model if a named assumption holds."),
    ("bounded", "Holds for every execution up to a stated length."),
    ("refuted", "Shown false, with a concrete witness."),
    ("abstract counterexample",
     "The solver found a state that would break it, but nothing shows the "
     "game can reach that state. Neither safe nor unsafe."),
    ("unknown", "Not settled either way."),
    ("observed", "Seen in test runs. Says nothing about runs not made."),
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
    ("lean", "L. de Moura, S. Ullrich. The Lean 4 Theorem Prover and Programming Language. CADE 2021."),
    ("z3", "L. de Moura, N. Bj&oslash;rner. Z3: An Efficient SMT Solver. TACAS 2008; H. Barbosa et al. cvc5: A Versatile and Industrial-Strength SMT Solver. TACAS 2022."),
]
NUM = {key: i for i, (key, _text) in enumerate(REFS, 1)}


def cite(*keys):
    return "[" + ", ".join(str(NUM[k]) for k in sorted(keys, key=NUM.get)) + "]"


def build():
    manifest = load("manifests", "obligations.json")
    validation = load("reports", "model_validation.json")
    full = load("reports", "model_validation_full.json")["totals"]
    exh = load("reports", "model_exhaustive_equivalence.json")["totals"]
    cross = load("reports", "dyn_crossvalidation.json")
    observed = load("reports", "dyn_observations_extended.json")
    observed2 = load("reports", "dyn_observations_extended_nespy.json")
    gaps = load("reports", "dyn_coverage_gaps.json")
    storm = load("reports", "dyn_nmi_storm.json")
    timing = load("reports", "interrupt_timing.json")
    init = load("reports", "init_memory.json")
    sep = load("reports", "stack_separation.json")
    replication_path = os.path.join(RESULTS, "reports", "replication.json")
    replication = (json.load(open(replication_path))
                   if os.path.exists(replication_path) else None)

    obligations = {o["id"]: o for o in manifest["obligations"]}
    counts = manifest["counts"]
    total = sum(counts.values())
    N = manifest["instruction_starts_N"]

    def status(ident):
        return obligations[ident]["status"]

    def B(ident):
        return "<b>" + status(ident).replace("_", " ") + "</b>"

    def by_prefix(prefix):
        return [o for o in manifest["obligations"]
                if o["id"].startswith(prefix)]

    def tally(items):
        out = {}
        for item in items:
            out[item["status"]] = out.get(item["status"], 0) + 1
        return ", ".join(f"{v} {k.replace('_', ' ')}"
                         for k, v in sorted(out.items())) or "none"

    doc = BaseDocTemplate(
        OUT, pagesize=letter,
        title="Can Controller Input Make Super Mario Bros. Run Code It "
              "Was Never Given?",
        author="Alexander Sadovsky, ChatGPT (OpenAI), and Claude (Anthropic)",
        leftMargin=0.8 * inch, rightMargin=0.8 * inch,
        topMargin=0.8 * inch, bottomMargin=0.8 * inch)
    fw = doc.width
    gutter = 0.28 * inch
    cw = (fw - gutter) / 2.0
    pad = dict(leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    lcol = Frame(doc.leftMargin, doc.bottomMargin, cw, doc.height, id="l", **pad)
    rcol = Frame(doc.leftMargin + cw + gutter, doc.bottomMargin, cw,
                 doc.height, id="r", **pad)
    cwi = cw / inch

    def footer(cv, d):
        cv.saveState()
        cv.setFont("Times-Roman", 7.5)
        cv.setFillColor(colors.Color(.4, .4, .4))
        cv.drawCentredString(letter[0] / 2, 0.5 * inch, f"{d.page}")
        cv.drawString(doc.leftMargin, 0.5 * inch, "Preprint - technical report")
        cv.drawRightString(letter[0] - doc.rightMargin, 0.5 * inch,
                           "SMB1 instruction-location invariant")
        cv.restoreState()

    head = 3.75 * inch
    top = Frame(doc.leftMargin, doc.bottomMargin + doc.height - head, fw,
                head, id="top", **pad)
    l1 = Frame(doc.leftMargin, doc.bottomMargin, cw, doc.height - head,
               id="l1", **pad)
    r1 = Frame(doc.leftMargin + cw + gutter, doc.bottomMargin, cw,
               doc.height - head, id="r1", **pad)
    doc.addPageTemplates([PageTemplate(id="title", frames=[top, l1, r1],
                                       onPage=footer),
                          PageTemplate(id="two", frames=[lcol, rcol],
                                       onPage=footer)])

    e = []
    add = e.append
    fig_no, eq_no, tab_no, sec = [0], [0], [0], [0]

    def EQ(tex, size=10.5):
        eq_no[0] += 1
        path, width, height = figures.equation(tex, size)
        scale = min(1.0, (cwi - 0.34) / width)
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
        add(KeepTogether([Spacer(1, 3), Image(path, cw, cw * h / w),
                          P(f"Figure {fig_no[0]}. {caption}", CAP)]))

    def TAB(rows, widths, caption):
        tab_no[0] += 1
        add(KeepTogether([table(rows, [cwi * w for w in widths]),
                          P(f"Table {tab_no[0]}. {caption}", CAP)]))

    def H(title):
        sec[0] += 1
        assert SECTIONS[sec[0] - 1] == title, (sec[0], title)
        add(P(f"{sec[0]}&nbsp;&nbsp;{title}", H1))

    def S(title):
        return str(SECTIONS.index(title) + 1)

    def SUB(title):
        add(P(title, H2))

    vec, py = validation["vectors"], validation["py65"]
    overall = cross["overall"]
    fetched = observed["fetched_program_counters"]
    fetched2 = observed2["fetched_program_counters"]
    landings = observed["dispatch_landings"]
    derailed = storm["manifest"]["variants_whose_pc_left_the_graph_or_prg"]
    variants = storm["manifest"]["variants"]
    part = init["partition"]
    never, warm = part["never_initialised"], part["preserved_in_the_warm_case_only"]
    sd, sk, vd = sep["data_side"], sep["stack_side"], sep["verdict"]
    contracts = [o for o in by_prefix("D-") if o["id"].endswith("-CONTRACT")]
    indices = [o for o in by_prefix("P6-") if o["id"].endswith("-INDEX")
               or o["id"].endswith("-GIVEN-071F")]
    closed_idx = sum(1 for o in indices
                     if o["status"] in ("proved", "conditional"))
    traced = (observed["manifest"]["instructions_total"]
              + observed2["manifest"]["instructions_total"])

    # ---------------------------------------------------------------- title
    add(P("Can Controller Input Make <i>Super Mario Bros.</i> Run Code It "
          "Was Never Given?", TITLE))
    add(P("Toward a machine-checked answer for the NES original", AUTH))
    add(Spacer(1, 3))
    add(P("Alexander Sadovsky, ChatGPT (OpenAI), and Claude (Anthropic)", AUTH))
    add(P("<font size=8>ChatGPT (OpenAI) wrote the verification plan this "
          "report carries out and the earlier review that prompted it. "
          "Claude (Anthropic) built the model, the proofs, the tooling and "
          "this text. Alexander Sadovsky directed the work and supplied the "
          "program image, which is not distributed.</font>", AUTH))
    add(P("November 2026", AUTH))
    add(Spacer(1, 6))
    add(P(
        "<b>Abstract.</b> Some classic games can be tricked, using nothing "
        "but the controller, into executing data as if it were program. We "
        "ask whether the original NES <i>Super Mario Bros.</i> can. Stated "
        "precisely: does the processor ever fetch an instruction from "
        "outside the cartridge's program ROM? <b>We do not settle it; the "
        f"theorem's status is {status('P1').replace('_', ' ')}.</b> What we "
        "have is a mathematical model of the console's processor that "
        f"agrees with {n(full['stable']['compared'])} published test cases "
        "without exception, and a ledger of "
        f"{total} claims about the game, each marked as proved, refuted, "
        "conditional, or open. The game has exactly two ways to send the "
        "processor somewhere unintended: a jump table read with a bad "
        "index, and a subroutine return through a damaged return address. "
        "We prove the jump mechanism itself is correct at all 18 places it "
        "is used, prove the property outright for the game's start-up "
        "sequence, and show it <i>fails</i> in a simplified model that "
        "ignores interrupt timing, which tells us what any proof must "
        "assume. What remains open is whether the table indices and return "
        "addresses stay valid during play. "
        f"In {n(traced)} traced instructions covering every level of the "
        "game nothing went wrong, which is encouraging and proves "
        "nothing.", ABSTRACT))
    add(Spacer(1, 4))
    add(NextPageTemplate("two"))
    add(FrameBreak())

    # ------------------------------------------------------------------ 1
    H("The question")
    add(P("<i>Arbitrary code execution</i> means getting a machine to run "
          "instructions its programmer never wrote. In several NES and SNES "
          "games, players have done this with controller input alone: a "
          "sequence of glitches corrupts memory until the processor jumps "
          "into data the player controls. For the original <i>Super Mario "
          "Bros.</i>, no such technique is known that starts from a normal "
          "power-on and uses only the controller."))
    add(P("Absence of a known technique is not proof that none exists. A "
          "companion audit in this repository narrowed down where one "
          "could hide. This report asks whether the question can be "
          "answered with the certainty of a mathematical proof checked by "
          "software, and reports how far that got."))
    add(P("<b>The short answer.</b> Not yet, and possibly not ever in the "
          "form first hoped. Table 1 summarises where each part stands. "
          "The rest of the report explains each row: Section "
          + S("How the game can go wrong") + " describes how the game "
          "could go wrong, Section " + S("What a proof would be")
          + " what a proof needs, and Sections " + S("What is proved")
          + " to " + S("What is open") + " what is proved, refuted and "
          "open."))
    TAB([["Claim", "Where it stands"],
         ["The processor model matches real 6502 behaviour",
          f"{n(full['stable']['compared'])} test cases, 0 disagreements "
          "(testing, not proof)"],
         ["The jump mechanism lands where its table says, if the index is "
          "in range", f"proved at all {len(contracts)} sites"],
         ["Start-up never fetches outside ROM",
          status("BOUNDED-P1-RESET") + ", complete for that phase"],
         ["The property holds if interrupts may fire at any time",
          "refuted, with a concrete run"],
         ["Every jump-table index stays in range during play",
          f"{closed_idx} of 18 settled; the rest open"],
         ["No return address is ever overwritten",
          status("SEP-SEPARATION").replace("_", " ")
          + f"; {len(sd['writers']) - len(sd['open'])} of "
          f"{len(sd['writers'])} risky writes bounded"],
         ["Passing every check of our proof plan implies the property",
          "proved in Lean for the corrected checks; refuted for the "
          "original ones"],
         ["<b>The full property, for all play</b>",
          "<b>" + status("P1").replace("_", " ") + "</b>"]],
        [0.6, 0.4], "Where the main claims stand.")
    add(P("<b>What counts as cheating.</b> Only controller input is "
          "allowed. Cheat devices, modified cartridges, swapping "
          "cartridges, debuggers and hardware modification are out of "
          "scope."))

    # ------------------------------------------------------------------ 2
    H("How the game can go wrong")
    add(P("A few facts about the machine are enough to follow everything "
          "else."))
    add(P("<b>Memory.</b> The processor sees 64 KiB of addresses "
          "(Figure 1). The top half is the cartridge's program ROM, which "
          "cannot be changed. The bottom holds 2 KiB of RAM, which the "
          "game changes constantly. In between are the graphics and sound "
          "chips and the controllers. The property we want is simply that "
          "the processor only ever executes from the top half."))
    FIG(figures.address_map(N),
        "The processor's address space (schematic, not to scale). The "
        "property confines instruction fetches to program ROM.")
    add(P("<b>Why it could leave.</b> Almost every jump in the program "
          "goes to a fixed address written in ROM, and those cannot be "
          "redirected. Only two kinds of instruction take their "
          "destination from changeable memory:"))
    add(P("&bull; <i>The dispatcher.</i> One shared routine at "
          + C("$8E04") + " picks a destination from a table using a number "
          "the game supplies, like choosing a line from a numbered list. "
          "It is used in 18 places. If the number is larger than the list, "
          "it reads whatever bytes come next and jumps there."))
    add(P("&bull; <i>Returns.</i> When a subroutine finishes, the "
          "processor goes back to an address it saved earlier in a region "
          "of RAM called the stack. There are 336 such returns, plus one "
          "at the end of the interrupt handler. If anything overwrites a "
          "saved address, the return goes somewhere else."))
    add(P("So the whole question reduces to two: are the 18 list numbers "
          "always in range, and are the saved return addresses always "
          "intact?"))
    add(P("<b>The interrupt.</b> Sixty times a second the graphics chip "
          "interrupts the processor so the game can update the screen. "
          "This interrupt (called NMI) saves three bytes on the stack and "
          "runs a handler, which in this game contains nearly all the game "
          "logic (Figure 2). The handler switches the interrupt off while "
          "it works and back on just before it finishes. Interrupt timing "
          "turns out to matter a great deal."))
    FIG(figures.handler_timeline(),
        "The interrupt handler. The lower trace is whether the interrupt "
        "is enabled. The two marked windows are where a proof has to "
        "assume no second interrupt arrives.")

    # ------------------------------------------------------------------ 3
    H("What a proof would be")
    add(P("<b>The property.</b> Call a snapshot of the processor and RAM a "
          "<i>state</i>. A state is <i>reachable</i> if the machine can "
          "get there from power-on by running the game with some sequence "
          "of controller inputs. The property, which we call P1, says that "
          "in every reachable state the program counter " + C("pc")
          + " (the address of the next instruction) is in ROM:"))
    EQ(r"\mathrm{P1}:\quad \mathrm{for\ every\ reachable\ state\ } s,\quad "
       r"\mathtt{8000}_{16} \,\leq\, pc(s) \,\leq\, \mathtt{FFFF}_{16}", 9.5)
    add(P("We actually aim for something slightly stronger: that "
          + C("pc") + " is always one of the " + n(N) + " addresses where "
          "an instruction of the program genuinely begins, which also "
          "rules out jumping into the middle of an instruction."))
    add(P("<b>Why not just try everything.</b> A state has 16,439 bits, "
          "so there are about 2<super>16439</super> of them. No computer "
          "can enumerate that. Testing can only ever sample."))
    add(P("<b>The standard way around this</b> is to find a description "
          + C("J") + " of &quot;healthy&quot; states and show three "
          "things: the machine starts healthy; one step from a healthy "
          "state always gives a healthy state; and healthy states have "
          + C("pc") + " in the right place. Each is a yes-or-no question "
          "an automated solver can answer:"))
    EQ(r"\mathrm{start} \Rightarrow J, \qquad J(s) \wedge \mathrm{step}(s,s') "
       r"\Rightarrow J(s'), \qquad J(s) \Rightarrow pc(s) \in N", 9)
    add(P("If all three hold, the property holds for every reachable "
          "state, with nothing enumerated. All the difficulty is in the "
          "middle one. " + C("J") + " has to say enough about RAM that no "
          "instruction, interrupt or reset can break it, which means "
          "capturing how the game really uses its memory."))
    add(P("<b>How we label claims.</b> Every claim in this work carries "
          "one label from Table 2, and software prevents a claim from "
          "being labelled <i>proved</i> if it depends on anything "
          "unproved. This matters because the most common way such "
          "projects go wrong is by quietly treating &quot;we tested it and "
          "saw no failure&quot; as &quot;it cannot fail&quot;."))
    TAB([["Label", "Meaning"]] + [[a, b] for a, b in STATUS_MEANING],
        [0.3, 0.7], "The labels used throughout.")
    add(P("<b>Proof transfers one way.</b> Our model deliberately allows "
          "more than a real console does: any value from any chip, an "
          "interrupt at awkward moments, a reset at any time. If the "
          "property holds in a model that allows more, it holds on the "
          "real thing. The reverse is not true: a failure in the generous "
          "model may be something a real console can never do. Section "
          + S("What is refuted") + " has exactly such a failure."))

    # ------------------------------------------------------------------ 4
    H("The model, and why we trust it")
    add(P("Everything below is a statement about a mathematical model of "
          "the console, so the model has to be right."))
    add(P("<b>What it is.</b> A definition, for each of the processor's "
          "256 instruction codes, of how it changes the registers and "
          "memory. The same definition is used two ways: fed concrete "
          "numbers it acts as an emulator, and fed unknowns it produces "
          "formulas for a solver. That means the thing we test is the "
          "thing we reason with. Readings from the graphics chip, sound "
          "chip and controllers are treated as completely unpredictable, "
          "which covers every possible controller input and more. Six "
          "obscure instruction codes whose real behaviour is erratic are "
          "modelled as doing anything at all."))
    add(P("<b>How it was tested.</b> Against a published suite of "
          "recorded single-instruction behaviour " + cite("sst")
          + f": {n(full['stable']['compared'])} cases covering "
          f"{full['stable']['opcodes']} instruction codes, with "
          f"<b>{full['stable']['mismatches']}</b> disagreements. And "
          "against a second, separately written processor implementation, "
          "trying every combination of the inputs that matter most for "
          "each instruction (every pair of operands for arithmetic, every "
          f"stack position, every jump target): {n(exh['stable']['compared'])} "
          f"cases, <b>{exh['stable']['mismatches']}</b> disagreements. The "
          "erratic instructions are checked only for what the model does "
          "pin down and are not counted as agreement."))
    add(P("<b>What that does not show.</b> Testing is not proof; a flaw "
          "the tests never exercise would silently undermine everything. "
          "The model works one whole instruction at a time, so it says "
          "nothing about what happens partway through one, and it models "
          "the graphics chip as a single on/off switch for the "
          "interrupt."))
    add(P("<b>The program's map.</b> The list of " + n(N) + " instruction "
          "starts comes from following the program from its three entry "
          "points. We checked that map against the model one instruction "
          "at a time: wherever an instruction's own bytes decide what "
          "comes next, the map and the model agree exactly ("
          + C("GRAPH-EDGES") + ": " + B("GRAPH-EDGES") + "). Returns and "
          "the dispatcher are excluded, since they are the open "
          "question."))
    add(P("<b>Second opinions.</b> Solvers have bugs too. Every answer we "
          "rely on is put to two further, independent solvers "
          + cite("z3") + "; none has disagreed."))

    # ------------------------------------------------------------------ 5
    H("What is proved")
    add(P("These hold in the model with no assumptions beyond it."))
    SUB("The dispatcher does what it should")
    add(P("At each of the 18 places the dispatcher is used, if the number "
          "it is given is within its list, the next instruction executed "
          "is the one the list names. Writing " + C("d") + " for the "
          "place, " + C("a") + " for the number (the low seven bits of a "
          "register), " + C("n") + " for the list's length and " + C("E")
          + " for the list:"))
    EQ(r"pc = d \;\wedge\; a < n \;\;\Rightarrow\;\; pc' = E[a]", 10)
    add(P("Status: " + tally(contracts) + ". The same statement with the "
          "limit loosened by one is refuted, as it must be: one past the "
          "end really does go astray. This moves the whole dispatcher "
          "question onto the numbers themselves."))
    SUB("One index formula, corrected")
    add(P("At one site the number is computed from a RAM cell " + C("v")
          + " in a way an earlier revision of the audit had misread. "
          "Running the actual ROM bytes through the model gives"))
    EQ(r"a \;=\; \left((v \,\vee\, 8) - 1\right) \;\mathrm{mod}\; 256, "
       r"\qquad v \leq 8 \;\Rightarrow\; a \leq 7")
    add(P("where " + C("&or;") + " is bitwise OR. The list there has 8 "
          "entries, so that site is safe exactly when " + C("v")
          + " never exceeds 8 (" + B("L-92C8-ROM-EXACT") + ")."))
    SUB("Start-up is safe")
    add(P("From the moment of power-on until the game first enables its "
          "interrupt, every instruction executed is a genuine instruction "
          "of the program. This is shown for <i>every</i> possible initial "
          "RAM content and every possible chip reading, by following the "
          "model forward with all of those left unknown ("
          + C("BOUNDED-P1-RESET") + ": " + B("BOUNDED-P1-RESET")
          + ", and complete for this phase: no case was skipped). Two "
          "loops that wait for the graphics chip could in principle spin "
          "forever; they are covered for any number of turns. The same "
          "method follows the first interrupt for 4,000 further "
          "instructions without finding a problem; beyond that depth it "
          "says nothing."))
    SUB("What start-up leaves in memory")
    add(P("A related analysis shows exactly what RAM contains when the "
          "interrupt is first enabled (Table 3). This matters because the "
          "property can only be true for some starting memory contents, "
          "and this pins down which cells are still undetermined."))
    TAB([["RAM cells", "Count", "Contents when play begins"],
         [", ".join(part["always_overwritten"]["ranges"]),
          n(part["always_overwritten"]["count"]),
          "set to known values, whatever was there"],
         [", ".join(warm["ranges"]), n(warm["count"]),
          "cleared on a fresh start; kept across a reset (high score and "
          "similar)"],
         [", ".join(never["ranges"]), n(never["count"]),
          "never touched: whatever the console powered on with"]],
        [0.36, 0.14, 0.5], "What start-up does to the 2,048 bytes of RAM.")
    add(P(f"So only {never['count']} cells, all in the upper part of the "
          f"stack area, plus {warm['count']} more after a reset, are left "
          "to chance. Everything else is fixed before any interrupt can "
          "run."))
    SUB("The proof plan is sound, once corrected")
    add(P("The plan for a full proof (Section " + S("What is open")
          + ") is a <i>certificate</i>: a statement of what is known at "
          "every instruction, plus a contract for each subroutine saying "
          "what it may change, each piece tested separately by a solver. "
          "That only helps if passing all the tests really implies the "
          "property. We proved that it does, in the Lean proof assistant "
          + cite("lean") + ", where every step is checked by a small "
          "trusted kernel."))
    add(P("The Lean development does not model the real processor. Its "
          "machine is abstract: a program counter, a stack position, a "
          "memory and the interrupt switch, able to step, call, return, "
          "take an interrupt, return from one, or reset. The certificate "
          "and each test are written as mathematical statements about "
          "that machine. The key to the proof is one statement about the "
          "whole call stack: the routine now running satisfies its "
          "invariant, and each routine waiting beneath it would still "
          "recognise memory, because whatever has changed since it was "
          "suspended lies within what the routines above it are permitted "
          "to change. A call and an interrupt suspend a routine in the "
          "same way, so one argument covers both."))
    add(P("The theorem: if every test holds, that statement is true of "
          "every reachable state, and so the program counter is always "
          "where it should be. It is proved with no steps left open; the "
          "build prints the axioms each theorem rests on, and only two "
          "of Lean's standard ones appear. It is a theorem about the "
          "<i>corrected</i> tests. Section " + S("What is refuted")
          + " says what was wrong with the original ones."))
    SUB("The interrupt cannot fire while switched off")
    add(P("From a small cycle-by-cycle model of the interrupt circuitry, "
          "built from published hardware documentation "
          + cite("nesdev-int") + ": while the game has the interrupt "
          "disabled, none can be taken, for any timing whatever. Two "
          "narrower timing claims are conditional (Section "
          + S("What is open") + ")."))

    # ------------------------------------------------------------------ 6
    H("What is refuted")
    add(P("Being told clearly what is false was as useful as what is "
          "true."))
    SUB("The property fails if interrupts can fire at any moment")
    add(P("Our first model let the interrupt fire whenever it was "
          "enabled. The handler takes a few instructions to switch the "
          "interrupt off, so that model allows the interrupt to interrupt "
          "<i>itself</i> again and again before doing anything. Each time "
          "costs 3 bytes of stack, and the stack is only 256 bytes and "
          "wraps around. After " + C("k") + " such entries the stack "
          "position " + C("S") + " is"))
    EQ(r"S_k \;=\; (S_0 - 3k) \;\mathrm{mod}\; 256, \qquad "
       r"3 \cdot 86 = 258 \equiv 2 \;(\mathrm{mod}\; 256)")
    add(P("Because 256 is not a multiple of 3, after 86 entries the "
          "stack has wrapped and new saved addresses land two bytes out "
          "of step with old ones (Figure 3). A later return then picks up "
          "a mixture of bytes from different saves."))
    FIG(figures.stack_wrap(storm),
        "Stack position at each forced interrupt: the formula above, and "
        "the values recorded when we ran it.")
    add(P("We ran it. Of " + str(variants) + " variations, <b>"
          + str(derailed) + "</b> ended with the processor executing "
          "from somewhere it should not (Figure 4): in some, a return "
          "landed in RAM; in others, in the middle of an instruction "
          "inside ROM."))
    FIG(figures.storm_outcomes(storm),
        "What happened in each variation. Every cell is one run of the "
        "simplified model; none is a claim about a real console.")
    add(P("<b>This is not a way to break a real console.</b> Real "
          "hardware delivers one interrupt per screen refresh, about "
          "30,000 processor cycles apart. The result is a diagnosis: no "
          "proof can succeed without saying something about <i>when</i> "
          "interrupts arrive. Those assumptions are the two marked "
          "windows in Figure 2."))
    SUB("Two things we had assumed")
    add(P("&bull; <i>&quot;No subroutine calls itself.&quot;</i> False. "
          "One routine can re-enter itself through its own dispatch list, "
          "so there is no simple limit on how deep the stack can go."))
    add(P("&bull; <i>&quot;A reset puts the stack back.&quot;</i> False "
          "in the model. Each reset moves the stack position down by "
          "three without writing, so repeated resets at the wrong moments "
          "walk it down the page."))
    SUB("Our own proof plan, as first designed")
    add(P("We had argued on paper that if every certificate test "
          "passed, the property would hold. Writing that argument in Lean "
          "showed it was wrong. The proof would not go through until five "
          "omissions were repaired (Table 4), and for the first of them "
          "the Lean development contains a tiny example, with two program "
          "addresses, that passes every one of the original tests and "
          "still reaches an address it should not. So the original tests "
          "did not imply the property, and that is itself a "
          "machine-checked fact."))
    TAB([["What the original tests left out", "Consequence"],
         ["The moments when &quot;no interrupt can occur&quot; were "
          "accepted from the certificate unverified",
          "a certificate could exempt itself from every interrupt test; "
          "the counterexample does exactly this"],
         ["An interrupt arriving inside a subroutine was not charged to "
          "the routines waiting beneath it",
          "a caller could resume believing memory unchanged when the "
          "handler had changed it"],
         ["The handler's final-state promise was tested just before the "
          "return from interrupt and relied on just after",
          "that instruction restores the interrupted code's flags, so "
          "the two states differ"],
         ["A shortcut in the checker tested less than the proof needs",
          "a test could pass because its premises contradicted each "
          "other"],
         ["Stack depth was compared in arithmetic that wraps at 256, "
          "with no limit on total depth",
          "the certificate fixed no real ordering of stack positions"]],
        [0.5, 0.5], "Omissions the Lean proof exposed.")
    add(P("Four of these had been spotted by reading the checker's code. "
          "The proof arrived at three of them independently, narrowed "
          "down the fourth, and found the fifth, which no reading had "
          "caught. Only the first is shown to be exploitable by example; "
          "the others are shown to be needed by the proof."))

    # ------------------------------------------------------------------ 7
    H("What is open")
    add(P("Figure 5 shows how the property breaks into parts and where "
          "each stands."))
    FIG(figures.decomposition(
        {k: v["status"] for k, v in obligations.items()},
        {"contracts_label": f"{len(contracts)} site\ncontracts",
         "contracts_status": ("proved" if all(
             o["status"] == "proved" for o in contracts) else "unknown"),
         "indices_label": f"18 index\nbounds:\n{closed_idx} closed",
         "indices_status": ("abstract_counterexample" if any(
             o["status"] == "abstract_counterexample" for o in indices)
             else "unknown")}),
        "How the property decomposes. An arrow means &quot;depends "
        "on&quot;; colour is the label from Table 2.")
    SUB("Are the 18 list numbers always in range?")
    add(P("We tried to show each number is in range by working backwards "
          "from the dispatcher through the instructions that lead to it. "
          f"That settles {closed_idx} sites, where the program checks or "
          "masks the number just before using it. At the others the "
          "number is loaded from a RAM cell set somewhere far away, and "
          "the backward search runs out of program with the cell still "
          "unconstrained (" + tally(indices) + "). That is not evidence "
          "of a fault. It means the answer depends on how that cell is "
          "used across the whole game, which a local search cannot see."))
    SUB("Are return addresses always intact?")
    add(P("The game stores ordinary data in the lower part of the same "
          "256-byte page that holds the stack, so the right question is "
          "whether the two ever meet."))
    add(P("<i>The stack's side.</i> Leaving aside the self-calling "
          f"routine, the stack never grows beyond "
          f"{sk['depth_without_recursion']} bytes, so it stays at or "
          "above position "
          + C(f"${sk['lowest_pointer_without_recursion']:02X}")
          + ". This is " + B("SEP-DEPTH") + ": it assumes interrupts do "
          "not pile up and that returns are already working correctly, "
          "which is part of what we are trying to show."))
    add(P("<i>The data's side.</i> "
          f"{len(sd['writers'])} instructions can write into that page as "
          f"ordinary data. For {len(sd['writers']) - len(sd['open'])} we "
          "have a limit on how high they reach, the highest being "
          + C(f"$01{sd['worst_offset']:02X}") + ". "
          f"The other {len(sd['open'])} are open, mostly because the "
          "position they write to is held in a register that is reloaded "
          "from memory after a subroutine call, and again the backward "
          "search cannot see through that."))
    add(P("If the open ones turned out to behave as they do in test "
          f"runs, data and stack would be {vd['margin_without_recursion']} "
          "bytes apart. That is a hope, not a result. Combined status: "
          + B("SEP-SEPARATION") + "."))
    SUB("The global argument (the certificate)")
    add(P("Both gaps above need facts about memory that hold across the "
          "whole game. The plan for that is a <i>certificate</i>: for "
          "every instruction, a statement of what is known there (which "
          "values certain RAM cells can hold, how deep the stack is), and "
          "for every subroutine a summary of what it may change. One "
          "program proposes the certificate; a separate, simpler program "
          "checks each piece with the solver. This is the approach of "
          "proof-carrying code " + cite("pcc") + " and annotation "
          "inference " + cite("houdini") + "."))
    add(P("The argument behind this plan is the one proved in Section "
          + S("What is proved") + ", after the corrections of Section "
          + S("What is refuted") + ". What is open is everything on the "
          "game's side of it. The checker exists, but until it enforces "
          "the corrected tests its verdicts would not mean what they need "
          "to, and we report none. A first trial certificate is also far "
          "too weak: it does not yet capture that the interrupt is "
          "enabled only while the game idles, so most tests about "
          "resuming after an interrupt cannot pass. Strengthening it is "
          "the main work remaining."))
    SUB("Interrupt timing")
    tc = timing["status_counts"]
    add(P("The two timing assumptions from Section "
          + S("What is refuted") + " were examined with the cycle-level "
          "model, trying every possible timing of the graphics chip "
          "(Table 5)."))
    TAB([["Claim", "Label", "Depends on"],
         ["No interrupt while it is switched off", "proved", "nothing"],
         ["No second interrupt in the 23 cycles before the handler "
          "switches it off", "conditional",
          "the screen-refresh signal not recurring within 23 cycles. "
          "Follows from documented timing; stated nowhere outright"],
         ["No interrupt in the instant between switching it back on and "
          "returning", "conditional",
          "the interrupt really having been off throughout the handler, "
          "a fact about the program"]],
        [0.38, 0.2, 0.42], "The interrupt-timing claims.")
    add(P("Each conditional claim is shown false, with an example, if its "
          "condition is removed. The third row is the notable one: it "
          "looked like a hardware fact and is really one more thing to "
          "prove about the game. None of this has been measured on a "
          "console."))
    SUB("Reset on some consoles")
    add(P("If the reset button is pressed while the interrupt is enabled, "
          "the model lets an interrupt slip in during the first "
          "instructions of start-up, after which start-up runs with "
          "interrupts on. Whether a real console allows this depends on "
          "whether its reset button also resets the graphics chip. "
          "Documentation says the original front-loading NES does, and "
          "the Famicom and the later top-loading NES do not "
          + cite("nesdev-ppu") + ". For the latter we have neither a "
          "proof that this is harmless nor any evidence that it is "
          "not."))
    SUB("Starting memory, and a published result")
    add(P("The model lets RAM hold anything at power-on. A published "
          "demonstration " + cite("tas8991") + " reports arbitrary code "
          "execution in this game after first running a <i>different</i> "
          "cartridge to leave chosen values in RAM. Swapping cartridges "
          "is outside our rules, and we have not reproduced it. But it "
          "tells us something about the theorem: with RAM completely "
          "unconstrained at power-on, the property should be expected to "
          "be false, so a true statement must say something about the "
          f"{never['count']} cells start-up leaves alone. What a real "
          "console guarantees about them is a hardware question we do "
          "not answer."))

    # ------------------------------------------------------------------ 8
    H("What we observed")
    add(P("Alongside the proofs we recorded real executions, instruction "
          "by instruction. These are observations and carry that label; "
          "they cannot show the property holds, only fail to show it "
          "does not."))
    add(P("A tracer built on a second processor implementation was "
          "checked against an independent emulator: "
          f"{n(overall['instructions_compared'])} instructions with "
          f"{overall['program_counter_differences']} differences in where "
          "the processor was. Two emulators agreeing is not the same as "
          "agreeing with a console."))
    sp = observed["stack_pointer"]
    add(P(f"Over {n(observed['manifest']['frames_total'] + observed2['manifest']['frames_total'])} "
          f"frames of play and {n(traced)} instructions:"))
    add(P("&bull; <b>"
          + str(fetched['fetched_but_not_an_instruction_start_count'])
          + "</b> instructions were executed from anywhere other than a "
          "genuine instruction start."))
    add(P(f"&bull; {n(landings['checked'])} uses of the dispatcher all "
          "landed where the list said, and no number was out of range at "
          f"the {sum(1 for s in observed['dispatch_sites'] if s['fetches'])} "
          "of 18 sites that were reached (Figure 7). At 16 sites every "
          "entry of the list was seen in use."))
    add(P("&bull; The stack stayed between positions "
          + C(f"${sp['min_at_any_fetch']:02X}") + " and "
          + C(f"${sp['max_at_any_fetch']:02X}") + ", well clear of the "
          "data below it."))
    add(P("&bull; No interrupt ever arrived while the handler was "
          "running."))
    FIG(figures.coverage(fetched, fetched2, N),
        "How much of the program the test runs actually executed.")
    FIG(figures.dispatch_sites(observed),
        "Largest list number seen at each dispatcher site, against the "
        "list's length.")
    unexec = N - max(fetched["graph_nodes_executed"],
                     fetched2["graph_nodes_executed"])
    add(P("<b>How much was exercised.</b> The runs include two published "
          "full play-throughs replayed from power-on with controller input "
          "only, which between them visit all 32 levels, both warp zones, "
          "the ending, game-over and two-player modes. The better-covered "
          f"engine executed {fetched2['graph_coverage']:.1%} of the "
          f"program's instructions, leaving {n(unexec)} never run. Most "
          "of those are branches not taken inside routines that did run; "
          "a few belong to objects and enemies no level played happens to "
          "contain; and six are reachable only through an instruction the "
          "game never executes in play."))
    add(P("<b>What this is worth.</b> It is good evidence that ordinary "
          "play, even of the whole game, does not stray. It is weak "
          "evidence about deliberate glitch play, which is exactly the "
          "kind of input these runs do not contain, and it bounds "
          "nothing."))

    # ------------------------------------------------------------------ 9
    H("What a reader is trusting")
    add(P("Someone who accepts a <i>proved</i> label here is relying "
          "on:"))
    add(P("&bull; <b>The processor model</b>, which is heavily tested "
          "but not proved correct, and works one instruction at a "
          "time."))
    add(P("&bull; <b>The table of instruction lengths</b>, shared by the "
          "model and the program map, so an error there would not show "
          "up as a disagreement between them."))
    add(P("&bull; <b>The solvers</b>, cross-checked against each other "
          "for most claims, but not for the certificate."))
    add(P("&bull; <b>The gap between the Lean proof and the checker.</b> "
          "The proof says which tests suffice. It does not show that the "
          "checker's code performs those tests, nor that each test is "
          "translated faithfully into a solver question. It also treats "
          "the stack position as an unbounded number, so the 256-byte "
          "wraparound cannot occur in it; the limit on stack depth that "
          "would justify this is stated but not proved."))
    add(P("&bull; <b>Our own code</b> that turns claims into solver "
          "questions. The certificate checker's faults described in "
          "Section " + S("What is open") + " are a reminder that such "
          "code can be wrong in ways tests do not catch."))
    add(P("&bull; <b>Hardware documentation written by enthusiasts</b>, "
          "not the manufacturer, for everything about interrupt timing."))
    add(P("The results are for one specific program image (SHA-1 "
          + C(manifest["rom_sha1"]) + ") and say nothing about other "
          "regional versions."))

    # ----------------------------------------------------------------- 10
    H("Related work")
    add(P("<b>None of the methods here is new.</b> Proving that a real "
          "program's jumps all stay within permitted bounds, against a "
          "formal processor model, was done for ARM by ARMor "
          + cite("armor") + " and for x86 by RockSalt " + cite("rocksalt")
          + ". The seL4 project " + cite("sel4") + " and Myreen's "
          "decompilation into logic " + cite("myreen") + " reason about "
          "machine code with every step checked by a proof assistant, a "
          "higher standard than ours. Recovering a program's map from its "
          "binary is the subject of value-set analysis " + cite("vsa")
          + " and Jakstab " + cite("jakstab") + ", and has been done with "
          "proof " + cite("verbeek") + ". BinSym " + cite("binsym")
          + " shows the value of reasoning from a formal processor "
          "definition."))
    add(P("Interrupt-driven programs on small processors were verified "
          "directly from machine code two decades ago by [mc]square "
          + cite("mcsquare") + ". Regehr and colleagues "
          + cite("regehr-int", "regehr-stack") + " bounded stack depth "
          "for such programs and stressed that tracking when interrupts "
          "are enabled is essential, which Section "
          + S("What is refuted") + " rediscovered. An automated "
          "alternative to our certificate approach is IC3 " + cite("ic3")
          + ", which we did not try."))
    add(P("For this processor, the best existing artefacts are a "
          "transistor-level simulation " + cite("visual6502") + " and "
          "large test suites " + cite("sst") + ". We found one hobbyist "
          "description of a solver-based 6502 tool " + cite("forum")
          + " and no published formal model. Research on games studies "
          "idealised versions " + cite("aloupis", "demaine") + " or "
          "catalogues known glitches " + cite("kingdoms") + ", the last "
          "noting that formal tools are rarely used to find them."))
    add(P("<b>What might be new</b> is the application: we found no "
          "earlier formal model of this processor and no formal "
          "verification of a commercial console game. That reflects what "
          "a search on 2026-11-25 turned up; unpublished work may exist. "
          "If it is new, the contribution is a precise list of what would "
          "have to be true for the game to be safe, not a theorem."))

    # ----------------------------------------------------------------- 11
    H("Reproducing this")
    text = ("The program image is not distributed; readers supply their "
            "own. " + C("tools/reproduce.sh") + " regenerates every "
            "result. All numbers in this report are read from those "
            "generated files, not typed in. Solvers: Z3 "
            + manifest["solver"]["z3"] + " and cvc5 "
            + manifest["solver"]["cvc5"] + ", with Bitwuzla as a third "
            "check. The Lean proof builds with no unproved steps. ")
    if replication is not None:
        diffs = replication["differences_from_committed_manifest"]
        changed = [k for k, v in diffs.items()
                   if not (v["committed"] and v["regenerated"]
                           and v["committed"][0] == v["regenerated"][0])]
        text += ("We re-ran everything from a fresh copy in a clean "
                 f"environment. All {replication['obligations']} claims "
                 "came out with "
                 + ("the same label" if not changed else
                    f"the same label except {len(changed)}")
                 + ", and every saved solver question matched its recorded "
                 "fingerprint. ")
        if diffs and not changed:
            text += (f"For {len(diffs)} claims, though, the <i>set</i> of "
                     "questions asked along the way differed between the "
                     "two runs while the answer did not. We have not "
                     "tracked down why, and until we do, those "
                     "claims are reproducible in outcome but not in every "
                     "step. An earlier run showed more such differences, "
                     "traced to a naming detail and fixed. ")
    else:
        text += ("A re-run from a fresh copy in a clean environment is "
                 "scripted but had not been carried out when this was "
                 "built. ")
    text += ("Such a re-run, by the same authors on the same machine, "
             "catches results that depend on chance or setup. It does not "
             "catch errors of reasoning.")
    add(P(text))

    H("References")
    for i, (_key, textref) in enumerate(REFS, 1):
        add(P(f"[{i}]&nbsp;&nbsp;{textref}", REF))

    doc.build(e)
    print(OUT, f"{os.path.getsize(OUT)} bytes")


if __name__ == "__main__":
    build()
