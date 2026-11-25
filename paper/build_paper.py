"""Build the academic-paper-style PDF from the audit findings (reportlab, no LaTeX).

    python3 paper/build_paper.py   ->  paper/smb1_ace_audit.pdf

Self-contained: the prose/tables below are the paper. Figures of ROM data are
reproducible with ../trace.py and ../audit.py.
"""
import os

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
    Preformatted, CondPageBreak, FrameBreak, NextPageTemplate,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smb1_ace_audit.pdf")

# ---------------------------------------------------------------- styles
ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=ss["BodyText"], fontName="Times-Roman",
                      fontSize=9.3, leading=12.2, alignment=TA_JUSTIFY, spaceAfter=5)
H1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                    fontSize=11, leading=13, spaceBefore=10, spaceAfter=4, textColor=colors.black)
H2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-BoldOblique",
                    fontSize=9.6, leading=12, spaceBefore=6, spaceAfter=2, textColor=colors.black)
TITLE = ParagraphStyle("title", parent=ss["Title"], fontName="Times-Bold",
                       fontSize=17, leading=20, alignment=TA_CENTER, spaceAfter=4)
AUTH = ParagraphStyle("auth", parent=BODY, alignment=TA_CENTER, fontSize=10, leading=13, spaceAfter=1)
ABSTRACT = ParagraphStyle("abs", parent=BODY, fontName="Times-Roman", fontSize=9, leading=11.5,
                          leftIndent=22, rightIndent=22, spaceBefore=4, spaceAfter=4)
CODE = ParagraphStyle("code", parent=ss["Code"], fontName="Courier", fontSize=7.1, leading=8.3,
                      leftIndent=6, backColor=colors.Color(.95, .95, .95), borderPadding=4,
                      spaceBefore=3, spaceAfter=5, textColor=colors.black)
CAP = ParagraphStyle("cap", parent=BODY, fontSize=8, leading=10, alignment=TA_CENTER,
                     spaceBefore=2, spaceAfter=7, textColor=colors.Color(.2, .2, .2))
REF = ParagraphStyle("ref", parent=BODY, fontSize=8.3, leading=10.5, leftIndent=14,
                     firstLineIndent=-14, spaceAfter=2)


def P(t, s=BODY):
    return Paragraph(t, s)


# ---------------------------------------------------------------- document
def build():
    doc = BaseDocTemplate(OUT, pagesize=letter, title="Static Audit of Controller-Only ACE in Super Mario Bros.",
                          author="Alexander Sadovsky, ChatGPT (OpenAI), and Claude (Anthropic)",
                          leftMargin=0.8 * inch, rightMargin=0.8 * inch,
                          topMargin=0.8 * inch, bottomMargin=0.8 * inch)
    fw = doc.width
    gutter = 0.28 * inch
    cw = (fw - gutter) / 2.0
    # full-width frame for the title block
    full = Frame(doc.leftMargin, doc.bottomMargin, fw, doc.height, id="full",
                 leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    # two columns for the body
    lcol = Frame(doc.leftMargin, doc.bottomMargin, cw, doc.height, id="l",
                 leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    rcol = Frame(doc.leftMargin + cw + gutter, doc.bottomMargin, cw, doc.height, id="r",
                 leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    def footer(cv, d):
        cv.saveState()
        cv.setFont("Times-Roman", 7.5)
        cv.setFillColor(colors.Color(.4, .4, .4))
        cv.drawCentredString(letter[0] / 2, 0.5 * inch, f"{d.page}")
        cv.drawString(doc.leftMargin, 0.5 * inch, "Preprint - technical report")
        cv.drawRightString(letter[0] - doc.rightMargin, 0.5 * inch, "Super Mario Bros. ACE audit")
        cv.restoreState()

    doc.addPageTemplates([
        PageTemplate(id="title", frames=[full], onPage=footer),
        PageTemplate(id="two", frames=[lcol, rcol], onPage=footer),
    ])

    e = []
    # ---- title block (full width) ----
    e.append(P("A Static Audit of Controller-Only Arbitrary Code Execution in <i>Super Mario Bros.</i> (NES)", TITLE))
    e.append(P("Alexander Sadovsky, ChatGPT (OpenAI), and Claude (Anthropic)", AUTH))
    e.append(P("<font size=8>ChatGPT (OpenAI) contributed the methodological review, exact 6502 semantics and ROM validation, "
               "and the remediation review of the first revision that identified the "
               "<font face='Courier'>$92C8</font> error and the conflation of observed bounds with "
               "proven exclusions; Claude (Anthropic) contributed the control-flow audit, emulator "
               "experiments, the derived dispatch bounds, and this revision's decoder, control-flow "
               "graph, value-set derivation, table-boundary analysis and corrections.</font>", AUTH))
    e.append(P("Revised November 2026 (second revision)", AUTH))
    e.append(Spacer(1, 6))
    e.append(P("<b>Abstract.</b> We ask whether the NES game <i>Super Mario Bros.</i> (NTSC/World, "
               "NROM) admits arbitrary code execution (ACE) driven solely by controller input on an "
               "unmodified cartridge. By recursive-descent disassembly from the CPU reset, NMI and IRQ "
               "vectors we establish that the entire 32 KiB program contains exactly one computed "
               "control transfer of the <i>direct</i> kind: the indirect "
               "<font face='Courier'>JMP ($0006)</font> inside the shared jump engine at "
               "<font face='Courier'>$8E04</font>. Its destination is always fetched from a fixed "
               "table in read-only program ROM, indexed by the calling routine. Three hundred and "
               "thirty-six <font face='Courier'>RTS</font> instructions and one "
               "<font face='Courier'>RTI</font> also take their destinations from memory, and we do "
               "not establish return-frame integrity. Because no executable code resides in writable "
               "memory, ACE requires forcing some dispatch's index past its table onto ROM bytes that "
               "encode a pointer into controllable RAM. We enumerate all 18 dispatch sites and derive "
               "each index set from the ROM by value-set analysis rather than asserting it. Two sites "
               "are bounded by instructions at the dispatch with no assumption about writable memory; "
               "thirteen are bounded only under an invariant that is observed or derived from routing "
               "tables rather than proved; and three do not keep the index inside the table even "
               "under the invariant asserted for them. Two dispatch-table boundaries had been "
               "over-read by a heuristic, "
               "one of which is what made a site appear safe. A controller-input fuzz of 144k frames "
               "and an identifier-injection probe found no index leaving its table. We therefore "
               "report no demonstrated controller-only ACE vector, give the structural reasons the "
               "search space is narrow, and state the remaining proof obligations. This revision "
               "withdraws our earlier claim that every dispatch index is provably in range; it is "
               "evidence, not a machine-checked proof of impossibility.", ABSTRACT))
    e.append(Spacer(1, 4))
    e.append(NextPageTemplate("two"))
    e.append(FrameBreak())

    # ---- 1 ----
    e.append(P("1&nbsp;&nbsp;Introduction", H1))
    e.append(P("Arbitrary code execution from controller input &mdash; redirecting a console's CPU into "
               "attacker-chosen bytes using only legitimate inputs on an unmodified game &mdash; is a "
               "mature subject in the tool-assisted speedrun (TAS) community. It has been demonstrated "
               "in <i>Super Mario World</i>, <i>Super Mario Bros. 3</i> and the Japanese "
               "<i>Super Mario Bros. 2</i> (Lost Levels), among others. For the original NTSC "
               "<i>Super Mario Bros.</i> no controller-only ACE is known; fast categories instead rely "
               "on the flagpole-glitch and frame-rule manipulation. This report asks the structural "
               "question behind that absence: <i>where, if anywhere, could such a vector live?</i>", BODY))
    e.append(P("We fix the threat model in Section&nbsp;3 and the memory model in Section&nbsp;2. In short: an unmodified cartridge, controller input only, and ACE means "
               "executing bytes the player controls rather than merely crashing the machine.", BODY))

    # ---- 2 ----
    e.append(P("2&nbsp;&nbsp;NES execution and memory model", H1))
    e.append(P("The cartridge is NROM (mapper&nbsp;0): 32&nbsp;KiB of program ROM fixed at "
               "<font face='Courier'>$8000-$FFFF</font>, 8&nbsp;KiB of character ROM, no bank "
               "switching and no mapper interrupt. The CPU is a 2A03, an NMOS 6502 without the "
               "65C02's indexed-indirect jump. Internal RAM is 2&nbsp;KiB at "
               "<font face='Courier'>$0000-$07FF</font>, <i>mirrored</i> three further times "
               "through <font face='Courier'>$1FFF</font>, so <font face='Courier'>$16B5</font> and "
               "<font face='Courier'>$06B5</font> are the same byte. Misreading those mirrors as I/O "
               "was a defect in the first version of this work (Section&nbsp;8). "
               "<font face='Courier'>$2000-$401F</font> is PPU and APU register space, and "
               "<font face='Courier'>$4020-$7FFF</font> is unmapped on this cartridge. The decisive "
               "consequence: executable bytes exist only in ROM, which the player cannot write, and "
               "controllable bytes exist only below <font face='Courier'>$2000</font>.", BODY))

    e.append(P("3&nbsp;&nbsp;Threat model", H1))
    e.append(P("The target is an unmodified NTSC cartridge and the only inputs are the two "
               "controllers. This excludes Game Genie codes and any other hardware that injects or "
               "patches bytes, which is a different model. We call an experiment "
               "<i>controller-only</i> when it uses the original ROM with no memory injection and no "
               "cheat interception, and <i>assisted</i> when it writes RAM, forces a starting area or "
               "patches the image. Assisted experiments are useful for testing a mechanism but are "
               "never evidence of a controller-only exploit, and are labelled as such throughout. "
               "Arbitrary code execution means driving the program counter into bytes the player "
               "controls and executing a chosen sequence; an unexpected jump that crashes or hangs "
               "the machine is not ACE.", BODY))

    e.append(P("4&nbsp;&nbsp;Method", H1))
    e.append(P("Recursive-descent disassembly from the three CPU vectors enumerates reachable code, "
               "separating instruction starts from operand bytes, dispatch-table data and unreached "
               "bytes. Every dispatch table is read with an instruction-accurate model of the jump "
               "engine rather than an arithmetic shortcut, over all 256 accumulator values. "
               "Destinations are classified against the memory model of Section&nbsp;2. Bounds are "
               "labelled by provenance: enforced at the dispatch, derived from routing tables, or "
               "merely observed. Dynamic work runs on the emulator with an added instruction tracer, "
               "so the program counter is observed per instruction rather than sampled per frame.", BODY))

    e.append(P("5&nbsp;&nbsp;Static control-flow analysis", H1))
    e.append(P("We disassembled the program by recursive descent from the three CPU vectors "
               "(reset <font face='Courier'>$8000</font>, NMI <font face='Courier'>$8082</font>, IRQ "
               "<font face='Courier'>$FFF0</font>), following every <font face='Courier'>JSR</font>, "
               "<font face='Courier'>JMP</font> and branch, and reading each RTS-dispatch jump table to "
               "enqueue its targets. The IRQ vector points into data &mdash; "
               "<font face='Courier'>$FFF0</font>, inside a byte table &mdash; and is never taken, "
               "but not for the reason we gave before. The 2A03 has two IRQ sources of its own, "
               "independent of the cartridge, so the absence of a mapper IRQ settles nothing. What "
               "settles it is that <font face='Courier'>SEI</font> executes at reset and no reachable "
               "instruction is <font face='Courier'>CLI</font> or <font face='Courier'>PLP</font>; the "
               "only reachable <font face='Courier'>RTI</font> can therefore restore only a status "
               "byte that already had the I flag set. By induction no maskable interrupt is ever "
               "serviced, whatever the APU configuration. The descent marks 22,806 of 32,768 program "
               "bytes (69%) as reachable code.", BODY))
    e.append(P("In all reachable code there is exactly one <i>direct</i> computed control transfer: the "
               "<font face='Courier'>JMP ($0006)</font> at <font face='Courier'>$8E16</font>, the last "
               "instruction of the shared jump engine. There are no indirect jumps through a RAM "
               "pointer elsewhere, and the NMOS 6502 has no indexed-indirect jump instruction. Every "
               "table-driven branch in the game &mdash; 18 call sites &mdash; funnels through this one "
               "engine, listed in Figure&nbsp;1. We stress a qualification absent from our earlier "
               "statement of this result: each of the 336 reachable <font face='Courier'>RTS</font> "
               "instructions and the one <font face='Courier'>RTI</font> also loads its destination "
               "from memory, so they are computed transfers too. The jump engine itself exploits this, "
               "consuming its caller's return address as a table pointer. Whether every other return "
               "consumes a valid frame is an open obligation, not a result.", BODY))
    e.append(Preformatted(
        "8E04  JumpEngine:\n"
        "8E04  0A        ASL A        ; 8-bit; bit 7 lost\n"
        "8E05  A8        TAY\n"
        "8E06  68        PLA          ; caller return ->\n"
        "8E07  85 04     STA $04      ;   $04/$05 = table-1\n"
        "8E09  68        PLA\n"
        "8E0A  85 05     STA $05\n"
        "8E0C  C8        INY\n"
        "8E0D  B1 04     LDA ($04),Y  ; $06 = CPU[ptr+wrapped Y]\n"
        "8E0F  85 06     STA $06\n"
        "8E11  C8        INY\n"
        "8E12  B1 04     LDA ($04),Y  ; $07 = CPU[ptr+wrapped Y]\n"
        "8E14  85 07     STA $07\n"
        "8E16  6C 06 00  JMP ($0006)  ; the only computed jump", CODE))
    e.append(P("Figure&nbsp;1: the jump engine. The caller does "
               "<font face='Courier'>LDA index; JSR $8E04</font>; the two-byte target follows the "
               "<font face='Courier'>JSR</font> in ROM.", CAP))

    # ---- 3 ----
    e.append(P("6&nbsp;&nbsp;JumpEngine analysis", H1))
    e.append(P("The engine forms <font face='Courier'>$06/$07</font> from the caller return address and "
               "the 6502's 8-bit <font face='Courier'>ASL</font>/<font face='Courier'>INY</font> "
               "sequence. For indices <font face='Courier'>$00..$7E</font> this agrees with "
               "<font face='Courier'>ROM[table + 2&middot;index]</font>. At <font face='Courier'>$7F</font> "
               "the second <font face='Courier'>INY</font> wraps and splits the byte pair; indices "
               "<font face='Courier'>$80..$FF</font> alias <font face='Courier'>$00..$7F</font> after "
               "the shift. The audit executes this exact model for all 256 accumulator values. For an "
               "in-range index the fetched address is a valid ROM routine, so the PC stays in ROM. To "
               "reach writable RAM the index must select bytes that encode a value below "
               "<font face='Courier'>$2000</font>, including mirrored internal RAM.", BODY))
    e.append(P("A scan of the trailing bytes of all 18 tables shows that such sub-"
               "<font face='Courier'>$0800</font> words are common &mdash; the game is therefore "
               "<i>not</i> protected by what its tables contain. It is protected entirely by each "
               "dispatch holding its index within bounds. Security reduces to 18 independent bounds "
               "obligations, summarized in Table&nbsp;1.", BODY))

    # Table 1
    data = [["site", "tbl", "N", "index source", "bound / note"]]
    rows = [
        ("$8215", "$8218", "4", "$0770 OperMode", "state ctr 0-3"),
        ("$8234", "$8237", "4", "$0772 task", "task counter"),
        ("$83A3", "$83A6", "5", "$0772", "task counter"),
        ("$856A", "$856D", "15", "$073C scr-task", "screen counter"),
        ("$921B", "$921E", "3", "$0772", "task counter"),
        ("$92C8", "$92CB", "8", "$071F, 8-for-0", "conditional"),
        ("$9664", "$9667", "47", "GameEngine $0E", "engine state"),
        ("$9743", "$9746", "5", "$0733", "state counter"),
        ("$AEDF", "$AEE2", "4", "$0772", "task counter"),
        ("$B04C", "$B04F", "13", "$0E", "state value"),
        ("$B34E", "$B351", "4", "$1D (CMP #3)", "checked"),
        ("$BDBD", "$BDC0", "9", "$05 via $BDF6", "CMP #9/BCC"),
        ("$C27F", "$C282", "55", "$16,x enemy ID", "table = ID space"),
        ("$C7A8", "$C7AB", "8", "$16,x - $12", "routed $12-$19"),
        ("$C88F", "$C892", "34", "$16,x -$14", "idx 34 -> $2060, I/O"),
        ("$C907", "$C90A", "21", "$16,x RAW", "no local bound *"),
        ("$C987", "$C98A", "7", "$16,x - $24", "routed $24-$2A"),
        ("$D2E5", "$D2E8", "5", "$0746 (CMP #5)", "explicit clamp"),
    ]
    data += [list(r) for r in rows]
    t = Table(data, colWidths=[0.44 * inch, 0.44 * inch, 0.2 * inch, 0.9 * inch, 0.92 * inch])
    tstyle = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 6.3),
        ("FONT", (0, 1), (2, -1), "Courier", 6.2),
        ("FONT", (3, 1), (3, -1), "Courier", 6.0),
        ("FONT", (4, 1), (4, -1), "Times-Roman", 6.3),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.black),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, colors.black),
        ("TOPPADDING", (0, 0), (-1, -1), 1.1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.1),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(.95, .95, .95)]),
    ]
    # highlight the C907 row
    c907 = 1 + [r[0] for r in rows].index("$C907")
    tstyle.append(("BACKGROUND", (0, c907), (-1, c907), colors.Color(1, .93, .75)))
    t.setStyle(TableStyle(tstyle))
    e.append(t)
    e.append(P("Table&nbsp;1: the 18 dispatch sites. <font face='Courier'>N</font> is the valid table "
               "length. (*) <font face='Courier'>$C907</font> is the only site without a local bound; "
               "Section&nbsp;5 treats it.", CAP))

    e.append(P("Two sites, not three, are bounded at the dispatch itself with no assumption about "
               "writable memory. <font face='Courier'>$D2E5</font> is bounded by a real clamp, "
               "<font face='Courier'>CMP #$05 / BCS</font>, which skips the dispatch entirely. "
               "<font face='Courier'>$BDBD</font> is bounded to <font face='Courier'>0..8</font> over "
               "nine entries, but by the subroutine <font face='Courier'>$BDF6</font> returning "
               "<font face='Courier'>Y &le; 13</font>, not by the "
               "<font face='Courier'>CMP #$09 / BCC</font> we previously cited: the other path falls "
               "through <font face='Courier'>SBC #$05</font> and is bounded only because the incoming "
               "value cannot exceed 13. Our third claimed site, "
               "<font face='Courier'>$92C8</font>, does not belong here at all. Its sequence "
               "<font face='Courier'>LDY $071F / BNE / LDY #$08 / STY $071F / DEY / TYA</font> "
               "substitutes eight for zero and never clamps the upper end, so the index is "
               "<font face='Courier'>((v or 8) - 1) &amp; $FF</font>, which value-set analysis derives "
               "as <font face='Courier'>{0..254}</font> over an eight-entry table. "
               "<font face='Courier'>RAM[$071F] = 9</font> would dispatch to "
               "<font face='Courier'>$26EE</font>. The site is in range only while "
               "<font face='Courier'>RAM[$071F] &le; 8</font>, an upstream invariant we can support "
               "but not prove: its only two exact writers are "
               "<font face='Courier'>$92B7</font> and <font face='Courier'>$92BF</font>, but 31 "
               "indexed and nine indirect stores could also reach it. The remaining sites are indexed "
               "by operation-mode, task, engine-state or enemy-identifier values that the game is only "
               "<i>observed</i> to keep small, which is why it does not crash in practice but is not "
               "the same as a bound.", BODY))

    # ---- 4 ----
    e.append(P("6.1&nbsp;&nbsp;The enemy master dispatch is sized to the identifier space", H2))
    e.append(P("The largest dispatch, <font face='Courier'>$C27F</font>, selects an enemy's behavior "
               "routine by its object identifier <font face='Courier'>$16,x</font>. Legal identifiers "
               "span <font face='Courier'>$00&ndash;$36</font>, and the table has 55 entries &mdash; "
               "exactly one per identifier &mdash; so no legal enemy can index out of range. Enemy "
               "identifiers are written only from level data in ROM and by hard-coded spawners; the "
               "player has no path to deposit an arbitrary byte into "
               "<font face='Courier'>$16,x</font> during normal play.", BODY))

    # ---- 5 ----
    e.append(P("6.2&nbsp;&nbsp;The one site that can reach RAM: $C907", H2))
    e.append(P("The enemy-graphics dispatch at <font face='Courier'>$C907</font> is unique: it indexes "
               "a 21-entry table by the raw identifier <font face='Courier'>$16,x</font> with no check "
               "at the dispatch, yet legal identifiers reach <font face='Courier'>$36</font>. Mapping "
               "every identifier through this table, exactly two land in writable RAM:", BODY))
    e.append(Preformatted(
        "enemy ID $34  -> index 52 -> JMP ($0006)=$0747  (RAM)\n"
        "enemy ID $35  -> index 53 -> JMP ($0006)=$03D0  (RAM)\n"
        "all other out-of-range IDs -> ROM code, or\n"
        "                              $2000-$7FFF I/O (crash)", CODE))
    e.append(P("Every other out-of-range identifier jumps either to unintended ROM or into "
               "<font face='Courier'>$2000&ndash;$7FFF</font> I/O space, which faults on open-bus/PPU "
               "reads rather than executing controllable data. So <font face='Courier'>$C907</font> is "
               "the sole place the game's only computed jump can reach writable memory, via identifiers "
               "<font face='Courier'>$34</font> or <font face='Courier'>$35</font>.", BODY))
    e.append(P("The exact model also yields the historical static candidate "
               "<font face='Courier'>$3C &rarr; $16B5</font>. This address is a mirror of physical "
               "internal RAM <font face='Courier'>$06B5</font>, but <font face='Courier'>$3C</font> is "
               "outside the legal identifier range. At the upstream master dispatch it resolves to "
               "<font face='Courier'>$95B6</font>, not the graphics dispatch, so it is not evidence of "
               "controller-only reachability.", BODY))
    e.append(P("These identifiers cannot arrive there in practice. The behavior master "
               "<font face='Courier'>$C27F</font> routes them to inert stubs, and no master handler "
               "feeds the <font face='Courier'>$C905</font> block; its sole caller sits in the "
               "enemy-graphics path, gated to low identifiers:", BODY))
    e.append(Preformatted(
        "ID $34 -> $C2F0:  RTS                     (no-op)\n"
        "ID $35 -> $C307:  LDA #$B8 / STA $CF,x / RTS\n"
        "\n"
        "$C905 has exactly one caller ($C8FF), inside the\n"
        "enemy-graphics routine, reached only for low IDs.", CODE))
    e.append(P("The gate is confirmed empirically: Bowser's identifier is "
               "<font face='Courier'>$2D</font>, well above the 21-entry table, yet he renders on every "
               "visit to <font face='Courier'>8-4</font> without crashing &mdash; proof that "
               "high-numbered enemies never enter the <font face='Courier'>$C905</font> path.", BODY))

    # ---- 6 ----
    e.append(P("<b>The gate, derived rather than inferred.</b> An earlier version argued the gate must "
               "exist because Bowser (identifier <font face='Courier'>$2D</font>) renders without "
               "crashing. The gate is in fact explicit in the collision dispatch: "
               "<font face='Courier'>CPY #$15 / BCC</font> selects collision-table entry 0 only for "
               "identifiers below <font face='Courier'>$15</font>, and that entry is the sole route "
               "into the block that calls <font face='Courier'>$C905</font>. Hence "
               "<font face='Courier'>$C907</font> receives identifiers "
               "<font face='Courier'>$00-$14</font>, indices 0-20, exactly its 21 entries. Applying the "
               "same derivation to all five enemy dispatches (<font face='Courier'>reach.py</font>) "
               "shows every in-bounds index at all 18 sites resolves to PRG ROM, and that exactly one "
               "legal identifier indexes past its table anywhere in the game: "
               "<font face='Courier'>$36</font> at <font face='Courier'>$C88F</font>, index 34 against "
               "34 entries, resolving to <font face='Courier'>$2060</font> in PPU register space. That "
               "can hang the machine but cannot execute controllable bytes, so it is not an ACE "
               "vector.", BODY))

    e.append(P("7&nbsp;&nbsp;Stack and interrupt analysis", H1))
    e.append(P("A claim that one instruction carries all computed control flow is only as strong as "
               "the search for alternatives. A 6502 can transfer control without a "
               "<font face='Courier'>JMP</font>: the classic trick pushes a computed address and "
               "returns into it with <font face='Courier'>RTS</font>. Our earlier revision scanned "
               "each reached instruction stream in address order for "
               "<font face='Courier'>PHA</font> ... <font face='Courier'>PHA</font> ... "
               "<font face='Courier'>RTS</font> within a 24-instruction window and, finding none, "
               "concluded that every <font face='Courier'>RTS</font> returns to a genuine call "
               "frame. A window in address order does not follow execution paths and cannot "
               "establish that: it would miss a push and a return in different basic blocks, and it "
               "says nothing about what any particular "
               "<font face='Courier'>RTS</font> consumes.", BODY))
    e.append(P("We replace it with per-routine abstract interpretation of the stack over the "
               "control-flow graph. A stack is a sequence of typed cells, each routine is analysed "
               "from an entry state holding the two bytes of its caller's return frame, and callee "
               "summaries (balanced, consumes-caller-frame, unresolved) are computed to a fixpoint "
               "over the call graph. Branch feasibility is carried alongside, which turned out to be "
               "necessary rather than decorative: SMB1 uses complementary branch pairs, and at "
               "<font face='Courier'>$BEAF</font> a <font face='Courier'>BCC</font> is followed by a "
               "<font face='Courier'>BCS</font> on the same carry, so the fallthrough cannot occur. "
               "Following it reaches a <font face='Courier'>PLA</font> with the entry frame on top "
               "and makes the balanced routine at <font face='Courier'>$BE70</font> appear to return "
               "through a frame it never created &mdash; a false positive our own first "
               "implementation produced.", BODY))
    e.append(P("The result supports the earlier conclusion on evidence that can carry it. Of 460 "
               "routines, 457 are balanced; all 627 reachable <font face='Courier'>RTS</font> sites "
               "consume exactly their routine's entry frame; and exactly one routine, the jump "
               "engine at <font face='Courier'>$8E04</font>, deliberately consumes its caller's "
               "frame, which is the intentional alternative the model must and does account for. The "
               "two unresolved routines are reset, whose <font face='Courier'>TXS</font> initialises "
               "the stack pointer, and the NMI handler, whose "
               "<font face='Courier'>RTI</font> frame this per-routine method does not model. It "
               "remains short of a proof in one specific way we report rather than bury: 29 indexed "
               "stores could reach <font face='Courier'>$0100-$01FF</font> without executing any "
               "stack instruction, and a frame overwritten that way would be invisible to an "
               "analysis that tracks cell provenance rather than values. None of the 29 has had its "
               "index range bounded.", BODY))
    e.append(P("The engine recovers its table pointer by pulling the caller's return address off "
               "the stack, so a sufficiently deranged stack pointer would make the table itself "
               "point into RAM. Measuring the recorded <font face='Courier'>sp</font> over four "
               "controller-only episodes of 3000 frames, the stack pointer stayed within "
               "<font face='Courier'>$EF-$FC</font>: 16 bytes of a 256-byte page, with 239 bytes of "
               "headroom. Overflow would need roughly 128 nested frames. This bounds the vector by "
               "measurement over reached states, not by proof.", BODY))

    e.append(P("8&nbsp;&nbsp;Emulator instrumentation", H1))
    e.append(P("Frame-granular sampling cannot see transient state, so we added an optional "
               "instruction tracer to the emulator. The hook sits at the single instruction boundary, "
               "immediately after the opcode fetch, and records the program counter, opcode, "
               "registers, stack pointer and status. Two filters keep it affordable: a 64&nbsp;KiB "
               "program-counter bitmap, and a flag that records any instruction executed below "
               "<font face='Courier'>$8000</font>. The second is the derailment detector; because "
               "all code is in ROM, an instruction running outside "
               "<font face='Courier'>$8000-$FFFF</font> means the program counter has entered RAM or "
               "I/O. With no filter set the hook is one predictable branch, and a regression test "
               "asserts that enabling tracing leaves emulation bit-identical.", BODY))

    e.append(P("9&nbsp;&nbsp;Controller-input experiments", H1))
    e.append(P("Two experiments on the real game (patched <font face='Courier'>nes-py</font>) "
               "complement the static audit. First, a <i>controller-only fuzz</i>: 48 episodes of "
               "3000 frames (144k frames) of structured and fully random input, two thirds on "
               "<font face='Courier'>1-1</font> and one third across varied start areas for dispatch "
               "coverage, reading the eight state-counter indices and five enemy-ID slots each frame. "
               "OperMode never left its valid range (zero derailments), every index stayed within the "
               "table it feeds, and identifiers <font face='Courier'>$34</font>/"
               "<font face='Courier'>$35</font> never appeared in any slot.", BODY))
    e.append(P("Second, an <i>identifier-injection</i> probe testing condition (C2) downstream: "
               "overwriting a live enemy slot's identifier each frame. Every in-range value "
               "<font face='Courier'>$00&ndash;$36</font>, including <font face='Courier'>$34</font> "
               "and <font face='Courier'>$35</font>, is absorbed without derailment &mdash; the master "
               "dispatch routes them to the stubs and the graphics gate keeps them from "
               "<font face='Courier'>$C905</font>. Only identifiers beyond the legal maximum "
               "(<font face='Courier'>$3F</font>, <font face='Courier'>$7F</font>) derail the CPU, by "
               "overrunning the 55-entry master table itself. Both halves of the static picture are "
               "thus confirmed: safety rests on identifiers never exceeding "
               "<font face='Courier'>$36</font> and on the routing of <font face='Courier'>$34</font>/"
               "<font face='Courier'>$35</font>. The search found no controller-only route to an "
               "out-of-range index.", BODY))

    # ---- method / repro ----
    e.append(P("<b>Instruction-level validation.</b> The frame-sampled fuzz cannot observe transient "
               "state. We therefore added an optional instruction tracer to the emulator and repeated "
               "the experiment per instruction. Two filters are armed: a watch on "
               "<font face='Courier'>$8E04</font>, where the accumulator still holds the dispatch "
               "index, and a derailment detector that records any instruction executed below "
               "<font face='Courier'>$8000</font>. On NROM all code is in ROM, so an instruction "
               "running outside <font face='Courier'>$8000-$FFFF</font> means the program counter has "
               "entered RAM or I/O, which is the precondition for ACE observed directly rather than "
               "inferred. Across six controller-only episodes of 4000 frames we recorded 67,675 "
               "dispatch invocations spanning 17 distinct indices, with a maximum index of 23 against "
               "a largest table of 55 entries, no dropped events, and <b>zero instructions executed "
               "outside PRG ROM</b>. This is a per-instruction observation rather than a sample, "
               "though it remains a search over the states these inputs reached.", BODY))

    e.append(P("10&nbsp;&nbsp;Candidate exploitability", H1))
    e.append(P("We classify every (dispatch site, index) pair whose destination is not an expected "
               "table entry, recording the entry point, index source, destination, memory region, "
               "what the controller can influence, reachability, exploitability and evidence. "
               "Provenance is kept as a separate dimension from the verdict, and only a bound that "
               "needs no assumption about writable memory may exclude an index outright. Our earlier "
               "classifier did not make that distinction: it excluded a candidate whenever the index "
               "exceeded a bound, whatever the bound rested on, and it discarded every program-ROM "
               "destination before classifying. Both choices inflated the result. Of the eighteen "
               "sites, two are bounded with no assumption, one structurally but conditional on an "
               "upstream invariant, four derived from routing tables, nine observed only, and two "
               "carry no bound that keeps the index inside the table.", BODY))
    e.append(P("Across all 256 indices at all eighteen sites there are 4608 resolutions, of which 4114 "
               "are not expected table entries. Classified with provenance separated: 505 are "
               "excluded unconditionally, 1252 only under a stated assumption, 1633 are not "
               "ACE-capable because the destination holds no player-influenced bytes, and 724 are "
               "destinations in controllable RAM that no proven bound excludes. None is demonstrated: "
               "no input sequence is known for any of them. Our previous figures, 2182 non-ROM "
               "destinations with 2181 excluded and none unknown, followed from the two choices "
               "described above. The single candidate we then reported, index 34 at "
               "<font face='Courier'>$C88F</font> from enemy identifier "
               "<font face='Courier'>$36</font>, resolving to <font face='Courier'>$2060</font>, "
               "stands on its merits and remains classified not-ACE, though we now record that "
               "destination as hardware-dependent rather than as a crash: an instruction fetch from a "
               "register region is a bus transaction, and we have not verified the outcome on "
               "hardware.", BODY))
    e.append(P("A further 1932 resolutions reach program ROM at an address that is not a table entry. "
               "We previously set these aside on the grounds that they resolve to ROM. That is not "
               "sound: 390 of them land on an operand byte of another instruction and 874 on bytes "
               "our control-flow graph never reaches, so execution would resume mid-instruction or in "
               "data, either of which can corrupt control flow further downstream. Two properties of "
               "the engine bound how far such an overrun can read. "
               "<font face='Courier'>ASL A</font> discards bit 7, so indices "
               "<font face='Courier'>i</font> and <font face='Courier'>i+128</font> share a "
               "destination and only 128 of the 256 indices are distinct; an overrun can therefore "
               "never read beyond 256 bytes past the <font face='Courier'>JSR</font>. And at "
               "effective index 127 the <font face='Courier'>INY</font> wraps, so the pointer's high "
               "byte is fetched from the return address itself.", BODY))

    e.append(P("11&nbsp;&nbsp;Results", H1))
    e.append(P("We demonstrate no controller-only ACE vector. The architectural reason the search "
               "space is narrow is uniform: a single jump engine, fed from fixed ROM tables in "
               "read-only memory, reached through 18 call sites. This is consistent with the TAS "
               "community's standing result that NTSC <i>Super Mario Bros.</i> has no known "
               "controller-only ACE while related titles do.", BODY))
    e.append(P("We withdraw the stronger claim of our earlier revision, that every index is held in "
               "range by explicit checks, exact table sizing or state-counter invariants. Derived "
               "from the ROM rather than asserted, two of the eighteen indices are bounded with no "
               "assumption about writable memory, thirteen are bounded only under an observed or "
               "derived invariant, and three do not keep the index inside the table even under the "
               "invariant we asserted. Two of those three are new findings; the third, "
               "<font face='Courier'>$C88F</font>, is the single escaping index we already "
               "published. Of the new pair, <font face='Courier'>$9743</font> we had recorded as bounded by "
               "<font face='Courier'>RAM[$0733] &le; 4</font> against a five-entry table; the table "
               "has three entries, because its own entry 0 points at "
               "<font face='Courier'>$974C</font>, which holds "
               "<font face='Courier'>JSR $9BBB</font>, and our boundary heuristic had read that "
               "instruction's bytes as entries 3 and 4. Under the bound we ourselves asserted, "
               "indices 3 and 4 dispatch outside the table. The other, "
               "<font face='Courier'>$9664</font>, we had attributed to "
               "<font face='Courier'>$0E</font>; its index is in fact "
               "<font face='Courier'>$00 + $07</font>, formed at "
               "<font face='Courier'>$965F-$9662</font>, over the game's largest table.", BODY))
    e.append(P("This is evidence, not a machine-checked proof of impossibility, and six proof "
               "obligations remain open or only partially established: control-flow completeness, "
               "jump-engine target legality, state invariants, return-frame integrity, the hardware "
               "and input model, and input controllability of unintended execution. In particular no "
               "variable that feeds a dispatch has a fully resolved writer set, because each is "
               "reachable in principle by an indirect store we have not constrained, so no state "
               "invariant is established inductively. The problem reduces to the following "
               "falsifiable conditions; exhibiting any one yields ACE:", BODY))
    e.append(P("<b>(C1) Out-of-range index injection.</b> Can a glitch drive any of the 18 index "
               "variables outside its table under a corrupted state the static bounds do not model? "
               "The mode and task counters were not exhaustively bounded against corrupted state.", BODY))
    e.append(P("<b>(C2) Identifier injection into the graphics path.</b> Can a glitch place enemy "
               "identifier <font face='Courier'>$34</font> or <font face='Courier'>$35</font> in a slot "
               "that reaches <font face='Courier'>$C905</font>, bypassing the stub routing of "
               "Section&nbsp;5? This is the only site whose indirect jump reaches RAM.", BODY))
    e.append(P("<b>(C3) Jump-engine stack corruption.</b> The engine recovers its <i>table pointer</i> "
               "by pulling the caller's return address off the stack. If stack depth can be corrupted "
               "so that this pull returns a RAM pointer, the &ldquo;table&rdquo; the engine indexes "
               "could itself point into controllable memory &mdash; an independent vector. Stack-depth "
               "invariants were not audited here.", BODY))
    e.append(P("<b>Coverage.</b> Static descent reached 69% of program ROM; code reached only through "
               "computed tables is included, but anything reached by descent-missed paths is unaudited. "
               "PPU and APU writes cannot execute code and are not an ACE path.", BODY))

    # ---- empirical ----
    e.append(P("12&nbsp;&nbsp;Limitations", H1))
    e.append(P("Static descent reaches 69% of program ROM; code reached only through computed tables "
               "is included, but anything reached by a path the descent misses is unaudited. Fifteen "
               "byte positions in unreached data would decode as "
               "<font face='Courier'>JMP (indirect)</font>; no traced path decodes them as "
               "instruction starts, but they are listed rather than dismissed. Nine dispatch bounds "
               "rest on observation rather than proof. The dynamic results are searches over the "
               "states the inputs reached, not exhaustive exploration, and the emulator's CPU core "
               "does not implement the undocumented opcodes, so a derailed run would diverge from "
               "hardware once it reached one. Finally, this is a single NTSC revision; other "
               "regional releases are not covered.", BODY))

    e.append(P("13&nbsp;&nbsp;Future research", H1))
    e.append(P("Three directions would tighten the result. First, prove the nine observed bounds by "
               "reasoning over reachable game states rather than sampling them, which is the only "
               "part of the argument that would turn measurement into proof. Second, extend the "
               "search with deterministic save states, so branches can be explored without replaying "
               "from power-on, and drive it by coverage of distinct (site, index) pairs rather than "
               "by episode. Third, apply the same method to the regional variants and to the "
               "closely related titles where ACE is known, which would show whether the structural "
               "property identified here (a single bounds-checked dispatcher reading fixed ROM "
               "tables) is what distinguishes them.", BODY))

    e.append(P("14&nbsp;&nbsp;Reproducibility", H1))
    e.append(P("The analysis is a few short Python scripts over the ROM: a 6502 linear disassembler, a "
               "recursive-descent tracer that emits the reached code set and the 18 dispatch tables, "
               "and an audit script that computes, per site, the index source, bound, and "
               "<font face='Courier'>JMP ($0006)</font> target region. The ROM itself is not "
               "redistributed. The invariant to re-derive is simple: for each dispatch, "
               "<font face='Courier'>index &le; N&minus;1</font> implies the fetched target is a fixed "
               "ROM routine and the PC stays in ROM; ACE requires breaking that inequality at a site "
               "whose trailing bytes encode a sub-<font face='Courier'>$2000</font> pointer and "
               "reaching it from controller input.", BODY))

    # ---- references ----
    e.append(P("15&nbsp;&nbsp;References", H1))
    refs = [
        "MOS Technology. <i>MCS6500 Microcomputer Family Programming Manual.</i> (6502 instruction "
        "set and addressing modes.)",
        "NESdev Wiki. <i>CPU, APU frame counter, and Game Genie.</i> nesdev.org/wiki.",
        "doppelganger et&nbsp;al. <i>Super Mario Bros. disassembly</i> (community reverse engineering; "
        "source of routine names such as JumpEngine, OperMode, and the enemy identifier map).",
        "TASVideos. <i>Arbitrary code execution</i> and game-resource pages for Super Mario World, "
        "Super Mario Bros. 3, and Super Mario Bros. 2 (Lost Levels). tasvideos.org.",
    ]
    for i, r in enumerate(refs, 1):
        e.append(P(f"[{i}]&nbsp;&nbsp;{r}", REF))

    doc.build(e)
    print(OUT, f"{os.path.getsize(OUT)} bytes")


if __name__ == "__main__":
    build()
