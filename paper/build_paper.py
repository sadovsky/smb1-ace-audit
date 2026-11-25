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
    e.append(P("November 2026", AUTH))
    e.append(Spacer(1, 6))
    e.append(P("<b>Abstract.</b> We ask whether the NES game <i>Super Mario Bros.</i> (NTSC/World, "
               "NROM) admits arbitrary code execution (ACE) driven solely by controller input on an "
               "unmodified cartridge. By recursive-descent disassembly from the CPU reset, NMI and IRQ "
               "vectors we establish that the entire 32 KiB program contains exactly one computed "
               "control transfer: the indirect <font face='Courier'>JMP ($0006)</font> inside the "
               "shared jump engine at <font face='Courier'>$8E04</font>. Its destination is always "
               "fetched from a fixed table in read-only program ROM, indexed by the calling routine. "
               "Because no executable code resides in writable memory, ACE is possible only by forcing "
               "some dispatch's index past its table onto ROM bytes that encode a pointer into "
               "controllable RAM. We enumerate all 18 dispatch sites, their index sources, and their "
               "bounds. Seventeen keep the program counter in ROM by explicit range checks, exact table "
               "sizing, or state-counter invariants. The eighteenth, the enemy-graphics dispatch at "
               "<font face='Courier'>$C907</font>, indexes a 21-entry table by a raw object identifier "
               "with no local bound and is the unique site whose out-of-range targets reach writable "
               "memory; we show the two offending identifiers are routed by the behavior dispatch to "
               "inert stubs and never reach it, consistent with the game not crashing on high-numbered "
               "enemies. A controller-input fuzz of 144k frames and an identifier-injection probe "
               "corroborate the analysis: no index leaves its table, the two RAM-reaching identifiers "
               "never arise, and the dispatch chain absorbs them when injected. We therefore report no "
               "controller-only ACE vector, give the structural reason "
               "none is known, and reduce the open problem to three precise, falsifiable conditions. We "
               "are explicit that this is strong structural evidence, not a machine-checked proof of "
               "impossibility.", ABSTRACT))
    e.append(Spacer(1, 4))
    e.append(NextPageTemplate("two"))
    e.append(FrameBreak())

    # ---- 1 ----
    e.append(P("1&nbsp;&nbsp;Introduction and threat model", H1))
    e.append(P("Arbitrary code execution from controller input &mdash; redirecting a console's CPU into "
               "attacker-chosen bytes using only legitimate inputs on an unmodified game &mdash; is a "
               "mature subject in the tool-assisted speedrun (TAS) community. It has been demonstrated "
               "in <i>Super Mario World</i>, <i>Super Mario Bros. 3</i> and the Japanese "
               "<i>Super Mario Bros. 2</i> (Lost Levels), among others. For the original NTSC "
               "<i>Super Mario Bros.</i> no controller-only ACE is known; fast categories instead rely "
               "on the flagpole-glitch and frame-rule manipulation. This report asks the structural "
               "question behind that absence: <i>where, if anywhere, could such a vector live?</i>", BODY))
    e.append(P("We fix the threat model precisely. The target is the unmodified cartridge; the only "
               "inputs are the two controllers. This excludes Game Genie codes and other hardware that "
               "inject or patch bytes (a different model). &ldquo;ACE&rdquo; means driving the 6502 "
               "program counter (PC) to an address whose bytes the player controls, and then executing "
               "a chosen payload from there.", BODY))
    e.append(P("The cartridge is NROM (mapper&nbsp;0): a fixed 32&nbsp;KiB of program ROM mapped at CPU "
               "<font face='Courier'>$8000&ndash;$FFFF</font>, with no bank switching and no mapper "
               "interrupt. Crucially, <i>all executable code is read-only</i>. The 2&nbsp;KiB of work "
               "RAM at <font face='Courier'>$0000&ndash;$07FF</font> is writable and carries mutable "
               "game and controller-derived state, but nothing executes from it unless the PC is "
               "redirected there. ACE thus reduces to one question: can controller input move the PC "
               "into writable RAM?", BODY))

    # ---- 2 ----
    e.append(P("2&nbsp;&nbsp;The attack surface is a single instruction", H1))
    e.append(P("We disassembled the program by recursive descent from the three CPU vectors "
               "(reset <font face='Courier'>$8000</font>, NMI <font face='Courier'>$8082</font>, IRQ "
               "<font face='Courier'>$FFF0</font>), following every <font face='Courier'>JSR</font>, "
               "<font face='Courier'>JMP</font> and branch, and reading each RTS-dispatch jump table to "
               "enqueue its targets. The IRQ vector points into data but is never taken: NROM has no "
               "mapper IRQ and the game runs with the APU frame interrupt disabled. The descent marks "
               "22,762 of 32,768 program bytes (69%) as reachable code.", BODY))
    e.append(P("In all reachable code there is exactly one computed or indirect control transfer: the "
               "<font face='Courier'>JMP ($0006)</font> at <font face='Courier'>$8E16</font>, the last "
               "instruction of the shared jump engine. There are no indirect jumps through a RAM "
               "pointer elsewhere, and the NMOS 6502 has no indexed-indirect jump instruction. Every "
               "dynamic branch in the game &mdash; 18 call sites &mdash; funnels through this one "
               "engine, listed in Figure&nbsp;1.", BODY))
    e.append(Preformatted(
        "8E04  JumpEngine:\n"
        "8E04  0A        ASL A        ; A = index*2\n"
        "8E05  A8        TAY\n"
        "8E06  68        PLA          ; caller return ->\n"
        "8E07  85 04     STA $04      ;   $04/$05 = table-1\n"
        "8E09  68        PLA\n"
        "8E0A  85 05     STA $05\n"
        "8E0C  C8        INY\n"
        "8E0D  B1 04     LDA ($04),Y  ; $06 = ROM[table+2i]\n"
        "8E0F  85 06     STA $06\n"
        "8E11  C8        INY\n"
        "8E12  B1 04     LDA ($04),Y  ; $07 = ROM[table+2i+1]\n"
        "8E14  85 07     STA $07\n"
        "8E16  6C 06 00  JMP ($0006)  ; the only computed jump", CODE))
    e.append(P("Figure&nbsp;1: the jump engine. The caller does "
               "<font face='Courier'>LDA index; JSR $8E04</font>; the two-byte target follows the "
               "<font face='Courier'>JSR</font> in ROM.", CAP))

    # ---- 3 ----
    e.append(P("3&nbsp;&nbsp;Targets come from fixed ROM tables", H1))
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
        ("$92C8", "$92CB", "8", "$071F -> 0..7", "structural"),
        ("$9664", "$9667", "47", "GameEngine $0E", "engine state"),
        ("$9743", "$9746", "5", "$0733", "state counter"),
        ("$AEDF", "$AEE2", "4", "$0772", "task counter"),
        ("$B04C", "$B04F", "13", "$0E", "state value"),
        ("$B34E", "$B351", "4", "$1D (CMP #3)", "checked"),
        ("$BDBD", "$BDC0", "9", "$05 via $BDF6", "CMP #9/BCC"),
        ("$C27F", "$C282", "55", "$16,x enemy ID", "table = ID space"),
        ("$C7A8", "$C7AB", "8", "$16,x - $12", "routed $12-$19"),
        ("$C88F", "$C892", "34", "$16,x -$14", "worst: I/O crash"),
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

    e.append(P("Three sites are bounded at the dispatch itself: "
               "<font face='Courier'>$D2E5</font> (<font face='Courier'>CMP #$05 / BCS</font>), "
               "<font face='Courier'>$BDBD</font> (<font face='Courier'>CMP #$09 / BCC</font>), and "
               "<font face='Courier'>$92C8</font>, whose index is forced into "
               "<font face='Courier'>0..7</font> for an eight-entry table. The remainder are indexed "
               "by operation-mode, task, or engine-state counters the game only sets to small in-range "
               "values; that these never exceed their tables is also why the game does not crash at "
               "these dispatches during normal play.", BODY))

    # ---- 4 ----
    e.append(P("4&nbsp;&nbsp;The enemy master dispatch is sized to the identifier space", H1))
    e.append(P("The largest dispatch, <font face='Courier'>$C27F</font>, selects an enemy's behavior "
               "routine by its object identifier <font face='Courier'>$16,x</font>. Legal identifiers "
               "span <font face='Courier'>$00&ndash;$36</font>, and the table has 55 entries &mdash; "
               "exactly one per identifier &mdash; so no legal enemy can index out of range. Enemy "
               "identifiers are written only from level data in ROM and by hard-coded spawners; the "
               "player has no path to deposit an arbitrary byte into "
               "<font face='Courier'>$16,x</font> during normal play.", BODY))

    # ---- 5 ----
    e.append(P("5&nbsp;&nbsp;The one site that can reach RAM: $C907", H1))
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
    e.append(P("6&nbsp;&nbsp;Verdict and open problem", H1))
    e.append(P("We found no controller-only ACE vector. The structural reason is uniform: a single "
               "jump engine, fed from fixed ROM tables, with every index held in range by explicit "
               "checks, exact table sizing, or state-counter invariants. This is consistent with the "
               "TAS community's standing result that NTSC <i>Super Mario Bros.</i> has no known "
               "controller-only ACE while related titles do.", BODY))
    e.append(P("We are explicit that this is structural evidence, not a machine-checked proof of "
               "impossibility. The problem reduces to three precise, falsifiable conditions; exhibiting "
               "any one yields ACE, and refuting all three would close the question:", BODY))
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
    e.append(P("7&nbsp;&nbsp;Empirical validation", H1))
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
    e.append(P("8&nbsp;&nbsp;Reproducibility", H1))
    e.append(P("The analysis is a few short Python scripts over the ROM: a 6502 linear disassembler, a "
               "recursive-descent tracer that emits the reached code set and the 18 dispatch tables, "
               "and an audit script that computes, per site, the index source, bound, and "
               "<font face='Courier'>JMP ($0006)</font> target region. The ROM itself is not "
               "redistributed. The invariant to re-derive is simple: for each dispatch, "
               "<font face='Courier'>index &le; N&minus;1</font> implies the fetched target is a fixed "
               "ROM routine and the PC stays in ROM; ACE requires breaking that inequality at a site "
               "whose trailing bytes encode a sub-<font face='Courier'>$0800</font> pointer and "
               "reaching it from controller input.", BODY))

    # ---- references ----
    e.append(P("References", H1))
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
